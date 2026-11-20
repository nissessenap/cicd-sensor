package kerneltracker

import (
	"errors"
	"testing"

	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"github.com/cicd-sensor/cicd-sensor/internal/netblock"
)

func netBlockTestJob(name string) jobcontext.JobIdentity {
	return jobcontext.GitLabJobIdentity("gitlab.com", "group/project", name)
}

func netBlockTestState(enabled bool, jobs ...jobcontext.JobIdentity) *jobTrackingState {
	state := newJobTrackingState()
	if enabled {
		state.netBlock = newNetBlockTokens()
	}
	for _, jobID := range jobs {
		state.registerJob(jobID, 1)
	}
	return state
}

var testNetBlockProgram = netblock.Program{netblock.Match(netblock.Tuple{Port: 443}, netblock.Tuple{Port: 0xffff})}

func setNetBlockProgram(t *testing.T, state *jobTrackingState, kernelIO *recordingKernelIO, jobID jobcontext.JobIdentity, program netblock.Program) error {
	t.Helper()
	reply := make(chan error, 1)
	effects := handleEngineInput(state, commandSetNetBlockProgram{JobID: jobID, Program: program, Reply: reply})
	engine := newTestKernelTracker(nil, nil, kernelIO, "")
	engine.jobTracking = state
	engine.runEngineEffects(t.Context(), effects)
	select {
	case err := <-reply:
		return err
	default:
		t.Fatal("no reply to commandSetNetBlockProgram")
		return nil
	}
}

func TestNetBlockTokens(t *testing.T) {
	t.Parallel()

	jobA, jobB := netBlockTestJob("a"), netBlockTestJob("b")

	t.Run("disabled tracker hands out no tokens", func(t *testing.T) {
		t.Parallel()
		state := netBlockTestState(false, jobA)
		if got := state.netBlock.tokenFor(jobA); got != 0 {
			t.Fatalf("token = %d, want 0", got)
		}
		state.removeJob(jobA)
	})

	t.Run("each job gets a distinct non-zero token", func(t *testing.T) {
		t.Parallel()
		state := netBlockTestState(true, jobA, jobB)
		tokenA, tokenB := state.netBlock.tokenFor(jobA), state.netBlock.tokenFor(jobB)
		if tokenA == 0 || tokenB == 0 || tokenA == tokenB {
			t.Fatalf("tokens = %d, %d, want distinct non-zero", tokenA, tokenB)
		}
	})

	t.Run("re-registering a job keeps its token", func(t *testing.T) {
		t.Parallel()
		state := netBlockTestState(true, jobA)
		before := state.netBlock.tokenFor(jobA)
		state.registerJob(jobA, 1)
		if got := state.netBlock.tokenFor(jobA); got != before {
			t.Fatalf("token after re-register = %d, want %d", got, before)
		}
	})

	t.Run("a removed job's token is never handed out again", func(t *testing.T) {
		t.Parallel()
		state := netBlockTestState(true, jobA)
		retired := state.netBlock.tokenFor(jobA)
		state.removeJob(jobA)
		if got := state.netBlock.tokenFor(jobA); got != 0 {
			t.Fatalf("token after removal = %d, want 0", got)
		}
		for _, jobID := range []jobcontext.JobIdentity{jobB, jobA} {
			state.registerJob(jobID, 1)
			if got := state.netBlock.tokenFor(jobID); got == 0 || got == retired {
				t.Fatalf("token for a later job = %d, want non-zero and not retired token %d", got, retired)
			}
		}
	})
}

func TestBindAndStageCarryJobNetBlockToken(t *testing.T) {
	t.Parallel()

	jobID := netBlockTestJob("bind")
	tests := []struct {
		name    string
		enabled bool
	}{
		{name: "enabled: the token rides on the tracking entry", enabled: true},
		{name: "disabled: tracking entries carry token zero", enabled: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			state := netBlockTestState(tc.enabled, jobID)
			want := state.netBlock.tokenFor(jobID)
			if (want != 0) != tc.enabled {
				t.Fatalf("token = %d with blocking enabled=%v", want, tc.enabled)
			}

			bindReply := make(chan error, 1)
			stageReply := make(chan error, 1)
			effects := handleEngineInput(state, commandBindCgroup{JobID: jobID, CgroupID: 42, Reply: bindReply})
			effects = append(effects, handleEngineInput(state, commandStageCgroupBasename{Basename: "docker-abc.scope", JobID: jobID, Reply: stageReply})...)
			kernelIO := runTestEffects(t, state, effects)

			if err := <-bindReply; err != nil {
				t.Fatalf("bind: %v", err)
			}
			if err := <-stageReply; err != nil {
				t.Fatalf("stage: %v", err)
			}
			if len(kernelIO.putTrackedTokens) != 1 || kernelIO.putTrackedTokens[0] != want {
				t.Fatalf("tracked_cgroups tokens = %v, want [%d]", kernelIO.putTrackedTokens, want)
			}
			if len(kernelIO.putStagingTokens) != 1 || kernelIO.putStagingTokens[0] != want {
				t.Fatalf("staging_map tokens = %v, want [%d]", kernelIO.putStagingTokens, want)
			}
		})
	}
}

func TestSetNetBlockProgram(t *testing.T) {
	t.Parallel()

	jobID := netBlockTestJob("install")
	installErr := errors.New("map write failed")

	t.Run("every install for a job writes the job's token", func(t *testing.T) {
		t.Parallel()
		state := netBlockTestState(true, netBlockTestJob("other"), jobID)
		token := state.netBlock.tokenFor(jobID)
		kernelIO := &recordingKernelIO{}
		for i := range 2 {
			if err := setNetBlockProgram(t, state, kernelIO, jobID, testNetBlockProgram); err != nil {
				t.Fatalf("install %d: %v", i, err)
			}
			if got := kernelIO.installs[i].token; got != token {
				t.Fatalf("install %d wrote token %d, want %d", i, got, token)
			}
		}
	})

	t.Run("kernel write failure is returned to the caller", func(t *testing.T) {
		t.Parallel()
		state := netBlockTestState(true, jobID)
		kernelIO := &recordingKernelIO{installErr: installErr}
		if err := setNetBlockProgram(t, state, kernelIO, jobID, testNetBlockProgram); !errors.Is(err, installErr) {
			t.Fatalf("error = %v, want %v", err, installErr)
		}
	})

	t.Run("blocking disabled", func(t *testing.T) {
		t.Parallel()
		state := netBlockTestState(false, jobID)
		kernelIO := &recordingKernelIO{}
		if err := setNetBlockProgram(t, state, kernelIO, jobID, testNetBlockProgram); !errors.Is(err, ErrNetBlockUnavailable) {
			t.Fatalf("error = %v, want %v", err, ErrNetBlockUnavailable)
		}
		if len(kernelIO.installs) != 0 {
			t.Fatalf("kernel was written despite rejection: %+v", kernelIO.installs)
		}
	})

	t.Run("unregistered job", func(t *testing.T) {
		t.Parallel()
		state := netBlockTestState(true)
		kernelIO := &recordingKernelIO{}
		if err := setNetBlockProgram(t, state, kernelIO, jobID, testNetBlockProgram); err == nil {
			t.Fatal("expected an error for a job that was never registered")
		}
		if len(kernelIO.installs) != 0 {
			t.Fatalf("kernel was written despite rejection: %+v", kernelIO.installs)
		}
	})
}

func TestRemoveJobDeletesNetBlockProgram(t *testing.T) {
	t.Parallel()

	jobID := netBlockTestJob("remove")
	deleteErr := errors.New("delete failed")

	t.Run("program is deleted and the token retired", func(t *testing.T) {
		t.Parallel()
		state := netBlockTestState(true, jobID)
		state.bind(jobID, 42)
		token := state.netBlock.tokenFor(jobID)

		reply := make(chan error, 1)
		kernelIO := runTestEffects(t, state, handleEngineInput(state, commandRemoveJob{JobID: jobID, Reply: reply}))
		if err := <-reply; err != nil {
			t.Fatalf("RemoveJob: %v", err)
		}
		if len(kernelIO.deletedPrograms) != 1 || kernelIO.deletedPrograms[0] != token {
			t.Fatalf("deleted programs = %v, want [%d]", kernelIO.deletedPrograms, token)
		}
		if got := state.netBlock.tokenFor(jobID); got != 0 {
			t.Fatalf("token after removal = %d, want 0", got)
		}
	})

	t.Run("delete failure keeps the job and its token for a retry", func(t *testing.T) {
		t.Parallel()
		state := netBlockTestState(true, jobID)
		token := state.netBlock.tokenFor(jobID)

		reply := make(chan error, 1)
		effects := handleEngineInput(state, commandRemoveJob{JobID: jobID, Reply: reply})
		engine := newTestKernelTracker(nil, nil, &recordingKernelIO{deleteProgramErr: deleteErr}, "")
		engine.jobTracking = state
		engine.runEngineEffects(t.Context(), effects)

		if err := <-reply; !errors.Is(err, deleteErr) {
			t.Fatalf("RemoveJob error = %v, want %v", err, deleteErr)
		}
		if got := state.netBlock.tokenFor(jobID); got != token {
			t.Fatalf("token after failed removal = %d, want %d kept", got, token)
		}
	})
}
