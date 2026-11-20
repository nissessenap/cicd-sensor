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

func netBlockTestState(slots uint32, jobs ...jobcontext.JobIdentity) *jobTrackingState {
	state := newJobTrackingState()
	if slots > 0 {
		state.netBlock = newNetBlockSlots(slots)
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

func TestNetBlockSlots(t *testing.T) {
	t.Parallel()

	jobA, jobB, jobC := netBlockTestJob("a"), netBlockTestJob("b"), netBlockTestJob("c")

	t.Run("disabled tracker hands out no slots", func(t *testing.T) {
		t.Parallel()
		state := netBlockTestState(0, jobA)
		if got := state.netBlock.slotFor(jobA); got != 0 {
			t.Fatalf("slot = %d, want 0", got)
		}
		state.removeJob(jobA)
	})

	t.Run("each job gets a distinct non-zero slot", func(t *testing.T) {
		t.Parallel()
		state := netBlockTestState(4, jobA, jobB)
		slotA, slotB := state.netBlock.slotFor(jobA), state.netBlock.slotFor(jobB)
		if slotA == 0 || slotB == 0 || slotA == slotB {
			t.Fatalf("slots = %d, %d, want distinct non-zero", slotA, slotB)
		}
	})

	t.Run("re-registering a job keeps its slot", func(t *testing.T) {
		t.Parallel()
		state := netBlockTestState(4, jobA)
		before := state.netBlock.slotFor(jobA)
		state.registerJob(jobA, 1)
		if got := state.netBlock.slotFor(jobA); got != before {
			t.Fatalf("slot after re-register = %d, want %d", got, before)
		}
	})

	t.Run("job beyond the limit is left without a slot", func(t *testing.T) {
		t.Parallel()
		state := netBlockTestState(2, jobA, jobB, jobC)
		if got := state.netBlock.slotFor(jobC); got != 0 {
			t.Fatalf("slot for job over the limit = %d, want 0", got)
		}
	})

	t.Run("removed job frees its slot for a later job", func(t *testing.T) {
		t.Parallel()
		state := netBlockTestState(2, jobA, jobB)
		freed := state.netBlock.slotFor(jobA)
		state.removeJob(jobA)
		state.registerJob(jobC, 1)
		if got := state.netBlock.slotFor(jobC); got != freed {
			t.Fatalf("slot for new job = %d, want freed slot %d", got, freed)
		}
	})

	t.Run("a just-freed slot is not the first one reused", func(t *testing.T) {
		t.Parallel()
		state := netBlockTestState(4, jobA)
		freed := state.netBlock.slotFor(jobA)
		state.removeJob(jobA)
		state.registerJob(jobB, 1)
		if got := state.netBlock.slotFor(jobB); got == freed || got == 0 {
			t.Fatalf("slot for new job = %d, want a slot other than just-freed %d", got, freed)
		}
	})

	t.Run("unknown job has no slot", func(t *testing.T) {
		t.Parallel()
		state := netBlockTestState(2)
		if got := state.netBlock.slotFor(jobA); got != 0 {
			t.Fatalf("slot = %d, want 0", got)
		}
		state.netBlock.release(jobA)
	})
}

func TestBindAndStageCarryJobNetBlockSlot(t *testing.T) {
	t.Parallel()

	jobID := netBlockTestJob("bind")
	tests := []struct {
		name  string
		slots uint32
	}{
		{name: "enabled: the slot rides on the tracking entry", slots: 4},
		{name: "disabled: tracking entries carry slot zero", slots: 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			state := netBlockTestState(tc.slots, jobID)
			want := state.netBlock.slotFor(jobID)
			if (want != 0) != (tc.slots != 0) {
				t.Fatalf("slot = %d with %d slots configured", want, tc.slots)
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
			if len(kernelIO.putTrackedSlots) != 1 || kernelIO.putTrackedSlots[0] != want {
				t.Fatalf("tracked_cgroups slots = %v, want [%d]", kernelIO.putTrackedSlots, want)
			}
			if len(kernelIO.putStagingSlots) != 1 || kernelIO.putStagingSlots[0] != want {
				t.Fatalf("staging_map slots = %v, want [%d]", kernelIO.putStagingSlots, want)
			}
		})
	}
}

func TestSetNetBlockProgram(t *testing.T) {
	t.Parallel()

	jobID := netBlockTestJob("install")
	installErr := errors.New("map write failed")

	t.Run("first install uses buffer one and a replacement alternates", func(t *testing.T) {
		t.Parallel()
		state := netBlockTestState(4, jobID)
		slot := state.netBlock.slotFor(jobID)
		kernelIO := &recordingKernelIO{}
		for i, wantBuffer := range []uint32{1, 2, 1} {
			if err := setNetBlockProgram(t, state, kernelIO, jobID, testNetBlockProgram); err != nil {
				t.Fatalf("install %d: %v", i, err)
			}
			got := kernelIO.installs[i]
			if got.slot != slot || got.buffer != wantBuffer {
				t.Fatalf("install %d wrote slot %d buffer %d, want slot %d buffer %d", i, got.slot, got.buffer, slot, wantBuffer)
			}
		}
	})

	t.Run("failed install keeps the previous buffer active", func(t *testing.T) {
		t.Parallel()
		state := netBlockTestState(4, jobID)
		kernelIO := &recordingKernelIO{}
		if err := setNetBlockProgram(t, state, kernelIO, jobID, testNetBlockProgram); err != nil {
			t.Fatalf("first install: %v", err)
		}
		kernelIO.installErr = installErr
		if err := setNetBlockProgram(t, state, kernelIO, jobID, testNetBlockProgram); !errors.Is(err, installErr) {
			t.Fatalf("failed install error = %v, want %v", err, installErr)
		}
		kernelIO.installErr = nil
		if err := setNetBlockProgram(t, state, kernelIO, jobID, testNetBlockProgram); err != nil {
			t.Fatalf("retry install: %v", err)
		}
		if got := kernelIO.installs[len(kernelIO.installs)-1].buffer; got != 2 {
			t.Fatalf("retry wrote buffer %d, want the still-idle buffer 2", got)
		}
	})

	rejected := []struct {
		name    string
		slots   uint32
		jobs    []jobcontext.JobIdentity
		program netblock.Program
		wantErr error
	}{
		{name: "blocking disabled", slots: 0, jobs: []jobcontext.JobIdentity{jobID}, program: testNetBlockProgram, wantErr: ErrNetBlockUnavailable},
		{name: "job without a slot", slots: 1, jobs: []jobcontext.JobIdentity{netBlockTestJob("first"), jobID}, program: testNetBlockProgram, wantErr: ErrNetBlockUnavailable},
		{name: "malformed program", slots: 4, jobs: []jobcontext.JobIdentity{jobID}, program: netblock.Program{netblock.And()}, wantErr: netblock.ErrMalformedProgram},
		{name: "empty program would silently stop enforcing", slots: 4, jobs: []jobcontext.JobIdentity{jobID}, program: nil, wantErr: netblock.ErrMalformedProgram},
	}
	for _, tc := range rejected {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			state := netBlockTestState(tc.slots, tc.jobs...)
			kernelIO := &recordingKernelIO{}
			if err := setNetBlockProgram(t, state, kernelIO, jobID, tc.program); !errors.Is(err, tc.wantErr) {
				t.Fatalf("error = %v, want %v", err, tc.wantErr)
			}
			if len(kernelIO.installs) != 0 {
				t.Fatalf("kernel was written despite rejection: %+v", kernelIO.installs)
			}
		})
	}

	t.Run("unregistered job", func(t *testing.T) {
		t.Parallel()
		state := netBlockTestState(4)
		kernelIO := &recordingKernelIO{}
		if err := setNetBlockProgram(t, state, kernelIO, jobID, testNetBlockProgram); err == nil {
			t.Fatal("expected an error for a job that was never registered")
		}
		if len(kernelIO.installs) != 0 {
			t.Fatalf("kernel was written despite rejection: %+v", kernelIO.installs)
		}
	})
}

func TestRemoveJobClearsNetBlockSlot(t *testing.T) {
	t.Parallel()

	jobID := netBlockTestJob("remove")
	clearErr := errors.New("clear failed")

	t.Run("slot stops enforcing and is released", func(t *testing.T) {
		t.Parallel()
		state := netBlockTestState(4, jobID)
		state.bind(jobID, 42)
		slot := state.netBlock.slotFor(jobID)

		reply := make(chan error, 1)
		kernelIO := runTestEffects(t, state, handleEngineInput(state, commandRemoveJob{JobID: jobID, Reply: reply}))
		if err := <-reply; err != nil {
			t.Fatalf("RemoveJob: %v", err)
		}
		if len(kernelIO.clearedSlots) != 1 || kernelIO.clearedSlots[0] != slot {
			t.Fatalf("cleared slots = %v, want [%d]", kernelIO.clearedSlots, slot)
		}
		if got := state.netBlock.slotFor(jobID); got != 0 {
			t.Fatalf("slot after removal = %d, want released", got)
		}
	})

	t.Run("clear failure keeps the job and its slot for a retry", func(t *testing.T) {
		t.Parallel()
		state := netBlockTestState(4, jobID)
		slot := state.netBlock.slotFor(jobID)

		reply := make(chan error, 1)
		effects := handleEngineInput(state, commandRemoveJob{JobID: jobID, Reply: reply})
		engine := newTestKernelTracker(nil, nil, &recordingKernelIO{clearErr: clearErr}, "")
		engine.jobTracking = state
		engine.runEngineEffects(t.Context(), effects)

		if err := <-reply; !errors.Is(err, clearErr) {
			t.Fatalf("RemoveJob error = %v, want %v", err, clearErr)
		}
		if got := state.netBlock.slotFor(jobID); got != slot {
			t.Fatalf("slot after failed removal = %d, want %d kept", got, slot)
		}
	})
}
