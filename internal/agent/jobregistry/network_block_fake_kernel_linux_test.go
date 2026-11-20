//go:build linux

package jobregistry

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/kerneltracker"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/kerneltracker/kernelio"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/managerclient"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"github.com/cicd-sensor/cicd-sensor/internal/netblock"
	"github.com/cicd-sensor/cicd-sensor/internal/rule"
	"github.com/cicd-sensor/cicd-sensor/internal/rulesource"
)

// recordingNetBlockKernelIO stands in for the kernel so start paths can be
// driven without privileges and with injected map write failures.
type recordingNetBlockKernelIO struct {
	mu         sync.Mutex
	installErr error
	installs   int
	tracked    int
}

func (k *recordingNetBlockKernelIO) counts() (installs, tracked int) {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.installs, k.tracked
}

func (k *recordingNetBlockKernelIO) InstallNetBlockProgram(context.Context, uint32, netblock.Program) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.installErr != nil {
		return k.installErr
	}
	k.installs++
	return nil
}

func (k *recordingNetBlockKernelIO) PutCgroupIDInTrackedCgroupsMap(context.Context, uint64, uint32) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.tracked++
	return nil
}

func (*recordingNetBlockKernelIO) DeleteNetBlockProgram(context.Context, uint32) error { return nil }

func (*recordingNetBlockKernelIO) DeleteCgroupIDsFromTrackedCgroupsMap(context.Context, []uint64) error {
	return nil
}

func (*recordingNetBlockKernelIO) PutCgroupBasenameInStagingMap(context.Context, string, uint32) error {
	return nil
}

func (*recordingNetBlockKernelIO) DeleteCgroupBasenamesFromStagingMap(context.Context, []string) error {
	return nil
}

func (*recordingNetBlockKernelIO) QueueHTTPUprobeReconciliation([]uint64) {}

func (*recordingNetBlockKernelIO) StartKernelSampleLoop(context.Context, kernelio.KernelSampleHandler) error {
	return kernelio.ErrNotSupported
}

func (*recordingNetBlockKernelIO) Close() error { return nil }

func newRecordingNetBlockRegistry(t *testing.T, kernelIO *recordingNetBlockKernelIO) *JobRegistry {
	t.Helper()
	const cgroupRoot = "/sys/fs/cgroup"
	if _, err := os.Stat(cgroupRoot + "/cgroup.controllers"); err != nil {
		t.Skipf("cgroup v2 unavailable: %v", err)
	}

	jr := newTestJobRegistry()
	jr.SetNetworkBlockEnabled(true)
	kernelTracker := kerneltracker.NewWithKernelIO(testLogger, jr, kernelIO, cgroupRoot, kerneltracker.Config{EnableNetworkBlock: true})
	jr.BindKernelTracker(kernelTracker)

	ctx, cancel := context.WithCancel(context.Background())
	engineDone := make(chan error, 1)
	go func() { engineDone <- kernelTracker.Run(ctx) }()
	t.Cleanup(func() {
		jr.FinalizeAll(context.Background(), kerneltracker.EndShutdown)
		cancel()
		<-engineDone
	})
	return jr
}

// documentationBlockRules returns count block rules that each name one port
// on a TEST-NET address.
func documentationBlockRules(prefix string, count int) []rule.Rule {
	rules := make([]rule.Rule, count)
	for i := range rules {
		rules[i] = networkBlockRule(fmt.Sprintf("%s%d", prefix, i), fmt.Sprintf(`remote_ip == "192.0.2.1" && remote_port == %d`, i+1))
	}
	return rules
}

func TestStartInstallsNetworkBlockProgramOrUnwinds(t *testing.T) {
	t.Parallel()

	selfPID := int32(os.Getpid())
	installErr := errors.New("map write failed")
	blockSource := networkBlockRuleSource(documentationBlockRules("deny", 1)...)
	hostFetcher := ruleSourceManagerFetcher{result: managerclient.FetchResult{RuleSources: []rulesource.LoadedRules{blockSource}}}
	githubID := jobcontext.GitHubJobIdentity("github.com", "acme/example", "1", "build", "1", "runner-1")
	gitlabID := jobcontext.GitLabJobIdentity("gitlab.com", "acme/example", "1")

	starts := []struct {
		name     string
		identity jobcontext.JobIdentity
		// wantTracked is how many cgroups a successful start binds.
		wantTracked int
		start       func(*JobRegistry) error
	}{
		{
			name: "GitHub host start", identity: githubID, wantTracked: 1,
			start: func(jr *JobRegistry) error {
				_, err := jr.ApplyGitHubHostStart(testCtx, githubID, jobcontext.JobMetadata{}, "machine", selfPID, managerclient.Connection{}, hostFetcher)
				return err
			},
		},
		{
			name: "GitHub project-only start", identity: githubID, wantTracked: 1,
			start: func(jr *JobRegistry) error {
				_, err := jr.ApplyGitHubProjectStart(testCtx, GitHubProjectStartConfig{
					Identity: githubID, RunnerType: "machine", PeerPID: selfPID, DisableBaselineRules: true,
					RuleSources: []rulesource.LoadedRules{blockSource},
				})
				return err
			},
		},
		{
			name: "GitLab host start", identity: gitlabID,
			start: func(jr *JobRegistry) error {
				_, err := jr.ApplyGitLabHostStart(testCtx, gitlabID, jobcontext.JobMetadata{}, "machine", managerclient.Connection{}, hostFetcher)
				return err
			},
		},
	}
	for _, tc := range starts {
		t.Run(tc.name+": program is installed", func(t *testing.T) {
			t.Parallel()
			kernelIO := &recordingNetBlockKernelIO{}
			jr := newRecordingNetBlockRegistry(t, kernelIO)
			if err := tc.start(jr); err != nil {
				t.Fatalf("start: %v", err)
			}
			if jr.get(tc.identity) == nil {
				t.Fatal("accepted start did not register the job")
			}
			if installs, tracked := kernelIO.counts(); installs != 1 || tracked != tc.wantTracked {
				t.Fatalf("installs=%d tracked=%d, want 1 and %d", installs, tracked, tc.wantTracked)
			}
		})

		t.Run(tc.name+": kernel write failure unwinds the job", func(t *testing.T) {
			t.Parallel()
			kernelIO := &recordingNetBlockKernelIO{installErr: installErr}
			jr := newRecordingNetBlockRegistry(t, kernelIO)
			if err := tc.start(jr); !errors.Is(err, installErr) {
				t.Fatalf("start error = %v, want %v", err, installErr)
			}
			if jr.get(tc.identity) != nil {
				t.Fatal("failed start left a job registered")
			}
			if _, tracked := kernelIO.counts(); tracked != 0 {
				t.Fatalf("failed start tracked %d cgroups, want 0", tracked)
			}
			// The KernelTracker forgot the Job too, so the identity is free.
			kernelIO.mu.Lock()
			kernelIO.installErr = nil
			kernelIO.mu.Unlock()
			if err := tc.start(jr); err != nil {
				t.Fatalf("retry after a failed start: %v", err)
			}
		})
	}
}

func TestProjectStartRejectsCombinedProgramTooLargeBeforeAttach(t *testing.T) {
	t.Parallel()

	// Each scope fits one program; the two together do not.
	const rulesPerScope = 12
	hostRules := documentationBlockRules("host", rulesPerScope)
	projectRules := documentationBlockRules("project", rulesPerScope)

	kernelIO := &recordingNetBlockKernelIO{}
	jr := newRecordingNetBlockRegistry(t, kernelIO)
	selfPID := int32(os.Getpid())
	id := jobcontext.GitHubJobIdentity("github.com", "acme/example", "1", "build", "1", "runner-1")

	hostFetcher := ruleSourceManagerFetcher{result: managerclient.FetchResult{
		RuleSources: []rulesource.LoadedRules{networkBlockRuleSource(hostRules...)},
	}}
	job, err := jr.ApplyGitHubHostStart(testCtx, id, jobcontext.JobMetadata{}, "machine", selfPID, managerclient.Connection{}, hostFetcher)
	if err != nil {
		t.Fatalf("ApplyGitHubHostStart: %v", err)
	}

	_, err = jr.ApplyGitHubProjectStart(testCtx, GitHubProjectStartConfig{
		Identity: id, RunnerType: "machine", PeerPID: selfPID, DisableBaselineRules: true,
		RuleSources: []rulesource.LoadedRules{networkBlockRuleSource(projectRules...)},
	})
	if !errors.Is(err, netblock.ErrProgramTooLarge) {
		t.Fatalf("ApplyGitHubProjectStart error = %v, want %v", err, netblock.ErrProgramTooLarge)
	}
	if job.ProjectScope() != nil {
		t.Fatal("rejected project scope was attached to the job")
	}
	if installs, _ := kernelIO.counts(); installs != 1 {
		t.Fatalf("installs = %d, want only the host program", installs)
	}
}
