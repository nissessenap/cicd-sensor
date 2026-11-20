//go:build linux

package jobregistry

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/jobscope"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/kerneltracker"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/managerclient"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"github.com/cicd-sensor/cicd-sensor/internal/rule"
	"github.com/cicd-sensor/cicd-sensor/internal/rulesource"
)

// startNetworkBlockRegistry boots a JobRegistry and a KernelTracker with
// network blocking enabled. It needs the privileges to load BPF programs and
// skips otherwise.
func startNetworkBlockRegistry(t *testing.T) (*JobRegistry, context.Context) {
	t.Helper()
	ctx, cancel := context.WithCancel(testCtx)

	jr := New(testLogger)
	jr.SetNetworkBlockEnabled(true)
	jr.SetBaselineLoadForTesting(func(context.Context, *slog.Logger, string) (rulesource.LoadedRules, error) {
		return rulesource.LoadedRules{}, nil
	})
	kernelTracker, err := kerneltracker.NewWithConfig(testLogger, jr, kerneltracker.Config{EnableNetworkBlock: true})
	if err != nil {
		cancel()
		t.Skipf("kernel tracker unavailable: %v", err)
	}
	jr.BindKernelTracker(kernelTracker)

	engineDone := make(chan error, 1)
	go func() { engineDone <- kernelTracker.Run(ctx) }()
	t.Cleanup(func() {
		jr.FinalizeAll(context.Background(), kerneltracker.EndShutdown)
		cancel()
		<-engineDone
		_ = kernelTracker.Close()
	})
	return jr, ctx
}

// loopbackBlockTarget listens on a loopback port owned by the test and
// returns a block rule that names only that port. The tracked cgroup is the
// one the test runs in, so the rule must not match anything else.
func loopbackBlockTarget(t *testing.T, ruleID string) (*net.TCPListener, rule.Rule) {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	port := listener.Addr().(*net.TCPAddr).Port
	return listener, networkBlockRule(ruleID, fmt.Sprintf(`remote_ip == "127.0.0.1" && remote_port == %d`, port))
}

func dialListener(listener *net.TCPListener) error {
	conn, err := net.DialTimeout("tcp4", listener.Addr().String(), 2*time.Second)
	if err == nil {
		_ = conn.Close()
	}
	return err
}

func waitForHitAction(t *testing.T, scope *jobscope.JobScopeState, ruleID string) string {
	t.Helper()
	var action string
	waitForJob(t, "hit for rule "+ruleID, func() bool {
		for _, hit := range scope.ObservationSnapshot().Hits {
			if hit.RuleID == ruleID {
				action = hit.Action
				return true
			}
		}
		return false
	})
	return action
}

func hasHit(scope *jobscope.JobScopeState, ruleID string) bool {
	for _, hit := range scope.ObservationSnapshot().Hits {
		if hit.RuleID == ruleID {
			return true
		}
	}
	return false
}

func TestJobRegistry_NetworkBlock(t *testing.T) {
	selfPID := int32(os.Getpid())

	t.Run("block rule refuses the connect and records a block hit", func(t *testing.T) {
		jr, ctx := startNetworkBlockRegistry(t)
		listener, blockRule := loopbackBlockTarget(t, "deny")
		id := jobcontext.GitHubJobIdentity("github.com", "acme/example", "1", "build", "1", "r1")

		job, err := jr.ApplyGitHubProjectStart(ctx, GitHubProjectStartConfig{
			Identity: id, RunnerType: "machine", PeerPID: selfPID, DisableBaselineRules: true,
			RuleSources: []rulesource.LoadedRules{networkBlockRuleSource(blockRule)},
		})
		if err != nil {
			t.Fatalf("ApplyGitHubProjectStart: %v", err)
		}

		if err := dialListener(listener); !errors.Is(err, syscall.EPERM) {
			t.Fatalf("dial blocked listener = %v, want EPERM", err)
		}
		if got := waitForHitAction(t, job.ProjectScope(), "deny"); got != string(rule.RuleActionBlock) {
			t.Fatalf("hit action = %q, want block", got)
		}
	})

	t.Run("monitor_mode lets the connect through and records a detect hit", func(t *testing.T) {
		jr, ctx := startNetworkBlockRegistry(t)
		listener, blockRule := loopbackBlockTarget(t, "deny")
		id := jobcontext.GitHubJobIdentity("github.com", "acme/example", "2", "build", "1", "r1")

		job, err := jr.ApplyGitHubProjectStart(ctx, GitHubProjectStartConfig{
			Identity: id, RunnerType: "machine", PeerPID: selfPID, DisableBaselineRules: true, MonitorMode: true,
			RuleSources: []rulesource.LoadedRules{networkBlockRuleSource(blockRule)},
		})
		if err != nil {
			t.Fatalf("ApplyGitHubProjectStart: %v", err)
		}

		if err := dialListener(listener); err != nil {
			t.Fatalf("dial under monitor_mode = %v, want success", err)
		}
		if got := waitForHitAction(t, job.ProjectScope(), "deny"); got != string(rule.RuleActionDetect) {
			t.Fatalf("hit action = %q, want detect", got)
		}
	})

	t.Run("host and project rules both enforce and each scope sees only its own hits", func(t *testing.T) {
		jr, ctx := startNetworkBlockRegistry(t)
		hostListener, hostRule := loopbackBlockTarget(t, "host_deny")
		projectListener, projectRule := loopbackBlockTarget(t, "project_deny")
		id := jobcontext.GitHubJobIdentity("github.com", "acme/example", "3", "build", "1", "r1")

		hostFetcher := ruleSourceManagerFetcher{result: managerclient.FetchResult{
			RuleSources: []rulesource.LoadedRules{networkBlockRuleSource(hostRule)},
		}}
		job, err := jr.ApplyGitHubHostStart(ctx, id, jobcontext.JobMetadata{}, "machine", selfPID, managerclient.Connection{}, hostFetcher)
		if err != nil {
			t.Fatalf("ApplyGitHubHostStart: %v", err)
		}
		if err := dialListener(projectListener); err != nil {
			t.Fatalf("dial project listener before project start = %v, want success", err)
		}

		// The project scope attaches to a Job whose cgroup is already tracked.
		if _, err := jr.ApplyGitHubProjectStart(ctx, GitHubProjectStartConfig{
			Identity: id, RunnerType: "machine", PeerPID: selfPID, DisableBaselineRules: true,
			RuleSources: []rulesource.LoadedRules{networkBlockRuleSource(projectRule)},
		}); err != nil {
			t.Fatalf("ApplyGitHubProjectStart: %v", err)
		}

		if err := dialListener(hostListener); !errors.Is(err, syscall.EPERM) {
			t.Fatalf("dial host-blocked listener = %v, want EPERM", err)
		}
		if err := dialListener(projectListener); !errors.Is(err, syscall.EPERM) {
			t.Fatalf("dial project-blocked listener = %v, want EPERM", err)
		}
		waitForHitAction(t, job.HostScope(), "host_deny")
		waitForHitAction(t, job.ProjectScope(), "project_deny")
		if hasHit(job.HostScope(), "project_deny") {
			t.Fatal("host scope recorded the project's block hit")
		}
		if hasHit(job.ProjectScope(), "host_deny") {
			t.Fatal("project scope recorded the host's block hit")
		}
	})
}
