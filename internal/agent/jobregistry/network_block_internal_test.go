package jobregistry

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/jobscope"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/kerneltracker"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/managerclient"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"github.com/cicd-sensor/cicd-sensor/internal/jobevent"
	"github.com/cicd-sensor/cicd-sensor/internal/netblock"
	managerv1beta1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/manager/v1beta1"
	"github.com/cicd-sensor/cicd-sensor/internal/rule"
	"github.com/cicd-sensor/cicd-sensor/internal/rule/celengine"
	"github.com/cicd-sensor/cicd-sensor/internal/rulesource"
)

func networkBlockRuleSource(rules ...rule.Rule) rulesource.LoadedRules {
	return rulesource.LoadedRules{RuleSets: []rule.RuleSet{{RulesetID: "egress", Rules: rules}}}
}

func networkBlockRule(id, condition string) rule.Rule {
	return rule.Rule{RuleID: id, EventType: jobevent.NetworkConnect, Condition: condition, Action: rule.RuleActionBlock}
}

type ruleSourceManagerFetcher struct {
	result managerclient.FetchResult
}

func (f ruleSourceManagerFetcher) FetchConfig(context.Context, *managerv1beta1.FetchConfigRequest) (*managerclient.FetchResult, error) {
	result := f.result
	return &result, nil
}

func TestValidateNetworkBlockRules(t *testing.T) {
	t.Parallel()

	metadata := networkBlockRule("metadata", `remote_ip == "169.254.169.254"`)
	usesProcess := networkBlockRule("curl", `process.exec_path == "/usr/bin/curl"`)
	detect := rule.Rule{RuleID: "watch", EventType: jobevent.NetworkConnect, Condition: `process.exec_path == "/usr/bin/curl"`, Action: rule.RuleActionDetect}
	var tooMany []rule.Rule
	for i := range netblock.MaxInsns {
		tooMany = append(tooMany, networkBlockRule(fmt.Sprintf("r%d", i), fmt.Sprintf(`remote_port == %d`, i+1)))
	}

	tests := []struct {
		name          string
		enabled       bool
		monitorMode   bool
		rules         []rule.Rule
		wantErr       error
		wantFieldName string
	}{
		{name: "disabled agent accepts scopes without block rules", rules: []rule.Rule{detect}},
		{name: "disabled agent rejects a block rule", rules: []rule.Rule{detect, metadata}, wantErr: ErrNetworkBlockDisabled},
		{name: "disabled agent rejects a block rule even under monitor_mode", monitorMode: true, rules: []rule.Rule{metadata}, wantErr: ErrNetworkBlockDisabled},
		{name: "enabled agent accepts a destination-only block rule", enabled: true, rules: []rule.Rule{detect, metadata}},
		{name: "enabled agent accepts an empty scope", enabled: true},
		{name: "enabled agent rejects a block rule it cannot lower", enabled: true, rules: []rule.Rule{usesProcess}, wantFieldName: "process.exec_path"},
		{name: "monitor_mode still rejects a block rule the agent could not lower", enabled: true, monitorMode: true, rules: []rule.Rule{usesProcess}, wantFieldName: "process.exec_path"},
		{name: "monitor_mode accepts a destination-only block rule", enabled: true, monitorMode: true, rules: []rule.Rule{metadata}},
		{name: "enabled agent rejects more block rules than one program holds", enabled: true, rules: tooMany, wantErr: netblock.ErrProgramTooLarge},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			jr := newTestJobRegistry()
			jr.SetNetworkBlockEnabled(tc.enabled)
			scope := jobscope.NewProject()
			scope.RuleSets = []rule.RuleSet{{RulesetID: "egress", Rules: tc.rules}}
			scope.MonitorMode = tc.monitorMode
			scope.ResolveRules(jobcontext.JobIdentity{})

			err := jr.validateNetworkBlockRules(scope)
			if tc.wantFieldName != "" {
				var conditionErr *celengine.BlockConditionError
				if !errors.As(err, &conditionErr) || conditionErr.Field != tc.wantFieldName {
					t.Fatalf("error = %v, want BlockConditionError naming %s", err, tc.wantFieldName)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("error = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestStartRejectsBlockRulesItCannotEnforce(t *testing.T) {
	t.Parallel()

	blockSource := networkBlockRuleSource(networkBlockRule("metadata", `remote_ip == "169.254.169.254"`))
	hostFetcher := ruleSourceManagerFetcher{result: managerclient.FetchResult{RuleSources: []rulesource.LoadedRules{blockSource}}}
	githubID := jobcontext.GitHubJobIdentity("github.com", "acme/example", "1", "build", "1", "runner-1")
	gitlabID := jobcontext.GitLabJobIdentity("gitlab.com", "acme/example", "1")

	starts := []struct {
		name     string
		identity jobcontext.JobIdentity
		start    func(*JobRegistry) error
	}{
		{
			name:     "project-local rules",
			identity: githubID,
			start: func(jr *JobRegistry) error {
				_, err := jr.ApplyGitHubProjectStart(testCtx, GitHubProjectStartConfig{
					Identity: githubID, RunnerType: "machine", DisableBaselineRules: true,
					RuleSources: []rulesource.LoadedRules{blockSource},
				})
				return err
			},
		},
		{
			name:     "project rules from the manager",
			identity: githubID,
			start: func(jr *JobRegistry) error {
				_, err := jr.ApplyGitHubProjectStart(testCtx, GitHubProjectStartConfig{
					Identity: githubID, RunnerType: "machine", ManagerClient: hostFetcher,
				})
				return err
			},
		},
		{
			name:     "GitHub host rules",
			identity: githubID,
			start: func(jr *JobRegistry) error {
				_, err := jr.ApplyGitHubHostStart(testCtx, githubID, jobcontext.JobMetadata{}, "machine", 1, managerclient.Connection{}, hostFetcher)
				return err
			},
		},
		{
			name:     "GitLab host rules",
			identity: gitlabID,
			start: func(jr *JobRegistry) error {
				_, err := jr.ApplyGitLabHostStart(testCtx, gitlabID, jobcontext.JobMetadata{}, "machine", managerclient.Connection{}, hostFetcher)
				return err
			},
		},
	}
	for _, tc := range starts {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			disabled := newTestJobRegistry()
			if err := tc.start(disabled); !errors.Is(err, ErrNetworkBlockDisabled) {
				t.Fatalf("start with blocking disabled: error = %v, want %v", err, ErrNetworkBlockDisabled)
			}
			if disabled.get(tc.identity) != nil {
				t.Fatal("rejected start left a job registered")
			}

			// Enabled, but no KernelTracker is bound to enforce the rule.
			unenforced := newTestJobRegistry()
			unenforced.SetNetworkBlockEnabled(true)
			if err := tc.start(unenforced); !errors.Is(err, kerneltracker.ErrNetBlockUnavailable) {
				t.Fatalf("start without a kernel tracker: error = %v, want %v", err, kerneltracker.ErrNetBlockUnavailable)
			}
			if unenforced.get(tc.identity) != nil {
				t.Fatal("rejected start left a job registered")
			}
		})
	}
}
