package jobregistry

import (
	"context"
	"errors"
	"fmt"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/evaluation"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/job"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/jobscope"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/kerneltracker"
	"github.com/cicd-sensor/cicd-sensor/internal/rule"
)

// ErrNetworkBlockDisabled reports a rule with action block on an agent that
// was started without --enable-network-block.
var ErrNetworkBlockDisabled = errors.New("action block requires the agent flag --enable-network-block")

// SetNetworkBlockEnabled controls whether scopes may carry block rules. It
// must match the KernelTracker's network block setting.
func (jr *JobRegistry) SetNetworkBlockEnabled(enabled bool) {
	jr.mu.Lock()
	defer jr.mu.Unlock()
	jr.networkBlockEnabled = enabled
}

// validateNetworkBlockRules rejects a scope whose block rules this agent
// would not enforce, before the scope is attached to a Job. monitor_mode
// resolves block to detect, so under it the authored rules are checked too:
// a scope that passes in monitor_mode also passes once it is switched off,
// except for the size of the combined program.
func (jr *JobRegistry) validateNetworkBlockRules(scope *jobscope.JobScopeState) error {
	jr.mu.Lock()
	enabled := jr.networkBlockEnabled
	jr.mu.Unlock()

	if !enabled {
		for _, set := range scope.RuleSets {
			for _, r := range set.Rules {
				if r.Action == rule.RuleActionBlock {
					return fmt.Errorf("rule %s/%s: %w", set.RulesetID, r.RuleID, ErrNetworkBlockDisabled)
				}
			}
		}
		return nil
	}
	if scope.MonitorMode {
		for _, set := range scope.RuleSets {
			for _, r := range set.Rules {
				if r.Action != rule.RuleActionBlock {
					continue
				}
				if _, err := evaluation.LowerNetBlockRule(rule.ResolvedRule{Rule: r}); err != nil {
					return fmt.Errorf("block rule %s/%s: %w", set.RulesetID, r.RuleID, err)
				}
			}
		}
	}
	_, err := evaluation.NetBlockProgram(&scope.ResolvedRules, nil)
	return err
}

// installNetworkBlockProgram installs the union of the block rules of the
// scopes currently attached to j. Callers run it after attaching a scope, so
// rule evaluation already knows a block rule by the time the kernel enforces
// it and no blocked connect goes unexplained.
func (jr *JobRegistry) installNetworkBlockProgram(ctx context.Context, j *job.Job) error {
	jr.mu.Lock()
	kernelTracker := jr.kernelTracker
	jr.mu.Unlock()

	program, err := evaluation.NetBlockProgram(resolvedRulesOf(j.HostScope()), resolvedRulesOf(j.ProjectScope()))
	if err != nil {
		return err
	}
	if len(program) == 0 {
		return nil
	}
	if kernelTracker == nil {
		return fmt.Errorf("install network block program: %w", kerneltracker.ErrNetBlockUnavailable)
	}
	if err := kernelTracker.SetJobNetBlockProgram(ctx, j.Identity(), program); err != nil {
		return fmt.Errorf("install network block program: %w", err)
	}
	jr.logger.InfoContext(ctx, "network_block_program_installed",
		"job_identity", j.Identity(),
		"instructions", len(program),
	)
	return nil
}

func resolvedRulesOf(scope *jobscope.JobScopeState) *rule.ResolvedRules {
	if scope == nil {
		return nil
	}
	return &scope.ResolvedRules
}
