package evaluation

import (
	"fmt"

	"github.com/cicd-sensor/cicd-sensor/internal/netblock"
	"github.com/cicd-sensor/cicd-sensor/internal/rule"
)

// LowerNetBlockRule lowers one block rule to its kernel-evaluable form.
func LowerNetBlockRule(resolved rule.ResolvedRule) (netblock.Program, error) {
	env, err := sharedRuleEnv()
	if err != nil {
		return nil, err
	}
	return env.LowerNetBlockRule(resolved)
}

// NetBlockProgram lowers the block rules of a Job's scopes into the one
// program its cgroups enforce. A connect is refused when either scope blocks
// it, so neither scope can weaken the other's rules; which scope a hit
// belongs to stays in the compiled rules, not in the kernel.
//
// Rules resolved under monitor_mode are already detect rules and contribute
// nothing. Unlike CEL compile errors, a block rule that cannot be lowered is
// an error: dropping it would silently run the Job without the block.
func NetBlockProgram(host, project *rule.ResolvedRules) (netblock.Program, error) {
	var programs []netblock.Program
	for _, entry := range mergeEvaluationRules(host, project) {
		if entry.rule.Rule.Action != rule.RuleActionBlock {
			continue
		}
		program, err := LowerNetBlockRule(entry.rule)
		if err != nil {
			return nil, fmt.Errorf("block rule %s: %w", entry.rule.CanonicalRuleID, err)
		}
		programs = append(programs, program)
	}
	program, err := netblock.Union(programs...)
	if err != nil {
		return nil, fmt.Errorf("block rules: %w", err)
	}
	return program, nil
}
