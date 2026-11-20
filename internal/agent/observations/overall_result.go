package observations

import (
	"github.com/cicd-sensor/cicd-sensor/internal/resultdoc"
	"github.com/cicd-sensor/cicd-sensor/internal/rule"
)

// OverallResult returns the highest-severity outcome implied by the given hits.
// Order: terminated > detected > passed. A block hit counts as detected: the
// connect was refused but the job kept running. The same vocabulary is used in
// the summary log's `result` field and the HTML report's ResultSummary.
func OverallResult(hits HitSnapshot) string {
	result := resultdoc.ResultPassed
	for _, h := range hits {
		switch h.Action {
		case string(rule.RuleActionTerminate):
			return resultdoc.ResultTerminated
		case string(rule.RuleActionDetect), string(rule.RuleActionBlock):
			result = resultdoc.ResultDetected
		}
	}
	return result
}
