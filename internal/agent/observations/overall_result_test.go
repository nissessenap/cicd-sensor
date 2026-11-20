package observations

import (
	"testing"

	"github.com/cicd-sensor/cicd-sensor/internal/resultdoc"
)

func TestOverallResult(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		actions []string
		want    string
	}{
		{name: "no hits", want: resultdoc.ResultPassed},
		{name: "collect is not an outcome", actions: []string{"collect"}, want: resultdoc.ResultPassed},
		{name: "detect", actions: []string{"detect"}, want: resultdoc.ResultDetected},
		{name: "block leaves the job running, so it reports as detected", actions: []string{"block"}, want: resultdoc.ResultDetected},
		{name: "terminate outranks block", actions: []string{"block", "terminate"}, want: resultdoc.ResultTerminated},
		{name: "terminate outranks a later detect", actions: []string{"terminate", "detect"}, want: resultdoc.ResultTerminated},
		{name: "unknown action is ignored", actions: []string{"delete"}, want: resultdoc.ResultPassed},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var hits HitSnapshot
			for _, action := range tc.actions {
				hits = append(hits, HitSummary{Action: action})
			}
			if got := OverallResult(hits); got != tc.want {
				t.Fatalf("OverallResult = %q, want %q", got, tc.want)
			}
		})
	}
}
