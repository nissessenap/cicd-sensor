package reconciler

// Verdict is the reconciler's conclusion about one completed job.
type Verdict string

const (
	// VerdictOK means a Summary arrived for the job.
	VerdictOK Verdict = "ok"
	// VerdictNoStart means the job ran and no sensor record arrived.
	VerdictNoStart Verdict = "no_start"
	// VerdictNoSummary means the sensor started and never finalized.
	VerdictNoSummary Verdict = "no_summary"
	// VerdictNotExpected means the job could not or need not run the sensor.
	VerdictNotExpected Verdict = "not_expected"
)

// IsFinding reports whether the verdict must be reported.
func (v Verdict) IsFinding() bool {
	return v == VerdictNoStart || v == VerdictNoSummary
}

const conclusionSkipped = "skipped"

// Decide returns the verdict for a completed job. It is a pure function of
// the stored row and the expectation config.
//
// A Summary without a start record is ok: the start record may not be
// routed, or the Agent may predate it.
func Decide(job Job, expect Expectation) Verdict {
	switch {
	case !job.RanOnRunner():
		return VerdictNotExpected
	case !expect.Expects(job.Repository, job.Labels):
		return VerdictNotExpected
	case job.SummarySeenAt != nil:
		return VerdictOK
	case job.StartSeenAt != nil:
		return VerdictNoSummary
	default:
		return VerdictNoStart
	}
}

// RanOnRunner reports whether the job was ever picked up by a runner.
// started_at cannot be used: GitHub sets it for skipped jobs and for jobs
// cancelled while queued. A skipped job has a null runner_name, a job
// cancelled while queued has an empty one, and neither has steps.
func (j Job) RanOnRunner() bool {
	if j.Conclusion == conclusionSkipped {
		return false
	}
	return j.RunnerName != "" || j.StepCount > 0
}
