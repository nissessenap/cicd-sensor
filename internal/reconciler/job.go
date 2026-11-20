package reconciler

import (
	"strings"
	"time"
)

// JobKey identifies one GitHub job. CheckRunID is the job `id` in GitHub's
// API and the `github_check_run_id` in sensor records.
type JobKey struct {
	ProviderHost string
	Repository   string
	CheckRunID   int64
}

// normalized lower-cases the host and repository so the provider's spelling
// and the sensor's spelling of the same repository share one row.
func (k JobKey) normalized() JobKey {
	k.ProviderHost = strings.ToLower(k.ProviderHost)
	k.Repository = strings.ToLower(k.Repository)
	return k
}

// ProviderJob is the provider's view of a job, from a workflow_job event.
type ProviderJob struct {
	JobKey
	RunID        int64
	RunAttempt   int
	JobName      string
	WorkflowName string
	Labels       []string
	RunnerName   string
	StepCount    int
	Status       string
	Conclusion   string
	StartedAt    *time.Time
	CompletedAt  *time.Time
}

// RecordKind is the sensor record type the reconciler tracks.
type RecordKind string

const (
	RecordJobStart RecordKind = "job_start"
	RecordSummary  RecordKind = "summary"
)

// SensorRecord is what the reconciler keeps from one job_start or summary
// record.
type SensorRecord struct {
	JobKey
	Kind RecordKind
	// RunID and RunAttempt are zero when the record did not carry them.
	RunID      int64
	RunAttempt int
	// SummaryResult and FinalizeReason are set for RecordSummary only.
	SummaryResult  string
	FinalizeReason string
}

// Job is one stored row: the provider's view joined with what the sensor
// reported.
type Job struct {
	ProviderJob
	StartSeenAt    *time.Time
	SummarySeenAt  *time.Time
	SummaryResult  string
	FinalizeReason string
}
