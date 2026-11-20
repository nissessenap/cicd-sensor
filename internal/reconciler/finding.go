package reconciler

import (
	"fmt"
	"net/url"
	"time"

	"github.com/google/uuid"

	"github.com/cicd-sensor/cicd-sensor/internal/logtype"
)

const (
	// FindingLogType is the `log_type` of a finding record. It shares the
	// sensor's namespace so a SIEM can route it next to the other logs.
	FindingLogType = "cicd_sensor.missing_telemetry"
	// FindingSchemaVersion is bumped on breaking changes to Finding.
	FindingSchemaVersion = "v1"
	findingServiceName   = logtype.ServiceName + "-reconciler"
)

// Finding reports one completed job whose sensor telemetry is missing.
type Finding struct {
	Timestamp     time.Time `json:"timestamp"`
	LogType       string    `json:"log_type"`
	ServiceName   string    `json:"service_name"`
	SchemaVersion string    `json:"schema_version"`
	LogID         string    `json:"log_id"`
	// Verdict is no_start or no_summary.
	Verdict       Verdict    `json:"verdict"`
	ProviderHost  string     `json:"provider_host"`
	Repository    string     `json:"repository"`
	CheckRunID    int64      `json:"github_check_run_id"`
	RunID         int64      `json:"github_run_id,omitempty"`
	RunAttempt    int        `json:"github_run_attempt,omitempty"`
	JobName       string     `json:"job_name,omitempty"`
	WorkflowName  string     `json:"workflow_name,omitempty"`
	RunnerName    string     `json:"runner_name,omitempty"`
	Labels        []string   `json:"labels,omitempty"`
	Conclusion    string     `json:"conclusion,omitempty"`
	JobLink       string     `json:"job_link,omitempty"`
	CompletedAt   *time.Time `json:"completed_at,omitempty"`
	StartSeenAt   *time.Time `json:"start_seen_at,omitempty"`
	SummarySeenAt *time.Time `json:"summary_seen_at,omitempty"`
}

func newFinding(job Job, verdict Verdict, now time.Time) Finding {
	id, err := uuid.NewV7()
	if err != nil {
		id = uuid.New()
	}
	return Finding{
		Timestamp:     now.UTC(),
		LogType:       FindingLogType,
		ServiceName:   findingServiceName,
		SchemaVersion: FindingSchemaVersion,
		LogID:         id.String(),
		Verdict:       verdict,
		ProviderHost:  job.ProviderHost,
		Repository:    job.Repository,
		CheckRunID:    job.CheckRunID,
		RunID:         job.RunID,
		RunAttempt:    job.RunAttempt,
		JobName:       job.JobName,
		WorkflowName:  job.WorkflowName,
		RunnerName:    job.RunnerName,
		Labels:        job.Labels,
		Conclusion:    job.Conclusion,
		JobLink:       jobLink(job),
		CompletedAt:   job.CompletedAt,
		StartSeenAt:   job.StartSeenAt,
		SummarySeenAt: job.SummarySeenAt,
	}
}

func jobLink(job Job) string {
	if job.ProviderHost == "" || job.Repository == "" || job.RunID == 0 {
		return ""
	}
	u := url.URL{
		Scheme: "https",
		Host:   job.ProviderHost,
		Path:   fmt.Sprintf("/%s/actions/runs/%d/job/%d", job.Repository, job.RunID, job.CheckRunID),
	}
	return u.String()
}
