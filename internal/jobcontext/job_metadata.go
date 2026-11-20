package jobcontext

import "errors"

// JobMetadata carries optional non-identity context attached to a Job.
// JobIdentity owns attribution; metadata is for logs, reports, and search.
type JobMetadata struct {
	// Shared across providers.
	CommitSHA string `json:"commit_sha,omitempty"`
	RefName   string `json:"ref_name,omitempty"`
	Trigger   string `json:"trigger,omitempty"`
	ActorID   string `json:"actor_id,omitempty"`
	ActorName string `json:"actor_name,omitempty"`

	// GitHub only.
	GitHubWorkflowRef string `json:"github_workflow_ref,omitempty"`
	GitHubWorkflowSHA string `json:"github_workflow_sha,omitempty"`
	GitHubWorkflow    string `json:"github_workflow,omitempty"`
	// GitHubCheckRunID is the job's check run ID (`job.check_run_id`), the
	// only per-job key GitHub's API also exposes. Runner hooks cannot read
	// it, so it is metadata: it must never take part in Job registry keys.
	GitHubCheckRunID string `json:"github_check_run_id,omitempty"`

	// GitLab only.
	GitLabJobName      string `json:"gitlab_job_name,omitempty"`
	GitLabConfigRefURI string `json:"gitlab_config_ref_uri,omitempty"`
}

// Validate checks the metadata fields that have a provider-defined shape.
// Free-form fields are not validated.
func (m JobMetadata) Validate() error {
	if m.GitHubCheckRunID == "" {
		return nil
	}
	if err := validateIdentityFieldLen("github_check_run_id", m.GitHubCheckRunID, maxIdentityFieldLen); err != nil {
		return err
	}
	if !isPositiveIntString(m.GitHubCheckRunID) {
		return errors.New("github_check_run_id must be a positive integer")
	}
	return nil
}
