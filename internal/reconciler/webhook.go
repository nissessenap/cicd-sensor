package reconciler

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// webhookMaxBodyBytes caps the request body. A workflow_job payload is
	// tens of kilobytes even with many steps.
	webhookMaxBodyBytes = 1 << 20

	githubSignatureHeader = "X-Hub-Signature-256"
	githubEventHeader     = "X-GitHub-Event"
	githubSignaturePrefix = "sha256="
	workflowJobEvent      = "workflow_job"
	pingEvent             = "ping"
)

// providerJobStore is the part of Store the webhook handler uses.
type providerJobStore interface {
	UpsertProviderJob(ctx context.Context, job ProviderJob, now time.Time) error
}

// GitHubWebhookHandler receives GitHub workflow_job events. The endpoint is
// internet-facing: nothing in a request is parsed until its HMAC signature
// over the raw body has been verified.
type GitHubWebhookHandler struct {
	secret  []byte
	store   providerJobStore
	metrics *Metrics
	logger  *slog.Logger
	now     func() time.Time
}

// NewGitHubWebhookHandler builds the handler. secret is the webhook secret
// configured in GitHub and must not be empty.
func NewGitHubWebhookHandler(secret string, store providerJobStore, metrics *Metrics, logger *slog.Logger) (*GitHubWebhookHandler, error) {
	if secret == "" {
		return nil, errors.New("github webhook secret is required")
	}
	return &GitHubWebhookHandler{
		secret:  []byte(secret),
		store:   store,
		metrics: metrics,
		logger:  logger.With("component", "github_webhook"),
		now:     time.Now,
	}, nil
}

func (h *GitHubWebhookHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, webhookMaxBodyBytes))
	if err != nil {
		if _, tooLarge := errors.AsType[*http.MaxBytesError](err); tooLarge {
			http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "unreadable body", http.StatusBadRequest)
		return
	}
	if !validGitHubSignature(h.secret, body, r.Header.Get(githubSignatureHeader)) {
		h.metrics.webhookSignatureFailures.Add(1)
		h.logger.WarnContext(ctx, "webhook_signature_rejected", "peer", r.RemoteAddr)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	switch event := r.Header.Get(githubEventHeader); event {
	case workflowJobEvent:
	case pingEvent:
		w.WriteHeader(http.StatusNoContent)
		return
	default:
		// A hook subscribed to more than workflow_job is a config mistake,
		// not an error GitHub should retry.
		h.logger.InfoContext(ctx, "webhook_event_ignored", "event", event)
		w.WriteHeader(http.StatusNoContent)
		return
	}

	var payload workflowJobPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	job, err := payload.providerJob()
	if err != nil {
		h.logger.WarnContext(ctx, "webhook_payload_rejected", "error", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := h.store.UpsertProviderJob(ctx, job, h.now().UTC()); err != nil {
		// A 5xx marks the delivery failed in GitHub so it can be redelivered.
		h.logger.ErrorContext(ctx, "webhook_store_failed", "error", err)
		http.Error(w, "store unavailable", http.StatusInternalServerError)
		return
	}
	h.logger.InfoContext(ctx, "workflow_job_received",
		"action", payload.Action,
		"repository", job.Repository,
		"github_check_run_id", job.CheckRunID,
		"status", job.Status,
		"conclusion", job.Conclusion,
	)
	w.WriteHeader(http.StatusNoContent)
}

// validGitHubSignature reports whether header is the HMAC-SHA256 of body
// under secret, in GitHub's "sha256=<hex>" form.
func validGitHubSignature(secret, body []byte, header string) bool {
	hexDigest, ok := strings.CutPrefix(header, githubSignaturePrefix)
	if !ok {
		return false
	}
	got, err := hex.DecodeString(hexDigest)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	return hmac.Equal(got, mac.Sum(nil))
}

// workflowJobPayload is the subset of the workflow_job webhook payload the
// reconciler reads. The workflow_job object has the same shape as a job in
// GitHub's REST jobs API.
type workflowJobPayload struct {
	Action      string `json:"action"`
	WorkflowJob struct {
		ID           int64      `json:"id"`
		RunID        int64      `json:"run_id"`
		RunAttempt   int        `json:"run_attempt"`
		Name         string     `json:"name"`
		WorkflowName string     `json:"workflow_name"`
		Status       string     `json:"status"`
		Conclusion   *string    `json:"conclusion"`
		Labels       []string   `json:"labels"`
		RunnerName   *string    `json:"runner_name"`
		StartedAt    *time.Time `json:"started_at"`
		CompletedAt  *time.Time `json:"completed_at"`
		Steps        []struct {
			Number int `json:"number"`
		} `json:"steps"`
	} `json:"workflow_job"`
	Repository struct {
		FullName string `json:"full_name"`
		HTMLURL  string `json:"html_url"`
	} `json:"repository"`
}

func (p workflowJobPayload) providerJob() (ProviderJob, error) {
	job := p.WorkflowJob
	if job.ID <= 0 {
		return ProviderJob{}, errors.New("workflow_job.id is required")
	}
	if p.Repository.FullName == "" {
		return ProviderJob{}, errors.New("repository.full_name is required")
	}
	if job.Status == "" {
		return ProviderJob{}, errors.New("workflow_job.status is required")
	}
	host, err := providerHostFromURL(p.Repository.HTMLURL)
	if err != nil {
		return ProviderJob{}, err
	}
	out := ProviderJob{
		JobKey:       JobKey{ProviderHost: host, Repository: p.Repository.FullName, CheckRunID: job.ID},
		RunID:        job.RunID,
		RunAttempt:   job.RunAttempt,
		JobName:      job.Name,
		WorkflowName: job.WorkflowName,
		Labels:       job.Labels,
		StepCount:    len(job.Steps),
		Status:       job.Status,
		StartedAt:    job.StartedAt,
		CompletedAt:  job.CompletedAt,
	}
	// GitHub sends null for both fields until they are known.
	if job.Conclusion != nil {
		out.Conclusion = *job.Conclusion
	}
	if job.RunnerName != nil {
		out.RunnerName = *job.RunnerName
	}
	if out.Status == "completed" && out.CompletedAt == nil {
		return ProviderJob{}, errors.New("workflow_job.completed_at is required for a completed job")
	}
	return out, nil
}

// providerHostFromURL returns the host sensor records use as provider_host.
func providerHostFromURL(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Hostname() == "" {
		return "", errors.New("repository.html_url must be an absolute URL")
	}
	return strings.ToLower(u.Hostname()), nil
}
