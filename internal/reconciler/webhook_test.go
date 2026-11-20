package reconciler

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const testWebhookSecret = "It's a Secret to Everybody"

type recordingProviderJobStore struct {
	mu   sync.Mutex
	jobs []ProviderJob
	err  error
}

func (s *recordingProviderJobStore) UpsertProviderJob(_ context.Context, job ProviderJob, _ time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	s.jobs = append(s.jobs, job)
	return nil
}

func signBody(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return githubSignaturePrefix + hex.EncodeToString(mac.Sum(nil))
}

// loadJobObjects returns the real job objects GitHub returned, by job id.
func loadJobObjects(t *testing.T, file string) map[int64]json.RawMessage {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "jobs", file))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var listing struct {
		Jobs []json.RawMessage `json:"jobs"`
	}
	if err := json.Unmarshal(data, &listing); err != nil {
		t.Fatalf("decode fixture %s: %v", file, err)
	}
	out := make(map[int64]json.RawMessage, len(listing.Jobs))
	for _, raw := range listing.Jobs {
		var head struct {
			ID int64 `json:"id"`
		}
		if err := json.Unmarshal(raw, &head); err != nil {
			t.Fatalf("decode job id: %v", err)
		}
		out[head.ID] = raw
	}
	return out
}

// webhookBody wraps a job object in the workflow_job webhook envelope.
func webhookBody(t *testing.T, action string, job json.RawMessage) []byte {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"action":       action,
		"workflow_job": job,
		"repository": map[string]any{
			"full_name": "acme/example",
			"html_url":  "https://github.com/acme/example",
		},
	})
	if err != nil {
		t.Fatalf("marshal webhook body: %v", err)
	}
	return body
}

func newTestWebhook(t *testing.T, store providerJobStore) (*GitHubWebhookHandler, *Metrics) {
	t.Helper()
	metrics := &Metrics{}
	handler, err := NewGitHubWebhookHandler(testWebhookSecret, store, metrics, testLogger)
	if err != nil {
		t.Fatalf("NewGitHubWebhookHandler: %v", err)
	}
	return handler, metrics
}

func TestValidGitHubSignature(t *testing.T) {
	t.Parallel()

	// Vector from GitHub's "Validating webhook deliveries" documentation.
	docBody := []byte("Hello, World!")
	const docSignature = "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17"

	cases := []struct {
		name   string
		secret string
		body   []byte
		header string
		want   bool
	}{
		{name: "GitHub's documented test vector verifies", secret: testWebhookSecret, body: docBody, header: docSignature, want: true},
		{name: "upper-case hex is the same digest", secret: testWebhookSecret, body: docBody, header: "sha256=" + strings.ToUpper(strings.TrimPrefix(docSignature, "sha256=")), want: true},
		{name: "empty body still has a valid signature", secret: testWebhookSecret, body: nil, header: signBody(testWebhookSecret, nil), want: true},
		{name: "signature made with another secret", secret: testWebhookSecret, body: docBody, header: signBody("other secret", docBody)},
		{name: "signature of a different body", secret: testWebhookSecret, body: []byte("Hello, World?"), header: docSignature},
		{name: "missing header", secret: testWebhookSecret, body: docBody, header: ""},
		{name: "legacy sha1 header value is not accepted", secret: testWebhookSecret, body: docBody, header: "sha1=757107ea0eb2509fc211221cce984b8a37570b6d"},
		{name: "digest without the algorithm prefix", secret: testWebhookSecret, body: docBody, header: strings.TrimPrefix(docSignature, "sha256=")},
		{name: "prefix with no digest", secret: testWebhookSecret, body: docBody, header: "sha256="},
		{name: "truncated digest", secret: testWebhookSecret, body: docBody, header: docSignature[:len(docSignature)-2]},
		{name: "non-hex digest", secret: testWebhookSecret, body: docBody, header: "sha256=" + strings.Repeat("z", 64)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := validGitHubSignature([]byte(tc.secret), tc.body, tc.header); got != tc.want {
				t.Fatalf("validGitHubSignature: got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestNewGitHubWebhookHandler_RequiresSecret(t *testing.T) {
	t.Parallel()

	// An empty secret would make every attacker-computed HMAC valid.
	if _, err := NewGitHubWebhookHandler("", &recordingProviderJobStore{}, &Metrics{}, testLogger); err == nil {
		t.Fatal("expected an error for an empty webhook secret")
	}
}

func TestGitHubWebhookHandler(t *testing.T) {
	t.Parallel()

	completed := loadJobObjects(t, "main-jobs.json")[136504227286]
	validBody := webhookBody(t, "completed", completed)
	oversize := append(bytes.Clone(validBody[:len(validBody)-1]), []byte(`,"padding":"`+strings.Repeat("a", webhookMaxBodyBytes)+`"}`)...)
	storeErr := errors.New("postgres down")

	type request struct {
		body      []byte
		signature string
		event     string
	}
	signed := func(body []byte, event string) request {
		return request{body: body, signature: signBody(testWebhookSecret, body), event: event}
	}

	cases := []struct {
		name            string
		req             request
		storeErr        error
		wantStatus      int
		wantStored      int
		wantSigFailures uint64
	}{
		{name: "signed workflow_job event is stored", req: signed(validBody, "workflow_job"), wantStatus: http.StatusNoContent, wantStored: 1},
		{name: "missing signature is rejected", req: request{body: validBody, event: "workflow_job"}, wantStatus: http.StatusUnauthorized, wantSigFailures: 1},
		{name: "signature from another secret is rejected", req: request{body: validBody, signature: signBody("guess", validBody), event: "workflow_job"}, wantStatus: http.StatusUnauthorized, wantSigFailures: 1},
		{name: "body altered after signing is rejected", req: request{body: bytes.Replace(validBody, []byte("success"), []byte("skipped"), 1), signature: signBody(testWebhookSecret, validBody), event: "workflow_job"}, wantStatus: http.StatusUnauthorized, wantSigFailures: 1},
		{name: "unsigned garbage gets 401, proving nothing is parsed before the signature check", req: request{body: []byte("{not json"), event: "workflow_job"}, wantStatus: http.StatusUnauthorized, wantSigFailures: 1},
		{name: "oversize body is refused even when correctly signed", req: signed(oversize, "workflow_job"), wantStatus: http.StatusRequestEntityTooLarge},
		{name: "ping from hook setup is acknowledged without storing", req: signed([]byte(`{"zen":"Keep it logically awesome."}`), "ping"), wantStatus: http.StatusNoContent},
		{name: "other signed events are acknowledged and ignored", req: signed(validBody, "workflow_run"), wantStatus: http.StatusNoContent},
		{name: "missing event header is ignored, not stored", req: signed(validBody, ""), wantStatus: http.StatusNoContent},
		{name: "signed but malformed JSON is a bad request", req: signed([]byte("{not json"), "workflow_job"), wantStatus: http.StatusBadRequest},
		{name: "payload without a job id cannot be keyed", req: signed([]byte(`{"action":"completed","workflow_job":{"status":"completed"},"repository":{"full_name":"acme/example","html_url":"https://github.com/acme/example"}}`), "workflow_job"), wantStatus: http.StatusBadRequest},
		{name: "payload without a repository cannot be keyed", req: signed([]byte(`{"action":"queued","workflow_job":{"id":1,"status":"queued"}}`), "workflow_job"), wantStatus: http.StatusBadRequest},
		{name: "payload without a repository URL has no provider host", req: signed([]byte(`{"action":"queued","workflow_job":{"id":1,"status":"queued"},"repository":{"full_name":"acme/example"}}`), "workflow_job"), wantStatus: http.StatusBadRequest},
		{name: "payload without a status cannot be ordered", req: signed([]byte(`{"action":"queued","workflow_job":{"id":1},"repository":{"full_name":"acme/example","html_url":"https://github.com/acme/example"}}`), "workflow_job"), wantStatus: http.StatusBadRequest},
		{name: "completed job without completed_at could never leave the grace period", req: signed([]byte(`{"action":"completed","workflow_job":{"id":1,"status":"completed"},"repository":{"full_name":"acme/example","html_url":"https://github.com/acme/example"}}`), "workflow_job"), wantStatus: http.StatusBadRequest},
		{name: "store failure returns 5xx so GitHub marks the delivery failed", req: signed(validBody, "workflow_job"), storeErr: storeErr, wantStatus: http.StatusInternalServerError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			store := &recordingProviderJobStore{err: tc.storeErr}
			handler, metrics := newTestWebhook(t, store)

			req := httptest.NewRequest(http.MethodPost, "/webhook/github", bytes.NewReader(tc.req.body))
			if tc.req.signature != "" {
				req.Header.Set(githubSignatureHeader, tc.req.signature)
			}
			if tc.req.event != "" {
				req.Header.Set(githubEventHeader, tc.req.event)
			}
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, req)

			if recorder.Code != tc.wantStatus {
				t.Fatalf("status: got %d, want %d (body %q)", recorder.Code, tc.wantStatus, recorder.Body.String())
			}
			if got := len(store.jobs); got != tc.wantStored {
				t.Fatalf("stored jobs: got %d, want %d", got, tc.wantStored)
			}
			if got := metrics.webhookSignatureFailures.Load(); got != tc.wantSigFailures {
				t.Fatalf("signature failures: got %d, want %d", got, tc.wantSigFailures)
			}
		})
	}
}

func TestGitHubWebhookHandler_OnlyPOSTIsRouted(t *testing.T) {
	t.Parallel()

	store := &recordingProviderJobStore{}
	webhook, _ := newTestWebhook(t, store)
	handler := newHTTPHandler(fakePinger{}, &Metrics{}, webhook)
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(method, "/webhook/github", nil))
		if recorder.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s /webhook/github: got %d, want %d", method, recorder.Code, http.StatusMethodNotAllowed)
		}
	}
	if len(store.jobs) != 0 {
		t.Fatal("non-POST requests must not reach the store")
	}
}

// TestGitHubWebhookHandler_RealJobObjects feeds every job object GitHub
// returned through the handler and checks the fields the verdict depends on.
func TestGitHubWebhookHandler_RealJobObjects(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		file        string
		action      string
		jobID       int64
		wantStatus  string
		wantRunner  string
		wantSteps   int
		wantRan     bool
		wantVerdict Verdict
	}{
		{name: "matrix-style job with a custom name", file: "main-jobs.json", action: "completed", jobID: 136504227286, wantStatus: "completed", wantRunner: "GitHub Actions 1001602055", wantSteps: 3, wantRan: true, wantVerdict: VerdictNoStart},
		{name: "job with composite steps", file: "main-jobs.json", action: "completed", jobID: 136504227514, wantStatus: "completed", wantRunner: "GitHub Actions 1001602054", wantSteps: 6, wantRan: true, wantVerdict: VerdictNoStart},
		{name: "job inside a reusable workflow", file: "main-jobs.json", action: "completed", jobID: 136504227905, wantStatus: "completed", wantRunner: "GitHub Actions 1001602053", wantSteps: 3, wantRan: true, wantVerdict: VerdictNoStart},
		{name: "skipped job has a null runner_name and no steps", file: "main-jobs.json", action: "completed", jobID: 136504229528, wantStatus: "completed", wantRan: false, wantVerdict: VerdictNotExpected},
		{name: "job cancelled while queued has an empty runner_name and no steps", file: "queued-after-cancel.json", action: "completed", jobID: 136504229348, wantStatus: "completed", wantRan: false, wantVerdict: VerdictNotExpected},
		{name: "queued job has null conclusion, runner_name and completed_at", file: "queued-before-cancel.json", action: "queued", jobID: 136504229348, wantStatus: "queued", wantRan: false, wantVerdict: VerdictNotExpected},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			raw, ok := loadJobObjects(t, tc.file)[tc.jobID]
			if !ok {
				t.Fatalf("job %d not in %s", tc.jobID, tc.file)
			}
			body := webhookBody(t, tc.action, raw)
			store := &recordingProviderJobStore{}
			handler, _ := newTestWebhook(t, store)
			req := httptest.NewRequest(http.MethodPost, "/webhook/github", bytes.NewReader(body))
			req.Header.Set(githubSignatureHeader, signBody(testWebhookSecret, body))
			req.Header.Set(githubEventHeader, workflowJobEvent)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, req)
			if recorder.Code != http.StatusNoContent {
				t.Fatalf("status: got %d (body %q)", recorder.Code, recorder.Body.String())
			}
			if len(store.jobs) != 1 {
				t.Fatalf("stored jobs: got %d, want 1", len(store.jobs))
			}
			got := store.jobs[0]
			wantKey := JobKey{ProviderHost: "github.com", Repository: "acme/example", CheckRunID: tc.jobID}
			if got.JobKey != wantKey {
				t.Errorf("key: got %+v, want %+v", got.JobKey, wantKey)
			}
			if got.Status != tc.wantStatus || got.RunnerName != tc.wantRunner || got.StepCount != tc.wantSteps {
				t.Errorf("status/runner/steps: got %q/%q/%d, want %q/%q/%d", got.Status, got.RunnerName, got.StepCount, tc.wantStatus, tc.wantRunner, tc.wantSteps)
			}
			if got.RunID == 0 || got.RunAttempt != 1 || got.JobName == "" || got.WorkflowName == "" || len(got.Labels) == 0 {
				t.Errorf("descriptive fields not decoded: %+v", got)
			}
			if got.StartedAt == nil {
				t.Error("started_at is set by GitHub for every job, including ones that never ran")
			}
			if (got.CompletedAt != nil) != (tc.wantStatus == "completed") {
				t.Errorf("completed_at presence: got %v for status %q", got.CompletedAt, tc.wantStatus)
			}
			job := Job{ProviderJob: got}
			if job.RanOnRunner() != tc.wantRan {
				t.Errorf("RanOnRunner: got %v, want %v", job.RanOnRunner(), tc.wantRan)
			}
			if verdict := Decide(job, Expectation{}); verdict != tc.wantVerdict {
				t.Errorf("verdict with no records: got %q, want %q", verdict, tc.wantVerdict)
			}
		})
	}
}

// TestGitHubWebhookHandler_RealDeliveries replays captured workflow_job
// deliveries, in the order GitHub sent them and in a shuffled order.
func TestGitHubWebhookHandler_RealDeliveries(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name         string
		file         string
		wantStatus   string
		wantRunner   string
		wantSteps    int
		wantComplete bool
		wantRan      bool
	}{
		{name: "queued event has no runner and no steps yet", file: "queued-ran.json", wantStatus: "queued"},
		{name: "in_progress event already names the runner and lists steps", file: "in_progress-ran.json", wantStatus: "in_progress", wantRunner: "GitHub Actions 1001602080", wantSteps: 3, wantRan: true},
		{name: "completed event of a job that ran", file: "completed-ran.json", wantStatus: "completed", wantRunner: "GitHub Actions 1001602080", wantSteps: 3, wantComplete: true, wantRan: true},
		{name: "skipped job arrives as a single completed event with a null runner", file: "completed-skipped.json", wantStatus: "completed", wantComplete: true},
		{name: "job waiting for a runner that does not exist", file: "queued-never-picked-up.json", wantStatus: "queued"},
		{name: "job cancelled while queued completes with an empty runner name", file: "completed-cancelled-while-queued.json", wantStatus: "completed", wantComplete: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			body, err := os.ReadFile(filepath.Join("testdata", "webhooks", tc.file))
			if err != nil {
				t.Fatalf("read delivery: %v", err)
			}
			store := &recordingProviderJobStore{}
			handler, _ := newTestWebhook(t, store)
			req := httptest.NewRequest(http.MethodPost, "/webhook/github", bytes.NewReader(body))
			req.Header.Set(githubSignatureHeader, signBody(testWebhookSecret, body))
			req.Header.Set(githubEventHeader, workflowJobEvent)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, req)
			if recorder.Code != http.StatusNoContent {
				t.Fatalf("status: got %d (body %q)", recorder.Code, recorder.Body.String())
			}
			if len(store.jobs) != 1 {
				t.Fatalf("stored jobs: got %d, want 1", len(store.jobs))
			}
			got := store.jobs[0]
			if got.ProviderHost != "github.com" || got.Repository != "acme/example" || got.CheckRunID == 0 {
				t.Errorf("key: got %+v", got.JobKey)
			}
			if got.RunAttempt != 2 {
				t.Errorf("run_attempt: got %d, want 2 (these are re-run deliveries)", got.RunAttempt)
			}
			if got.Status != tc.wantStatus || got.RunnerName != tc.wantRunner || got.StepCount != tc.wantSteps {
				t.Errorf("status/runner/steps: got %q/%q/%d, want %q/%q/%d", got.Status, got.RunnerName, got.StepCount, tc.wantStatus, tc.wantRunner, tc.wantSteps)
			}
			if (got.CompletedAt != nil) != tc.wantComplete {
				t.Errorf("completed_at: got %v, want set=%v", got.CompletedAt, tc.wantComplete)
			}
			if ran := (Job{ProviderJob: got}).RanOnRunner(); ran != tc.wantRan {
				t.Errorf("RanOnRunner: got %v, want %v", ran, tc.wantRan)
			}
		})
	}
}

func TestProviderHostFromURL(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		rawURL  string
		want    string
		wantErr bool
	}{
		{name: "github.com repository", rawURL: "https://github.com/acme/example", want: "github.com"},
		{name: "enterprise host is lower-cased and loses its port", rawURL: "https://GHE.Example.com:8443/acme/example", want: "ghe.example.com"},
		{name: "empty URL", rawURL: "", wantErr: true},
		{name: "relative URL has no host", rawURL: "/acme/example", wantErr: true},
		{name: "unparseable URL", rawURL: "https://%zz", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := providerHostFromURL(tc.rawURL)
			if (err != nil) != tc.wantErr {
				t.Fatalf("providerHostFromURL error: got %v, wantErr %v", err, tc.wantErr)
			}
			if got != tc.want {
				t.Fatalf("providerHostFromURL: got %q, want %q", got, tc.want)
			}
		})
	}
}
