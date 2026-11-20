//go:build reconciler_e2e

// Package e2e_test drives the docker-compose stack in this directory: it
// replays fixture sensor records through the real manager, posts signed
// workflow_job webhooks to the real reconciler, and asserts on the verdicts
// in Postgres and on the findings the reconciler publishes.
package e2e_test

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"cloud.google.com/go/pubsub/v2"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/managerclient"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	logv1beta1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/log/v1beta1"
	managerv1beta1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/manager/v1beta1"
	"github.com/cicd-sensor/cicd-sensor/internal/reconciler"
)

// Defaults match docker-compose.yaml.
var (
	managerURL    = cmp.Or(os.Getenv("E2E_MANAGER_URL"), "http://127.0.0.1:18080")
	reconcilerURL = cmp.Or(os.Getenv("E2E_RECONCILER_URL"), "http://127.0.0.1:18081")
	postgresDSN   = cmp.Or(os.Getenv("E2E_POSTGRES_DSN"), "postgres://reconciler:reconciler@127.0.0.1:15432/reconciler?sslmode=disable")
	pubsubHost    = cmp.Or(os.Getenv("E2E_PUBSUB_EMULATOR_HOST"), "127.0.0.1:18085")
)

const (
	managerToken  = "sk_cs_e2e0000000000000000000000000000000000000000000000000000000000000000"
	webhookSecret = "e2e-webhook-secret"

	jobClean          = 136504227286 // start + summary
	jobKilled         = 136504227514 // start, no summary
	jobNoRecords      = 136504227688 // sensor never ran
	jobHookStarted    = 136504227905 // summary without a check run id
	jobSkipped        = 136504229528 // if: false
	jobCancelledQueue = 136504229348 // cancelled before a runner picked it up
)

func TestReconcilerEndToEnd(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()

	waitForHTTP(ctx, t, reconcilerURL+"/healthz")
	db, err := pgx.Connect(ctx, postgresDSN)
	if err != nil {
		t.Fatalf("connect postgres: %v", err)
	}
	defer db.Close(context.WithoutCancel(ctx))
	if _, err := db.Exec(ctx, `TRUNCATE jobs`); err != nil {
		t.Fatalf("truncate jobs: %v", err)
	}

	t.Setenv("PUBSUB_EMULATOR_HOST", pubsubHost)
	pubsubClient, err := pubsub.NewClient(ctx, "e2e")
	if err != nil {
		t.Fatalf("pubsub client: %v", err)
	}
	defer pubsubClient.Close()
	findings := collectFindings(ctx, t, pubsubClient)

	mainJobs := loadJobs(t, "main-jobs.json")
	queuedJob := loadJobs(t, "queued-before-cancel.json")[jobCancelledQueue]
	cancelledJob := loadJobs(t, "queued-after-cancel.json")[jobCancelledQueue]

	// GitHub tells the reconciler about a job before the sensor does.
	postWebhook(ctx, t, "queued", queuedJob, http.StatusNoContent)

	// Sensor records flow agent -> manager -> Pub/Sub -> reconciler. The
	// manager is real; only the agent is replaced by the replay.
	replayRecords(ctx, t, "clean.jsonl", "killed.jsonl", "hook-started.jsonl")
	waitFor(ctx, t, "records to reach the reconciler", func() bool {
		var seen int
		err := db.QueryRow(ctx, `
SELECT count(*) FROM jobs
WHERE (check_run_id = $1 AND start_seen_at IS NOT NULL AND summary_seen_at IS NOT NULL)
   OR (check_run_id = $2 AND start_seen_at IS NOT NULL)`, jobClean, jobKilled).Scan(&seen)
		return err == nil && seen == 2
	})

	// The jobs complete. A forged delivery must not be able to mark the
	// killed job as skipped.
	forged := bytes.Replace(webhookBody(t, "completed", mainJobs[jobKilled]), []byte(`"conclusion":"success"`), []byte(`"conclusion":"skipped"`), 1)
	postRaw(ctx, t, forged, "sha256="+strings.Repeat("0", 64), http.StatusUnauthorized)
	for _, id := range []int64{jobClean, jobKilled, jobNoRecords, jobHookStarted, jobSkipped} {
		postWebhook(ctx, t, "completed", mainJobs[id], http.StatusNoContent)
	}
	postWebhook(ctx, t, "completed", cancelledJob, http.StatusNoContent)
	// GitHub may deliver an older event late; it must not reopen the job.
	postWebhook(ctx, t, "queued", queuedJob, http.StatusNoContent)

	wantVerdicts := map[int64]reconciler.Verdict{
		jobClean:          reconciler.VerdictOK,
		jobKilled:         reconciler.VerdictNoSummary,
		jobNoRecords:      reconciler.VerdictNoStart,
		jobHookStarted:    reconciler.VerdictNoStart,
		jobSkipped:        reconciler.VerdictNotExpected,
		jobCancelledQueue: reconciler.VerdictNotExpected,
	}
	var gotVerdicts map[int64]reconciler.Verdict
	waitFor(ctx, t, "every completed job to get a verdict", func() bool {
		gotVerdicts = readVerdicts(ctx, t, db)
		return len(gotVerdicts) == len(wantVerdicts)
	})
	for id, want := range wantVerdicts {
		if got := gotVerdicts[id]; got != want {
			t.Errorf("verdict for job %d: got %q, want %q", id, got, want)
		}
	}
	var rows int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM jobs`).Scan(&rows); err != nil {
		t.Fatalf("count jobs: %v", err)
	}
	if rows != len(wantVerdicts) {
		t.Errorf("job rows: got %d, want %d (the unjoinable record must not create a row)", rows, len(wantVerdicts))
	}

	wantFindings := map[int64]reconciler.Verdict{
		jobKilled:      reconciler.VerdictNoSummary,
		jobNoRecords:   reconciler.VerdictNoStart,
		jobHookStarted: reconciler.VerdictNoStart,
	}
	waitFor(ctx, t, "findings to be published", func() bool { return findings.len() >= len(wantFindings) })
	// Give a duplicate or an unexpected finding a few reconcile passes to show up.
	time.Sleep(4 * time.Second)
	got := findings.snapshot()
	if len(got) != len(wantFindings) {
		t.Errorf("findings: got %d, want %d: %+v", len(got), len(wantFindings), got)
	}
	for _, finding := range got {
		want, ok := wantFindings[finding.CheckRunID]
		if !ok {
			t.Errorf("unexpected finding for job %d: %+v", finding.CheckRunID, finding)
			continue
		}
		if finding.Verdict != want {
			t.Errorf("finding verdict for job %d: got %q, want %q", finding.CheckRunID, finding.Verdict, want)
		}
		if finding.LogType != reconciler.FindingLogType || finding.Repository != "acme/example" || finding.ProviderHost != "github.com" {
			t.Errorf("finding envelope for job %d: %+v", finding.CheckRunID, finding)
		}
		wantLink := fmt.Sprintf("https://github.com/acme/example/actions/runs/44798508261/job/%d", finding.CheckRunID)
		if finding.JobLink != wantLink {
			t.Errorf("finding job_link: got %q, want %q", finding.JobLink, wantLink)
		}
		delete(wantFindings, finding.CheckRunID)
	}
	for id := range wantFindings {
		t.Errorf("no finding published for job %d", id)
	}

	metrics := httpGet(ctx, t, reconcilerURL+"/metrics")
	for _, want := range []string{
		`cicd_sensor_reconciler_findings_total{verdict="no_start"} 2`,
		`cicd_sensor_reconciler_findings_total{verdict="no_summary"} 1`,
		`cicd_sensor_reconciler_unjoinable_records_total 1`,
		`cicd_sensor_reconciler_webhook_signature_failures_total 1`,
	} {
		if !strings.Contains(metrics, want) {
			t.Errorf("metrics missing %q:\n%s", want, metrics)
		}
	}
}

func readVerdicts(ctx context.Context, t *testing.T, db *pgx.Conn) map[int64]reconciler.Verdict {
	t.Helper()
	rows, err := db.Query(ctx, `SELECT check_run_id, verdict FROM jobs WHERE verdict IS NOT NULL`)
	if err != nil {
		t.Fatalf("query verdicts: %v", err)
	}
	defer rows.Close()
	out := map[int64]reconciler.Verdict{}
	for rows.Next() {
		var id int64
		var verdict string
		if err := rows.Scan(&id, &verdict); err != nil {
			t.Fatalf("scan verdict: %v", err)
		}
		out[id] = reconciler.Verdict(verdict)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("read verdicts: %v", err)
	}
	return out
}

type findingCollector struct {
	mu       sync.Mutex
	findings []reconciler.Finding
}

func (c *findingCollector) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.findings)
}

func (c *findingCollector) snapshot() []reconciler.Finding {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]reconciler.Finding(nil), c.findings...)
}

// collectFindings receives from the findings subscription for the rest of
// the test. Findings left over from an earlier run are older than this
// test and are dropped.
func collectFindings(ctx context.Context, t *testing.T, client *pubsub.Client) *findingCollector {
	t.Helper()
	startedAt := time.Now().Add(-time.Second)
	collector := &findingCollector{}
	receiveCtx, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		err := client.Subscriber("findings-e2e").Receive(receiveCtx, func(_ context.Context, msg *pubsub.Message) {
			msg.Ack()
			var finding reconciler.Finding
			if err := json.Unmarshal(msg.Data, &finding); err != nil {
				t.Errorf("finding is not valid JSON: %v: %s", err, msg.Data)
				return
			}
			if finding.Timestamp.Before(startedAt) {
				return
			}
			if msg.Attributes["log_type"] != "missing_telemetry" || msg.Attributes["verdict"] != string(finding.Verdict) {
				t.Errorf("finding attributes do not match the body: %v", msg.Attributes)
			}
			collector.mu.Lock()
			collector.findings = append(collector.findings, finding)
			collector.mu.Unlock()
		})
		if err != nil && receiveCtx.Err() == nil {
			t.Errorf("receive findings: %v", err)
		}
	}()
	t.Cleanup(func() {
		stop()
		<-done
	})
	return collector
}

// loadJobs returns the real GitHub job objects from the reconciler's
// testdata, by job id.
func loadJobs(t *testing.T, file string) map[int64]json.RawMessage {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "testdata", "jobs", file))
	if err != nil {
		t.Fatalf("read job fixture: %v", err)
	}
	var listing struct {
		Jobs []json.RawMessage `json:"jobs"`
	}
	if err := json.Unmarshal(data, &listing); err != nil {
		t.Fatalf("decode job fixture %s: %v", file, err)
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

func webhookBody(t *testing.T, action string, job json.RawMessage) []byte {
	t.Helper()
	if job == nil {
		t.Fatal("job fixture missing")
	}
	// Compact keeps the fixture's field order and values byte-for-byte.
	var compact bytes.Buffer
	if err := json.Compact(&compact, job); err != nil {
		t.Fatalf("compact job fixture: %v", err)
	}
	return fmt.Appendf(nil,
		`{"action":%q,"workflow_job":%s,"repository":{"full_name":"acme/example","html_url":"https://github.com/acme/example"}}`,
		action, compact.Bytes())
}

func postWebhook(ctx context.Context, t *testing.T, action string, job json.RawMessage, wantStatus int) {
	t.Helper()
	body := webhookBody(t, action, job)
	mac := hmac.New(sha256.New, []byte(webhookSecret))
	mac.Write(body)
	postRaw(ctx, t, body, "sha256="+hex.EncodeToString(mac.Sum(nil)), wantStatus)
}

func postRaw(ctx context.Context, t *testing.T, body []byte, signature string, wantStatus int) {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reconcilerURL+"/webhook/github", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("build webhook request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GitHub-Event", "workflow_job")
	req.Header.Set("X-Hub-Signature-256", signature)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post webhook: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != wantStatus {
		dump, _ := io.ReadAll(resp.Body)
		t.Fatalf("webhook status: got %d, want %d (%s)", resp.StatusCode, wantStatus, dump)
	}
}

type recordHead struct {
	LogType string            `json:"log_type"`
	Scope   string            `json:"scope"`
	Job     map[string]string `json:"job"`
}

type batchKey struct {
	logType    string
	scope      string
	identity   jobcontext.JobIdentity
	checkRunID string
}

// replayRecords sends fixture JSONL records to the manager with the Agent's
// own managerclient, so each request (gzip JSONL batch, job identity, scope,
// bearer token) is built exactly like the Agent builds it. Every line is
// first decoded strictly into its log proto type, so a fixture cannot drift
// from the schema.
func replayRecords(ctx context.Context, t *testing.T, files ...string) {
	t.Helper()
	var order []batchKey
	batches := map[batchKey][][]byte{}
	for _, file := range files {
		fh, err := os.Open(filepath.Join("testdata", "records", file))
		if err != nil {
			t.Fatalf("open record fixture: %v", err)
		}
		scanner := bufio.NewScanner(fh)
		scanner.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
		for line := 1; scanner.Scan(); line++ {
			record := bytes.Clone(scanner.Bytes())
			if len(record) == 0 {
				continue
			}
			var head recordHead
			if err := json.Unmarshal(record, &head); err != nil {
				t.Fatalf("%s:%d: %v", file, line, err)
			}
			var msg proto.Message
			switch head.LogType {
			case "cicd_sensor.job_start":
				msg = &logv1beta1.JobStartLogEntry{}
			case "cicd_sensor.summary":
				msg = &logv1beta1.SummaryLogEntry{}
			default:
				t.Fatalf("%s:%d: unsupported log_type %q", file, line, head.LogType)
			}
			if err := protojson.Unmarshal(record, msg); err != nil {
				t.Fatalf("%s:%d: does not match the log schema: %v", file, line, err)
			}
			job := head.Job
			key := batchKey{
				logType:    head.LogType,
				scope:      head.Scope,
				identity:   jobcontext.GitHubJobIdentity(job["provider_host"], job["project_path"], job["github_run_id"], job["github_job"], job["github_run_attempt"], job["github_runner_tracking_id"]),
				checkRunID: job["github_check_run_id"],
			}
			if _, ok := batches[key]; !ok {
				order = append(order, key)
			}
			batches[key] = append(batches[key], record)
		}
		if err := scanner.Err(); err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		fh.Close()
	}

	scopes := map[string]managerv1beta1.Scope{
		"host":    managerv1beta1.Scope_SCOPE_HOST,
		"project": managerv1beta1.Scope_SCOPE_PROJECT,
	}
	logTypes := map[string]managerv1beta1.LogType{
		"cicd_sensor.job_start": managerv1beta1.LogType_LOG_TYPE_JOB_START,
		"cicd_sensor.summary":   managerv1beta1.LogType_LOG_TYPE_SUMMARY,
	}
	client := managerclient.NewCollectorServiceClient(slog.New(slog.DiscardHandler), nil, managerclient.Connection{BaseURL: managerURL, Token: managerToken})
	for _, key := range order {
		err := client.SendLogBatch(ctx, managerclient.LogBatch{
			Identity:         key.identity,
			GitHubCheckRunID: key.checkRunID,
			Scope:            scopes[key.scope],
			Type:             logTypes[key.logType],
			Records:          batches[key],
			FlushAt:          time.Now().UTC(),
		})
		if err != nil {
			t.Fatalf("send %s for job %s: %v", key.logType, key.identity.GitHubJob, err)
		}
	}
}

func httpGet(ctx context.Context, t *testing.T, url string) string {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s: %v", url, err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: status %d: %s", url, resp.StatusCode, body)
	}
	return string(body)
}

func waitForHTTP(ctx context.Context, t *testing.T, url string) {
	t.Helper()
	waitFor(ctx, t, url+" to answer", func() bool {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return false
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	})
}

func waitFor(ctx context.Context, t *testing.T, what string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) && ctx.Err() == nil {
		if condition() {
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}
