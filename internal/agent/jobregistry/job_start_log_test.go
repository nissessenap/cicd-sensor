package jobregistry_test

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/jobregistry"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/kerneltracker"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/managerclient"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	logv1beta1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/log/v1beta1"
	managerv1beta1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/manager/v1beta1"
	"github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/manager/v1beta1/managerv1beta1connect"
)

// fakeCollector is a CollectorService that keeps every ingested batch. Set
// fail to make every IngestLog return an error.
type fakeCollector struct {
	mu      sync.Mutex
	batches []*managerv1beta1.IngestLogBatch
	calls   int
	fail    bool
}

func (c *fakeCollector) IngestLog(_ context.Context, req *connect.Request[managerv1beta1.IngestLogRequest]) (*connect.Response[managerv1beta1.IngestLogResponse], error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	if c.fail {
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("collector down"))
	}
	c.batches = append(c.batches, req.Msg.GetBatch())
	return connect.NewResponse(&managerv1beta1.IngestLogResponse{ReceivedBatches: 1}), nil
}

func (c *fakeCollector) callCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

func (c *fakeCollector) batchesOfType(logType managerv1beta1.LogType) []*managerv1beta1.IngestLogBatch {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []*managerv1beta1.IngestLogBatch
	for _, batch := range c.batches {
		if batch.GetLogType() == logType {
			out = append(out, batch)
		}
	}
	return out
}

// jobStartEntries decodes every job_start record the collector received.
func (c *fakeCollector) jobStartEntries(t *testing.T) []*logv1beta1.JobStartLogEntry {
	t.Helper()
	var entries []*logv1beta1.JobStartLogEntry
	for _, batch := range c.batchesOfType(managerv1beta1.LogType_LOG_TYPE_JOB_START) {
		reader, err := gzip.NewReader(bytes.NewReader(batch.GetCompressedJsonl()))
		if err != nil {
			t.Fatalf("gunzip job start batch: %v", err)
		}
		scanner := bufio.NewScanner(reader)
		for scanner.Scan() {
			entry := &logv1beta1.JobStartLogEntry{}
			if err := protojson.Unmarshal(scanner.Bytes(), entry); err != nil {
				t.Fatalf("decode job start record %q: %v", scanner.Bytes(), err)
			}
			entries = append(entries, entry)
		}
		if err := scanner.Err(); err != nil {
			t.Fatalf("scan job start batch: %v", err)
		}
	}
	return entries
}

func newFakeCollector(t *testing.T) (*fakeCollector, managerclient.Connection) {
	t.Helper()
	collector := &fakeCollector{}
	mux := http.NewServeMux()
	mux.Handle(managerv1beta1connect.NewCollectorServiceHandler(collector))
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return collector, managerclient.Connection{BaseURL: server.URL, Token: "sk_cs_test"}
}

func jobStartRouted() *recordingFetcher {
	return &recordingFetcher{result: managerclient.FetchResult{
		ConfigRevision: "config-sha",
		OutputSettings: &managerv1beta1.OutputSettings{
			JobStart: &managerv1beta1.OutputSetting{Enabled: true},
		},
	}}
}

func jobStartNotRouted() *recordingFetcher {
	return &recordingFetcher{result: managerclient.FetchResult{
		OutputSettings: &managerv1beta1.OutputSettings{
			Summary: &managerv1beta1.OutputSetting{Enabled: true},
		},
	}}
}

func waitForJobStartEntries(t *testing.T, collector *fakeCollector, want int) []*logv1beta1.JobStartLogEntry {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if entries := collector.jobStartEntries(t); len(entries) >= want {
			return entries
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("job start records: got %d, want %d", len(collector.jobStartEntries(t)), want)
	return nil
}

func entryForScope(t *testing.T, entries []*logv1beta1.JobStartLogEntry, scope jobcontext.ScopeType) *logv1beta1.JobStartLogEntry {
	t.Helper()
	var found *logv1beta1.JobStartLogEntry
	for _, entry := range entries {
		if entry.GetScope() != string(scope) {
			continue
		}
		if found != nil {
			t.Fatalf("scope %s emitted more than one job start record", scope)
		}
		found = entry
	}
	if found == nil {
		t.Fatalf("scope %s emitted no job start record", scope)
	}
	return found
}

func TestJobRegistry_JobStartLog_GitHubHostStart(t *testing.T) {
	t.Parallel()

	collector, conn := newFakeCollector(t)
	jr := newJobRegistry(t)
	id := jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "runner-1")

	job, err := jr.ApplyGitHubHostStart(testCtx, id, jobcontext.JobMetadata{CommitSHA: "abc123"}, "machine", 0, conn, jobStartRouted())
	if err != nil {
		t.Fatalf("ApplyGitHubHostStart: %v", err)
	}
	if job.HostScope() == nil {
		t.Fatal("host scope must be attached before the start record is emitted")
	}

	entry := entryForScope(t, waitForJobStartEntries(t, collector, 1), jobcontext.ScopeTypeHost)
	if got, want := entry.GetJob().GetGithubRunId(), "123"; got != want {
		t.Fatalf("job.github_run_id: got %q, want %q", got, want)
	}
	if got, want := entry.GetJob().GetCommitSha(), "abc123"; got != want {
		t.Fatalf("job.commit_sha: got %q, want %q", got, want)
	}
	if got, want := entry.GetRunnerType(), "machine"; got != want {
		t.Fatalf("runner_type: got %q, want %q", got, want)
	}
	if got, want := entry.GetConfigRevision(), "config-sha"; got != want {
		t.Fatalf("config_revision: got %q, want %q", got, want)
	}
	if got := entry.GetJob().GetGithubCheckRunId(); got != "" {
		t.Fatalf("hook-started job must not report a check run id, got %q", got)
	}

	jr.FinalizeAll(testCtx, kerneltracker.EndShutdown)
	if got := len(collector.jobStartEntries(t)); got != 1 {
		t.Fatalf("job start records after finalize: got %d, want 1", got)
	}
}

func TestJobRegistry_JobStartLog_GitHubProjectOnly(t *testing.T) {
	t.Parallel()

	collector, conn := newFakeCollector(t)
	jr := newJobRegistry(t)
	id := jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "matrix", "1", "runner-1")

	if _, err := jr.ApplyGitHubProjectStart(testCtx, jobregistry.GitHubProjectStartConfig{
		Identity:          id,
		Metadata:          jobcontext.JobMetadata{GitHubCheckRunID: "88812345678"},
		RunnerType:        "machine",
		ManagerConnection: conn,
		ManagerClient:     jobStartRouted(),
	}); err != nil {
		t.Fatalf("ApplyGitHubProjectStart: %v", err)
	}

	entry := entryForScope(t, waitForJobStartEntries(t, collector, 1), jobcontext.ScopeTypeProject)
	if got, want := entry.GetJob().GetGithubCheckRunId(), "88812345678"; got != want {
		t.Fatalf("job.github_check_run_id: got %q, want %q", got, want)
	}
	batches := collector.batchesOfType(managerv1beta1.LogType_LOG_TYPE_JOB_START)
	if got, want := batches[0].GetJobIdentity().GetGithubCheckRunId(), "88812345678"; got != want {
		t.Fatalf("wire job_identity.github_check_run_id: got %q, want %q", got, want)
	}
	if got, want := batches[0].GetScope(), managerv1beta1.Scope_SCOPE_PROJECT; got != want {
		t.Fatalf("batch scope: got %s, want %s", got, want)
	}
}

func TestJobRegistry_JobStartLog_ProjectAttachedToHostJobKeepsScopesSeparate(t *testing.T) {
	t.Parallel()

	hostCollector, hostConn := newFakeCollector(t)
	projectCollector, projectConn := newFakeCollector(t)
	jr := newJobRegistry(t)
	id := jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "runner-1")

	if _, err := jr.ApplyGitHubHostStart(testCtx, id, jobcontext.JobMetadata{}, "machine", 0, hostConn, jobStartRouted()); err != nil {
		t.Fatalf("ApplyGitHubHostStart: %v", err)
	}
	if _, err := jr.ApplyGitHubProjectStart(testCtx, jobregistry.GitHubProjectStartConfig{
		Identity:          id,
		Metadata:          jobcontext.JobMetadata{GitHubCheckRunID: "88812345678"},
		RunnerType:        "machine",
		ManagerConnection: projectConn,
		ManagerClient:     jobStartRouted(),
	}); err != nil {
		t.Fatalf("ApplyGitHubProjectStart: %v", err)
	}

	hostEntry := entryForScope(t, waitForJobStartEntries(t, hostCollector, 1), jobcontext.ScopeTypeHost)
	projectEntry := entryForScope(t, waitForJobStartEntries(t, projectCollector, 1), jobcontext.ScopeTypeProject)
	if got := hostEntry.GetJob().GetGithubCheckRunId(); got != "" {
		t.Fatalf("host scope record must not learn the project start's check run id, got %q", got)
	}
	// The Job was created by host start, so its metadata has no check run id;
	// the project scope must still report the one its own start supplied.
	if got, want := projectEntry.GetJob().GetGithubCheckRunId(), "88812345678"; got != want {
		t.Fatalf("project job.github_check_run_id: got %q, want %q", got, want)
	}
	if got := len(hostCollector.jobStartEntries(t)); got != 1 {
		t.Fatalf("host manager job start records: got %d, want 1", got)
	}
	if got := len(projectCollector.jobStartEntries(t)); got != 1 {
		t.Fatalf("project manager job start records: got %d, want 1", got)
	}
}

func TestJobRegistry_JobStartLog_GitLabLazyStartEmitsOnce(t *testing.T) {
	t.Parallel()

	collector, conn := newFakeCollector(t)
	jr := newJobRegistry(t)
	id := jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "14274377073")

	// Docker proxy calls repeat host start for the same job.
	for range 3 {
		if _, err := jr.ApplyGitLabHostStart(testCtx, id, jobcontext.JobMetadata{}, "machine", conn, jobStartRouted()); err != nil {
			t.Fatalf("ApplyGitLabHostStart: %v", err)
		}
	}

	entry := entryForScope(t, waitForJobStartEntries(t, collector, 1), jobcontext.ScopeTypeHost)
	if got, want := entry.GetJob().GetGitlabJobId(), "14274377073"; got != want {
		t.Fatalf("job.gitlab_job_id: got %q, want %q", got, want)
	}
	jr.FinalizeAll(testCtx, kerneltracker.EndShutdown)
	if got := len(collector.jobStartEntries(t)); got != 1 {
		t.Fatalf("job start records: got %d, want 1", got)
	}
}

func TestJobRegistry_JobStartLog_NotEmittedUnlessRouted(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		fetcher *recordingFetcher
	}{
		{name: "manager routes other log types only", fetcher: jobStartNotRouted()},
		{name: "manager serves no output settings", fetcher: &recordingFetcher{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			collector, conn := newFakeCollector(t)
			jr := newJobRegistry(t)
			id := jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "runner-1")

			if _, err := jr.ApplyGitHubProjectStart(testCtx, jobregistry.GitHubProjectStartConfig{
				Identity:          id,
				Metadata:          jobcontext.JobMetadata{GitHubCheckRunID: "88812345678"},
				RunnerType:        "machine",
				ManagerConnection: conn,
				ManagerClient:     tc.fetcher,
			}); err != nil {
				t.Fatalf("ApplyGitHubProjectStart: %v", err)
			}
			// Finalize drains every worker, so anything emitted has arrived.
			jr.FinalizeAll(testCtx, kerneltracker.EndShutdown)
			if got := len(collector.jobStartEntries(t)); got != 0 {
				t.Fatalf("job start records: got %d, want 0", got)
			}
		})
	}
}

func TestJobRegistry_JobStartLog_LocalConfigProjectEmitsNothing(t *testing.T) {
	t.Parallel()

	jr := newJobRegistry(t)
	id := jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "runner-1")
	job, err := jr.ApplyGitHubProjectStart(testCtx, jobregistry.GitHubProjectStartConfig{
		Identity:   id,
		Metadata:   jobcontext.JobMetadata{GitHubCheckRunID: "88812345678"},
		RunnerType: "machine",
	})
	if err != nil {
		t.Fatalf("ApplyGitHubProjectStart: %v", err)
	}
	if job.ProjectScope().ManagerJobLogsForTesting().HasJobStartLog() {
		t.Fatal("project-local config has no manager and must not create a job start output")
	}
}

func TestJobRegistry_JobStartLog_SendFailureDoesNotFailStart(t *testing.T) {
	t.Parallel()

	collector, conn := newFakeCollector(t)
	collector.fail = true
	jr := newJobRegistry(t)
	id := jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "runner-1")

	job, err := jr.ApplyGitHubProjectStart(testCtx, jobregistry.GitHubProjectStartConfig{
		Identity:          id,
		RunnerType:        "machine",
		ManagerConnection: conn,
		ManagerClient:     jobStartRouted(),
	})
	if err != nil {
		t.Fatalf("start must succeed while the collector is down: %v", err)
	}
	if job.ProjectScope() == nil {
		t.Fatal("project scope must stay attached")
	}
	deadline := time.Now().Add(5 * time.Second)
	for collector.callCount() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if collector.callCount() == 0 {
		t.Fatal("job start record was never attempted")
	}
	if registeredJob(jr, id) == nil {
		t.Fatal("job must stay registered after a failed start record")
	}
}

func TestJobRegistry_JobStartLog_CancelledStartRequestStillDelivers(t *testing.T) {
	t.Parallel()

	collector, conn := newFakeCollector(t)
	jr := newJobRegistry(t)
	id := jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "runner-1")

	// The listener passes the HTTP request context, which ends when the
	// hook's request returns. An already-ended context is the worst case.
	requestCtx, finishRequest := context.WithCancel(testCtx)
	finishRequest()
	if _, err := jr.ApplyGitHubProjectStart(requestCtx, jobregistry.GitHubProjectStartConfig{
		Identity:          id,
		RunnerType:        "machine",
		ManagerConnection: conn,
		ManagerClient:     jobStartRouted(),
	}); err != nil {
		t.Fatalf("ApplyGitHubProjectStart: %v", err)
	}
	waitForJobStartEntries(t, collector, 1)
}
