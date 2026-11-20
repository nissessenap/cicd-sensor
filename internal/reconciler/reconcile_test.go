package reconciler

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

var testLogger = slog.New(slog.NewTextHandler(io.Discard, nil))

// fakeVerdictStore serves pending jobs and records verdicts the way Store
// does: a failed decide leaves that job, and the ones after it, pending.
type fakeVerdictStore struct {
	mu       sync.Mutex
	pending  []Job
	verdicts map[int64]Verdict

	decideErr     error
	deleteErr     error
	countErr      error
	orphans       int64
	deleteCutoff  time.Time
	decideCutoffs []time.Time
}

func (s *fakeVerdictStore) DecidePending(ctx context.Context, completedBefore, _ time.Time, limit int, decide func(context.Context, Job) (Verdict, error)) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.decideCutoffs = append(s.decideCutoffs, completedBefore)
	if s.decideErr != nil {
		return 0, s.decideErr
	}
	if s.verdicts == nil {
		s.verdicts = make(map[int64]Verdict)
	}
	for decided := range limit {
		if len(s.pending) == 0 {
			return decided, nil
		}
		job := s.pending[0]
		verdict, err := decide(ctx, job)
		if err != nil {
			return decided, err
		}
		s.verdicts[job.CheckRunID] = verdict
		s.pending = s.pending[1:]
	}
	return limit, nil
}

func (s *fakeVerdictStore) DeleteOlderThan(_ context.Context, cutoff time.Time) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deleteCutoff = cutoff
	return 0, s.deleteErr
}

func (s *fakeVerdictStore) CountRecordsWithoutProviderJob(context.Context, time.Time) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.orphans, s.countErr
}

type recordingPublisher struct {
	mu       sync.Mutex
	findings []Finding
	attempts []Finding
	timeouts []time.Duration
	err      error
	// failCheckRunID makes only that job's publish fail.
	failCheckRunID int64
}

func (p *recordingPublisher) Publish(ctx context.Context, finding Finding) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.attempts = append(p.attempts, finding)
	if deadline, ok := ctx.Deadline(); ok {
		p.timeouts = append(p.timeouts, time.Until(deadline))
	}
	if p.err != nil && (p.failCheckRunID == 0 || p.failCheckRunID == finding.CheckRunID) {
		return p.err
	}
	p.findings = append(p.findings, finding)
	return nil
}

func completedJob(checkRunID int64, mutate func(*Job)) Job {
	completedAt := time.Date(2026, 11, 20, 19, 3, 16, 0, time.UTC)
	job := Job{ProviderJob: ProviderJob{
		JobKey:       JobKey{ProviderHost: "github.com", Repository: "acme/api", CheckRunID: checkRunID},
		RunID:        44798508261,
		RunAttempt:   1,
		JobName:      "custom name b",
		WorkflowName: "verify-check-run-id",
		Labels:       []string{"ubuntu-latest"},
		RunnerName:   "GitHub Actions 1001602055",
		StepCount:    3,
		Status:       "completed",
		Conclusion:   "success",
		CompletedAt:  &completedAt,
	}}
	if mutate != nil {
		mutate(&job)
	}
	return job
}

func testReconciler(store verdictStore, publisher FindingPublisher) (*Reconciler, *Metrics) {
	metrics := &Metrics{}
	cfg := ReconcilerConfig{
		GracePeriod: 5 * time.Minute,
		Retention:   30 * 24 * time.Hour,
		Metrics:     metrics,
		Logger:      testLogger,
	}
	if publisher != nil {
		cfg.Publisher = publisher
	}
	r := NewReconciler(store, cfg)
	r.now = func() time.Time { return time.Date(2026, 11, 20, 20, 0, 0, 0, time.UTC) }
	return r, metrics
}

func TestReconcileOnce_EmitsOneFindingPerMissingTelemetryJob(t *testing.T) {
	t.Parallel()

	seen := time.Date(2026, 11, 20, 19, 3, 14, 0, time.UTC)
	store := &fakeVerdictStore{
		orphans: 2,
		pending: []Job{
			completedJob(1, func(j *Job) { j.StartSeenAt, j.SummarySeenAt = &seen, &seen }),
			completedJob(2, func(j *Job) { j.StartSeenAt = &seen }),
			completedJob(3, nil),
			completedJob(4, func(j *Job) { j.Conclusion, j.RunnerName, j.StepCount = "skipped", "", 0 }),
		},
	}
	publisher := &recordingPublisher{}
	r, metrics := testReconciler(store, publisher)

	if err := r.ReconcileOnce(t.Context()); err != nil {
		t.Fatalf("ReconcileOnce: %v", err)
	}

	wantVerdicts := map[int64]Verdict{1: VerdictOK, 2: VerdictNoSummary, 3: VerdictNoStart, 4: VerdictNotExpected}
	for id, want := range wantVerdicts {
		if got := store.verdicts[id]; got != want {
			t.Errorf("verdict for job %d: got %q, want %q", id, got, want)
		}
	}
	if len(publisher.findings) != 2 {
		t.Fatalf("published findings: got %d, want 2", len(publisher.findings))
	}
	byJob := map[int64]Finding{}
	for _, finding := range publisher.findings {
		byJob[finding.CheckRunID] = finding
	}
	noSummary := byJob[2]
	if noSummary.Verdict != VerdictNoSummary || noSummary.StartSeenAt == nil || noSummary.SummarySeenAt != nil {
		t.Errorf("no_summary finding: got %+v", noSummary)
	}
	noStart := byJob[3]
	if noStart.Verdict != VerdictNoStart || noStart.StartSeenAt != nil {
		t.Errorf("no_start finding: got %+v", noStart)
	}
	if got, want := noStart.JobLink, "https://github.com/acme/api/actions/runs/44798508261/job/3"; got != want {
		t.Errorf("job_link: got %q, want %q", got, want)
	}
	if noStart.LogType != FindingLogType || noStart.SchemaVersion != FindingSchemaVersion || noStart.LogID == "" {
		t.Errorf("finding envelope: got %+v", noStart)
	}
	if got := metrics.findingsNoStart.Load(); got != 1 {
		t.Errorf("no_start findings counter: got %d, want 1", got)
	}
	if got := metrics.findingsNoSummary.Load(); got != 1 {
		t.Errorf("no_summary findings counter: got %d, want 1", got)
	}
	if got := metrics.recordsWithoutProviderJob.Load(); got != 2 {
		t.Errorf("records without provider job gauge: got %d, want 2", got)
	}

	now := r.now()
	if got, want := store.decideCutoffs[0], now.Add(-5*time.Minute); !got.Equal(want) {
		t.Errorf("grace cutoff: got %s, want %s", got, want)
	}
	if got, want := store.deleteCutoff, now.Add(-30*24*time.Hour); !got.Equal(want) {
		t.Errorf("retention cutoff: got %s, want %s", got, want)
	}
}

func TestReconcileOnce_WithoutPublisherStillCountsAndStoresVerdict(t *testing.T) {
	t.Parallel()

	store := &fakeVerdictStore{pending: []Job{completedJob(1, nil)}}
	r, metrics := testReconciler(store, nil)

	if err := r.ReconcileOnce(t.Context()); err != nil {
		t.Fatalf("ReconcileOnce: %v", err)
	}
	if got := store.verdicts[1]; got != VerdictNoStart {
		t.Fatalf("verdict: got %q, want %q", got, VerdictNoStart)
	}
	if got := metrics.findingsNoStart.Load(); got != 1 {
		t.Fatalf("findings counter: got %d, want 1", got)
	}
}

func TestReconcileOnce_DrainsMoreThanOneBatch(t *testing.T) {
	t.Parallel()

	store := &fakeVerdictStore{}
	for id := range int64(decideBatchSize + 1) {
		store.pending = append(store.pending, completedJob(id+1, nil))
	}
	r, metrics := testReconciler(store, nil)

	if err := r.ReconcileOnce(t.Context()); err != nil {
		t.Fatalf("ReconcileOnce: %v", err)
	}
	if got, want := len(store.verdicts), decideBatchSize+1; got != want {
		t.Fatalf("decided jobs: got %d, want %d", got, want)
	}
	if got, want := metrics.findingsNoStart.Load(), uint64(decideBatchSize+1); got != want {
		t.Fatalf("findings counter: got %d, want %d", got, want)
	}
}

func TestReconcileOnce_PublishFailureLeavesJobUndecided(t *testing.T) {
	t.Parallel()

	publishErr := errors.New("pubsub unavailable")
	store := &fakeVerdictStore{pending: []Job{completedJob(1, nil)}}
	publisher := &recordingPublisher{err: publishErr}
	r, metrics := testReconciler(store, publisher)

	err := r.ReconcileOnce(t.Context())
	if !errors.Is(err, publishErr) {
		t.Fatalf("ReconcileOnce error: got %v, want %v", err, publishErr)
	}
	if _, decided := store.verdicts[1]; decided {
		t.Fatal("a job whose finding could not be published must stay undecided")
	}
	if got := metrics.findingsNoStart.Load(); got != 0 {
		t.Fatalf("findings counter: got %d, want 0", got)
	}

	// The next pass retries and succeeds.
	publisher.mu.Lock()
	publisher.err = nil
	publisher.mu.Unlock()
	if err := r.ReconcileOnce(t.Context()); err != nil {
		t.Fatalf("ReconcileOnce retry: %v", err)
	}
	if got := store.verdicts[1]; got != VerdictNoStart {
		t.Fatalf("verdict after retry: got %q, want %q", got, VerdictNoStart)
	}
	if len(publisher.findings) != 1 {
		t.Fatalf("published findings after retry: got %d, want 1", len(publisher.findings))
	}
}

func TestReconcileOnce_StoreErrors(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("postgres down")
	cases := []struct {
		name  string
		store *fakeVerdictStore
	}{
		{name: "verdict query fails", store: &fakeVerdictStore{decideErr: sentinel}},
		{name: "retention delete fails", store: &fakeVerdictStore{deleteErr: sentinel}},
		{name: "lost-webhook count fails", store: &fakeVerdictStore{countErr: sentinel}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r, _ := testReconciler(tc.store, nil)
			if err := r.ReconcileOnce(t.Context()); !errors.Is(err, sentinel) {
				t.Fatalf("ReconcileOnce error: got %v, want %v", err, sentinel)
			}
		})
	}
}

func TestReconcileOnce_PublishFailureRetriesOnlyThatJobWithTheSameFinding(t *testing.T) {
	t.Parallel()

	publishErr := errors.New("pubsub unavailable")
	store := &fakeVerdictStore{pending: []Job{completedJob(1, nil), completedJob(2, nil), completedJob(3, nil)}}
	publisher := &recordingPublisher{err: publishErr, failCheckRunID: 2}
	r, metrics := testReconciler(store, publisher)

	if err := r.ReconcileOnce(t.Context()); !errors.Is(err, publishErr) {
		t.Fatalf("ReconcileOnce error: got %v, want %v", err, publishErr)
	}
	if got := store.verdicts[1]; got != VerdictNoStart {
		t.Fatalf("job decided before the failure: got verdict %q, want %q", got, VerdictNoStart)
	}
	if _, decided := store.verdicts[2]; decided {
		t.Fatal("the job whose finding could not be published must stay undecided")
	}

	publisher.mu.Lock()
	publisher.err = nil
	publisher.mu.Unlock()
	if err := r.ReconcileOnce(t.Context()); err != nil {
		t.Fatalf("ReconcileOnce retry: %v", err)
	}

	published := map[int64]int{}
	for _, finding := range publisher.findings {
		published[finding.CheckRunID]++
	}
	for id := range int64(3) {
		if published[id+1] != 1 {
			t.Errorf("job %d published %d times, want exactly once", id+1, published[id+1])
		}
	}
	if got := metrics.findingsNoStart.Load(); got != 3 {
		t.Errorf("findings counter: got %d, want 3", got)
	}
	logIDs := map[string]bool{}
	for _, attempt := range publisher.attempts {
		if attempt.CheckRunID == 2 {
			logIDs[attempt.LogID] = true
		}
	}
	if len(logIDs) != 1 {
		t.Errorf("log_id of the retried finding: got %d distinct values, want 1 so consumers can deduplicate", len(logIDs))
	}
	for _, timeout := range publisher.timeouts {
		if timeout <= 0 || timeout > publishTimeout {
			t.Errorf("publish deadline: got %s, want within %s", timeout, publishTimeout)
		}
	}
	if len(publisher.timeouts) != len(publisher.attempts) {
		t.Errorf("publishes with a deadline: got %d of %d", len(publisher.timeouts), len(publisher.attempts))
	}
}

func TestNewFinding_LogID(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 11, 20, 20, 0, 0, 0, time.UTC)
	base := newFinding(completedJob(1, nil), VerdictNoStart, now).LogID
	cases := []struct {
		name     string
		job      Job
		verdict  Verdict
		at       time.Time
		wantSame bool
	}{
		{name: "same job and verdict at a later time", job: completedJob(1, nil), verdict: VerdictNoStart, at: now.Add(time.Hour), wantSame: true},
		{name: "other verdict for the same job", job: completedJob(1, nil), verdict: VerdictNoSummary, at: now},
		{name: "other job", job: completedJob(2, nil), verdict: VerdictNoStart, at: now},
		{name: "same check run id in another repository", job: completedJob(1, func(j *Job) { j.Repository = "acme/web" }), verdict: VerdictNoStart, at: now},
		{name: "same check run id on another host", job: completedJob(1, func(j *Job) { j.ProviderHost = "ghe.example.com" }), verdict: VerdictNoStart, at: now},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := newFinding(tc.job, tc.verdict, tc.at).LogID
			if got == "" {
				t.Fatal("log_id is empty")
			}
			if (got == base) != tc.wantSame {
				t.Fatalf("log_id %q vs base %q: same=%t, want %t", got, base, got == base, tc.wantSame)
			}
		})
	}
}

func TestReconcilerRun_WaitsOneGracePeriodBeforeTheFirstPass(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		store := &fakeVerdictStore{pending: []Job{completedJob(1, nil)}}
		r, _ := testReconciler(store, nil)
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan error, 1)
		go func() { done <- r.Run(ctx, 30*time.Second) }()

		passes := func() int {
			synctest.Wait()
			store.mu.Lock()
			defer store.mu.Unlock()
			return len(store.decideCutoffs)
		}
		if got := passes(); got != 0 {
			t.Fatalf("passes at start: got %d, want 0", got)
		}
		time.Sleep(r.gracePeriod - time.Second)
		if got := passes(); got != 0 {
			t.Fatalf("passes just before the grace period ends: got %d, want 0", got)
		}
		time.Sleep(time.Second)
		if got := passes(); got != 1 {
			t.Fatalf("passes once the grace period has elapsed: got %d, want 1", got)
		}

		cancel()
		if err := <-done; err != nil {
			t.Errorf("Run: got %v, want nil", err)
		}
	})
}

func TestReconcilerRun_StopsDuringTheInitialWait(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		store := &fakeVerdictStore{pending: []Job{completedJob(1, nil)}}
		r, _ := testReconciler(store, nil)
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan error, 1)
		go func() { done <- r.Run(ctx, 30*time.Second) }()

		time.Sleep(time.Minute)
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Run: got %v, want nil", err)
		}
		if len(store.decideCutoffs) != 0 {
			t.Errorf("passes: got %d, want none before the grace period", len(store.decideCutoffs))
		}
	})
}

func TestReconcilerRun_KeepsTickingAfterAFailedPass(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		store := &fakeVerdictStore{decideErr: errors.New("postgres down")}
		r, metrics := testReconciler(store, nil)
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan error, 1)
		go func() { done <- r.Run(ctx, 30*time.Second) }()

		// One pass after the grace period, then one per interval.
		time.Sleep(r.gracePeriod + 65*time.Second)
		synctest.Wait()
		if got := metrics.reconcileErrors.Load(); got != 3 {
			t.Errorf("failed passes: got %d, want 3", got)
		}

		store.mu.Lock()
		store.decideErr = nil
		store.pending = []Job{completedJob(1, nil)}
		store.mu.Unlock()
		time.Sleep(30 * time.Second)
		synctest.Wait()
		store.mu.Lock()
		verdict := store.verdicts[1]
		store.mu.Unlock()
		if verdict != VerdictNoStart {
			t.Errorf("verdict after recovery: got %q, want %q", verdict, VerdictNoStart)
		}

		cancel()
		if err := <-done; err != nil {
			t.Errorf("Run: got %v, want nil", err)
		}
	})
}

func TestJobLink(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		job  Job
		want string
	}{
		{
			name: "job with a known run links to the job page",
			job:  completedJob(136504227286, nil),
			want: "https://github.com/acme/api/actions/runs/44798508261/job/136504227286",
		},
		{
			name: "job known only from a record without run id has no link",
			job:  Job{ProviderJob: ProviderJob{JobKey: JobKey{ProviderHost: "github.com", Repository: "acme/api", CheckRunID: 1}}},
			want: "",
		},
		{
			name: "zero job has no link",
			job:  Job{},
			want: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := jobLink(tc.job); got != tc.want {
				t.Fatalf("jobLink: got %q, want %q", got, tc.want)
			}
		})
	}
}

type fakePinger struct{ err error }

func (p fakePinger) Ping(context.Context) error { return p.err }

func TestHTTPHandler(t *testing.T) {
	t.Parallel()

	metrics := &Metrics{}
	metrics.countFinding(VerdictNoStart)
	metrics.countFinding(VerdictNoStart)
	metrics.countFinding(VerdictNoSummary)
	metrics.countFinding(VerdictOK)
	metrics.unjoinableRecords.Add(4)
	metrics.recordsWithoutProviderJob.Store(7)

	cases := []struct {
		name       string
		method     string
		path       string
		db         pinger
		wantStatus int
		wantBody   []string
	}{
		{name: "healthy database", method: http.MethodGet, path: "/healthz", db: fakePinger{}, wantStatus: http.StatusOK, wantBody: []string{"ok"}},
		{name: "unreachable database fails the probe", method: http.MethodGet, path: "/healthz", db: fakePinger{err: errors.New("down")}, wantStatus: http.StatusServiceUnavailable},
		{
			name: "metrics expose findings by verdict and ignore non-findings", method: http.MethodGet, path: "/metrics", db: fakePinger{}, wantStatus: http.StatusOK,
			wantBody: []string{
				`cicd_sensor_reconciler_findings_total{verdict="no_start"} 2`,
				`cicd_sensor_reconciler_findings_total{verdict="no_summary"} 1`,
				`cicd_sensor_reconciler_unjoinable_records_total 4`,
				`cicd_sensor_reconciler_records_without_provider_job 7`,
				`cicd_sensor_reconciler_webhook_signature_failures_total 0`,
			},
		},
		{name: "nothing else is exposed", method: http.MethodGet, path: "/", db: fakePinger{}, wantStatus: http.StatusNotFound},
		{name: "debug endpoints are not exposed", method: http.MethodGet, path: "/debug/pprof/", db: fakePinger{}, wantStatus: http.StatusNotFound},
		{name: "metrics are read-only", method: http.MethodPost, path: "/metrics", db: fakePinger{}, wantStatus: http.StatusMethodNotAllowed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			recorder := httptest.NewRecorder()
			newHTTPHandler(tc.db, metrics, http.NotFoundHandler()).ServeHTTP(recorder, httptest.NewRequest(tc.method, tc.path, nil))
			if recorder.Code != tc.wantStatus {
				t.Fatalf("status: got %d, want %d", recorder.Code, tc.wantStatus)
			}
			for _, want := range tc.wantBody {
				if !strings.Contains(recorder.Body.String(), want) {
					t.Errorf("body missing %q:\n%s", want, recorder.Body.String())
				}
			}
		})
	}
}
