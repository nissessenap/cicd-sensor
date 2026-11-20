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

// fakeVerdictStore serves pending jobs in batches and records verdicts the
// way Store does: a failed decide stores nothing from that batch.
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
	batch := s.pending[:min(limit, len(s.pending))]
	decided := make(map[int64]Verdict, len(batch))
	for _, job := range batch {
		verdict, err := decide(ctx, job)
		if err != nil {
			return 0, err
		}
		decided[job.CheckRunID] = verdict
	}
	if s.verdicts == nil {
		s.verdicts = make(map[int64]Verdict)
	}
	for id, verdict := range decided {
		s.verdicts[id] = verdict
	}
	s.pending = s.pending[len(batch):]
	return len(batch), nil
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
	err      error
}

func (p *recordingPublisher) Publish(_ context.Context, finding Finding) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err != nil {
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
	r := newReconciler(store, cfg)
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
	if got := metrics.FindingsTotal(VerdictNoStart); got != 1 {
		t.Errorf("no_start findings counter: got %d, want 1", got)
	}
	if got := metrics.FindingsTotal(VerdictNoSummary); got != 1 {
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
	if got := metrics.FindingsTotal(VerdictNoStart); got != 1 {
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
	if got, want := metrics.FindingsTotal(VerdictNoStart), uint64(decideBatchSize+1); got != want {
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
	if got := metrics.FindingsTotal(VerdictNoStart); got != 0 {
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

func TestReconcilerRun_KeepsTickingAfterAFailedPass(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		store := &fakeVerdictStore{decideErr: errors.New("postgres down")}
		r, metrics := testReconciler(store, nil)
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan error, 1)
		go func() { done <- r.Run(ctx, 30*time.Second) }()

		// One pass at start, then one per interval.
		time.Sleep(65 * time.Second)
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
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Errorf("Run: got %v, want context.Canceled", err)
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
