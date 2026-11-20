//go:build integration

package reconciler

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"
)

// storeTestDSNEnv names the Postgres the store tests may truncate.
const storeTestDSNEnv = "CICD_SENSOR_RECONCILER_TEST_POSTGRES_DSN"

// openTestStore returns a Store over an empty jobs table. Store tests share
// one table, so they must not run in parallel.
func openTestStore(t *testing.T) *Store {
	t.Helper()
	dsn := os.Getenv(storeTestDSNEnv)
	if dsn == "" {
		t.Skipf("%s is not set", storeTestDSNEnv)
	}
	store, err := OpenStore(t.Context(), dsn)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	t.Cleanup(store.Close)
	if _, err := store.pool.Exec(t.Context(), `TRUNCATE jobs`); err != nil {
		t.Fatalf("truncate jobs: %v", err)
	}
	return store
}

type storedJob struct {
	Job
	Verdict   string
	VerdictAt *time.Time
}

func readJob(t *testing.T, store *Store, key JobKey) (storedJob, bool) {
	t.Helper()
	key = key.normalized()
	rows, err := store.pool.Query(t.Context(), `
SELECT COALESCE(run_id, 0), COALESCE(run_attempt, 0), COALESCE(job_name, ''), COALESCE(runner_name, ''),
  COALESCE(step_count, 0), COALESCE(status, ''), COALESCE(conclusion, ''), completed_at,
  start_seen_at, summary_seen_at, COALESCE(summary_result, ''), COALESCE(finalize_reason, ''),
  COALESCE(verdict, ''), verdict_at
FROM jobs WHERE provider_host = $1 AND repository = $2 AND check_run_id = $3`,
		key.ProviderHost, key.Repository, key.CheckRunID)
	if err != nil {
		t.Fatalf("query job: %v", err)
	}
	defer rows.Close()
	if !rows.Next() {
		return storedJob{}, false
	}
	var got storedJob
	got.JobKey = key
	if err := rows.Scan(
		&got.RunID, &got.RunAttempt, &got.JobName, &got.RunnerName,
		&got.StepCount, &got.Status, &got.Conclusion, &got.CompletedAt,
		&got.StartSeenAt, &got.SummarySeenAt, &got.SummaryResult, &got.FinalizeReason,
		&got.Verdict, &got.VerdictAt,
	); err != nil {
		t.Fatalf("scan job: %v", err)
	}
	return got, true
}

var (
	storeTestKey = JobKey{ProviderHost: "github.com", Repository: "Acme/API", CheckRunID: 136504227286}
	storeT0      = time.Date(2026, 11, 20, 19, 3, 0, 0, time.UTC)
)

func providerJobAt(status string, completedAt *time.Time) ProviderJob {
	startedAt := storeT0
	job := ProviderJob{
		JobKey:       storeTestKey,
		RunID:        44798508261,
		RunAttempt:   1,
		JobName:      "custom name b",
		WorkflowName: "verify-check-run-id",
		Labels:       []string{"ubuntu-latest"},
		Status:       status,
		StartedAt:    &startedAt,
		CompletedAt:  completedAt,
	}
	if status != "queued" {
		job.RunnerName = "GitHub Actions 1001602055"
	}
	if status == "completed" {
		job.Conclusion = "success"
		job.StepCount = 3
	}
	return job
}

func decideWith(expect Expectation) func(context.Context, Job) (Verdict, error) {
	return func(_ context.Context, job Job) (Verdict, error) { return Decide(job, expect), nil }
}

func TestStore_UpsertInEitherOrderConvergesToTheSameRow(t *testing.T) {
	completedAt := storeT0.Add(16 * time.Second)
	webhook := func(t *testing.T, store *Store) {
		t.Helper()
		if err := store.UpsertProviderJob(t.Context(), providerJobAt("completed", &completedAt), storeT0); err != nil {
			t.Fatalf("UpsertProviderJob: %v", err)
		}
	}
	record := func(kind RecordKind) func(*testing.T, *Store) {
		return func(t *testing.T, store *Store) {
			t.Helper()
			// The record spells the repository in lower case.
			key := JobKey{ProviderHost: "github.com", Repository: "acme/api", CheckRunID: storeTestKey.CheckRunID}
			if _, err := store.RecordSensorRecord(t.Context(), SensorRecord{
				JobKey: key, Kind: kind, RunID: 44798508261, RunAttempt: 1,
				SummaryResult: "passed", FinalizeReason: "completed",
			}, storeT0.Add(time.Second)); err != nil {
				t.Fatalf("RecordSensorRecord(%s): %v", kind, err)
			}
		}
	}

	cases := []struct {
		name  string
		steps []func(*testing.T, *Store)
	}{
		{name: "webhook first, then start, then summary", steps: []func(*testing.T, *Store){webhook, record(RecordJobStart), record(RecordSummary)}},
		{name: "records first, webhook last (fast job, slow webhook)", steps: []func(*testing.T, *Store){record(RecordJobStart), record(RecordSummary), webhook}},
		{name: "summary before start (Pub/Sub does not order)", steps: []func(*testing.T, *Store){record(RecordSummary), webhook, record(RecordJobStart)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := openTestStore(t)
			for _, step := range tc.steps {
				step(t, store)
			}
			got, ok := readJob(t, store, storeTestKey)
			if !ok {
				t.Fatal("job row missing")
			}
			if got.Status != "completed" || got.Conclusion != "success" || got.RunnerName == "" || got.StepCount != 3 {
				t.Errorf("provider columns: got %+v", got.ProviderJob)
			}
			if got.RunID != 44798508261 || got.RunAttempt != 1 {
				t.Errorf("run identity: got %d/%d", got.RunID, got.RunAttempt)
			}
			if got.StartSeenAt == nil || got.SummarySeenAt == nil {
				t.Errorf("seen columns: start=%v summary=%v", got.StartSeenAt, got.SummarySeenAt)
			}
			if got.SummaryResult != "passed" || got.FinalizeReason != "completed" {
				t.Errorf("summary columns: got %q/%q", got.SummaryResult, got.FinalizeReason)
			}
			var rows int
			if err := store.pool.QueryRow(t.Context(), `SELECT count(*) FROM jobs`).Scan(&rows); err != nil {
				t.Fatalf("count rows: %v", err)
			}
			if rows != 1 {
				t.Errorf("rows: got %d, want 1 (repository case must not split the job)", rows)
			}
		})
	}
}

func TestStore_RedeliveredRecordsKeepTheFirstSeenTime(t *testing.T) {
	store := openTestStore(t)
	first := storeT0.Add(time.Second)
	for i, at := range []time.Time{first, first.Add(time.Minute), first.Add(time.Hour)} {
		after, err := store.RecordSensorRecord(t.Context(), SensorRecord{
			JobKey: storeTestKey, Kind: RecordSummary, SummaryResult: []string{"passed", "detected", "terminated"}[i],
		}, at)
		if err != nil {
			t.Fatalf("RecordSensorRecord #%d: %v", i, err)
		}
		if after {
			t.Fatalf("delivery #%d reported a verdict that does not exist", i)
		}
	}
	got, _ := readJob(t, store, storeTestKey)
	if got.SummarySeenAt == nil || !got.SummarySeenAt.Equal(first) {
		t.Fatalf("summary_seen_at: got %v, want %s", got.SummarySeenAt, first)
	}
	if got.SummaryResult != "passed" {
		t.Fatalf("summary_result: got %q, want the first delivery's value", got.SummaryResult)
	}
	if got.StartSeenAt != nil {
		t.Fatalf("start_seen_at: got %v, want nil (a summary is not a start)", got.StartSeenAt)
	}
}

func TestStore_RecordSensorRecord_RejectsUnknownKind(t *testing.T) {
	store := openTestStore(t)
	if _, err := store.RecordSensorRecord(t.Context(), SensorRecord{JobKey: storeTestKey, Kind: "detection"}, storeT0); err == nil {
		t.Fatal("expected an error for an unsupported record kind")
	}
	if _, ok := readJob(t, store, storeTestKey); ok {
		t.Fatal("an unsupported record must not create a row")
	}
}

func TestStore_UpsertProviderJob_LateEventCannotMoveAJobBackwards(t *testing.T) {
	completedAt := storeT0.Add(16 * time.Second)
	cases := []struct {
		name       string
		statuses   []string
		wantStatus string
	}{
		{name: "in-order delivery ends completed", statuses: []string{"queued", "in_progress", "completed"}, wantStatus: "completed"},
		{name: "queued delivered after completed is ignored", statuses: []string{"completed", "queued"}, wantStatus: "completed"},
		{name: "in_progress delivered after completed is ignored", statuses: []string{"queued", "completed", "in_progress"}, wantStatus: "completed"},
		{name: "queued delivered after in_progress is ignored", statuses: []string{"in_progress", "queued"}, wantStatus: "in_progress"},
		{name: "redelivered completed event is applied again", statuses: []string{"completed", "completed"}, wantStatus: "completed"},
		{name: "waiting ranks with queued", statuses: []string{"in_progress", "waiting"}, wantStatus: "in_progress"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := openTestStore(t)
			for _, status := range tc.statuses {
				var done *time.Time
				if status == "completed" {
					done = &completedAt
				}
				if err := store.UpsertProviderJob(t.Context(), providerJobAt(status, done), storeT0); err != nil {
					t.Fatalf("UpsertProviderJob(%s): %v", status, err)
				}
			}
			got, _ := readJob(t, store, storeTestKey)
			if got.Status != tc.wantStatus {
				t.Fatalf("status: got %q, want %q", got.Status, tc.wantStatus)
			}
			if tc.wantStatus == "completed" && (got.CompletedAt == nil || got.Conclusion != "success") {
				t.Fatalf("completed columns lost: %+v", got.ProviderJob)
			}
		})
	}
}

func TestStore_DecidePending_GraceAndStatusBoundaries(t *testing.T) {
	completedAt := storeT0
	cases := []struct {
		name            string
		job             ProviderJob
		completedBefore time.Time
		wantDecided     int
	}{
		{name: "job past the grace cutoff is decided", job: providerJobAt("completed", &completedAt), completedBefore: completedAt.Add(time.Nanosecond * 1000), wantDecided: 1},
		{name: "job completed exactly at the cutoff waits", job: providerJobAt("completed", &completedAt), completedBefore: completedAt, wantDecided: 0},
		{name: "job still inside the grace period waits", job: providerJobAt("completed", &completedAt), completedBefore: completedAt.Add(-time.Minute), wantDecided: 0},
		{name: "running job is never decided", job: providerJobAt("in_progress", nil), completedBefore: completedAt.Add(time.Hour), wantDecided: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := openTestStore(t)
			if err := store.UpsertProviderJob(t.Context(), tc.job, storeT0); err != nil {
				t.Fatalf("UpsertProviderJob: %v", err)
			}
			verdictAt := storeT0.Add(time.Hour)
			decided, err := store.DecidePending(t.Context(), tc.completedBefore, verdictAt, 10, decideWith(Expectation{}))
			if err != nil {
				t.Fatalf("DecidePending: %v", err)
			}
			if decided != tc.wantDecided {
				t.Fatalf("decided: got %d, want %d", decided, tc.wantDecided)
			}
			got, _ := readJob(t, store, storeTestKey)
			if tc.wantDecided == 0 {
				if got.Verdict != "" {
					t.Fatalf("verdict: got %q, want none", got.Verdict)
				}
				return
			}
			if got.Verdict != string(VerdictNoStart) || got.VerdictAt == nil || !got.VerdictAt.Equal(verdictAt) {
				t.Fatalf("verdict: got %q at %v, want no_start at %s", got.Verdict, got.VerdictAt, verdictAt)
			}
		})
	}
}

func TestStore_DecidePending_VerdictIsFinal(t *testing.T) {
	store := openTestStore(t)
	completedAt := storeT0
	if err := store.UpsertProviderJob(t.Context(), providerJobAt("completed", &completedAt), storeT0); err != nil {
		t.Fatalf("UpsertProviderJob: %v", err)
	}
	cutoff := completedAt.Add(time.Hour)
	if _, err := store.DecidePending(t.Context(), cutoff, cutoff, 10, decideWith(Expectation{})); err != nil {
		t.Fatalf("DecidePending: %v", err)
	}

	// A late Summary and a redelivered webhook must not reopen the job.
	after, err := store.RecordSensorRecord(t.Context(), SensorRecord{JobKey: storeTestKey, Kind: RecordSummary, SummaryResult: "passed"}, cutoff.Add(time.Minute))
	if err != nil {
		t.Fatalf("RecordSensorRecord: %v", err)
	}
	if !after {
		t.Fatal("a record arriving after the verdict must be reported as late")
	}
	if err := store.UpsertProviderJob(t.Context(), providerJobAt("completed", &completedAt), cutoff.Add(time.Minute)); err != nil {
		t.Fatalf("UpsertProviderJob redelivery: %v", err)
	}
	decided, err := store.DecidePending(t.Context(), cutoff.Add(time.Hour), cutoff.Add(time.Hour), 10, func(context.Context, Job) (Verdict, error) {
		t.Error("a decided job must not be offered again")
		return VerdictOK, nil
	})
	if err != nil {
		t.Fatalf("DecidePending again: %v", err)
	}
	if decided != 0 {
		t.Fatalf("decided again: got %d, want 0", decided)
	}
	got, _ := readJob(t, store, storeTestKey)
	if got.Verdict != string(VerdictNoStart) {
		t.Fatalf("verdict: got %q, want it to stay no_start", got.Verdict)
	}
	if got.SummarySeenAt == nil {
		t.Fatal("the late summary should still be recorded for investigation")
	}
}

func TestStore_DecidePending_DecideErrorRollsBackTheBatch(t *testing.T) {
	store := openTestStore(t)
	completedAt := storeT0
	for id := range int64(3) {
		job := providerJobAt("completed", &completedAt)
		job.CheckRunID = id + 1
		if err := store.UpsertProviderJob(t.Context(), job, storeT0); err != nil {
			t.Fatalf("UpsertProviderJob: %v", err)
		}
	}
	publishErr := errors.New("finding output unavailable")
	calls := 0
	cutoff := completedAt.Add(time.Hour)
	_, err := store.DecidePending(t.Context(), cutoff, cutoff, 10, func(context.Context, Job) (Verdict, error) {
		calls++
		if calls == 2 {
			return "", publishErr
		}
		return VerdictNoStart, nil
	})
	if !errors.Is(err, publishErr) {
		t.Fatalf("DecidePending error: got %v, want %v", err, publishErr)
	}
	var withVerdict int
	if err := store.pool.QueryRow(t.Context(), `SELECT count(*) FROM jobs WHERE verdict IS NOT NULL`).Scan(&withVerdict); err != nil {
		t.Fatalf("count verdicts: %v", err)
	}
	if withVerdict != 0 {
		t.Fatalf("jobs with a verdict after a failed batch: got %d, want 0", withVerdict)
	}

	decided, err := store.DecidePending(t.Context(), cutoff, cutoff, 10, decideWith(Expectation{}))
	if err != nil || decided != 3 {
		t.Fatalf("retry: decided %d, err %v; want 3, nil", decided, err)
	}
}

func TestStore_DecidePending_HonoursLimitOldestFirst(t *testing.T) {
	store := openTestStore(t)
	for id := range int64(5) {
		completedAt := storeT0.Add(time.Duration(id) * time.Second)
		job := providerJobAt("completed", &completedAt)
		job.CheckRunID = id + 1
		if err := store.UpsertProviderJob(t.Context(), job, storeT0); err != nil {
			t.Fatalf("UpsertProviderJob: %v", err)
		}
	}
	cutoff := storeT0.Add(time.Hour)
	var order []int64
	decided, err := store.DecidePending(t.Context(), cutoff, cutoff, 2, func(_ context.Context, job Job) (Verdict, error) {
		order = append(order, job.CheckRunID)
		return VerdictOK, nil
	})
	if err != nil {
		t.Fatalf("DecidePending: %v", err)
	}
	if decided != 2 || len(order) != 2 || order[0] != 1 || order[1] != 2 {
		t.Fatalf("decided %d in order %v, want the two oldest jobs [1 2]", decided, order)
	}
}

func TestStore_DecidePending_ConcurrentLoopsDecideEachJobOnce(t *testing.T) {
	store := openTestStore(t)
	const jobs = 200
	completedAt := storeT0
	for id := range int64(jobs) {
		job := providerJobAt("completed", &completedAt)
		job.CheckRunID = id + 1
		if err := store.UpsertProviderJob(t.Context(), job, storeT0); err != nil {
			t.Fatalf("UpsertProviderJob: %v", err)
		}
	}

	var mu sync.Mutex
	seen := make(map[int64]int, jobs)
	cutoff := completedAt.Add(time.Hour)
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Go(func() {
			for {
				decided, err := store.DecidePending(t.Context(), cutoff, cutoff, 7, func(_ context.Context, job Job) (Verdict, error) {
					mu.Lock()
					seen[job.CheckRunID]++
					mu.Unlock()
					return VerdictNoStart, nil
				})
				if err != nil {
					errs <- err
					return
				}
				if decided == 0 {
					// Rows locked by other replicas are skipped, so an
					// empty batch can mean "someone else has the rest".
					var pending int
					if err := store.pool.QueryRow(t.Context(), `SELECT count(*) FROM jobs WHERE verdict IS NULL`).Scan(&pending); err != nil {
						errs <- err
						return
					}
					if pending == 0 {
						return
					}
				}
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent DecidePending: %v", err)
	}
	if len(seen) != jobs {
		t.Fatalf("decided jobs: got %d, want %d", len(seen), jobs)
	}
	for id, count := range seen {
		if count != 1 {
			t.Fatalf("job %d decided %d times, want exactly once", id, count)
		}
	}
}

func TestStore_DeleteOlderThan(t *testing.T) {
	store := openTestStore(t)
	old := providerJobAt("completed", nil)
	old.CheckRunID = 1
	fresh := providerJobAt("completed", nil)
	fresh.CheckRunID = 2
	if err := store.UpsertProviderJob(t.Context(), old, storeT0); err != nil {
		t.Fatalf("UpsertProviderJob old: %v", err)
	}
	if err := store.UpsertProviderJob(t.Context(), fresh, storeT0.Add(48*time.Hour)); err != nil {
		t.Fatalf("UpsertProviderJob fresh: %v", err)
	}

	cases := []struct {
		name        string
		cutoff      time.Time
		wantDeleted int64
	}{
		{name: "row updated exactly at the cutoff is kept", cutoff: storeT0, wantDeleted: 0},
		{name: "row older than the cutoff is deleted", cutoff: storeT0.Add(time.Hour), wantDeleted: 1},
		{name: "second pass finds nothing left to delete", cutoff: storeT0.Add(time.Hour), wantDeleted: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			deleted, err := store.DeleteOlderThan(t.Context(), tc.cutoff)
			if err != nil {
				t.Fatalf("DeleteOlderThan: %v", err)
			}
			if deleted != tc.wantDeleted {
				t.Fatalf("deleted: got %d, want %d", deleted, tc.wantDeleted)
			}
		})
	}
	if _, ok := readJob(t, store, fresh.JobKey); !ok {
		t.Fatal("fresh row must survive retention")
	}
}

func TestStore_CountRecordsWithoutProviderJob(t *testing.T) {
	store := openTestStore(t)
	orphan := JobKey{ProviderHost: "github.com", Repository: "acme/api", CheckRunID: 1}
	recent := JobKey{ProviderHost: "github.com", Repository: "acme/api", CheckRunID: 2}
	joined := JobKey{ProviderHost: "github.com", Repository: "acme/api", CheckRunID: 3}
	for key, at := range map[JobKey]time.Time{orphan: storeT0, recent: storeT0.Add(time.Hour), joined: storeT0} {
		if _, err := store.RecordSensorRecord(t.Context(), SensorRecord{JobKey: key, Kind: RecordJobStart}, at); err != nil {
			t.Fatalf("RecordSensorRecord: %v", err)
		}
	}
	job := providerJobAt("in_progress", nil)
	job.JobKey = joined
	if err := store.UpsertProviderJob(t.Context(), job, storeT0); err != nil {
		t.Fatalf("UpsertProviderJob: %v", err)
	}

	got, err := store.CountRecordsWithoutProviderJob(t.Context(), storeT0.Add(time.Minute))
	if err != nil {
		t.Fatalf("CountRecordsWithoutProviderJob: %v", err)
	}
	if got != 1 {
		t.Fatalf("count: got %d, want 1 (only the old record with no webhook)", got)
	}
}

func TestStore_ContextCancelled(t *testing.T) {
	store := openTestStore(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := store.UpsertProviderJob(ctx, providerJobAt("queued", nil), storeT0); !errors.Is(err, context.Canceled) {
		t.Fatalf("UpsertProviderJob: got %v, want context.Canceled", err)
	}
	if _, err := store.DecidePending(ctx, storeT0, storeT0, 1, decideWith(Expectation{})); !errors.Is(err, context.Canceled) {
		t.Fatalf("DecidePending: got %v, want context.Canceled", err)
	}
}

func TestOpenStore_UnreachableDatabase(t *testing.T) {
	if os.Getenv(storeTestDSNEnv) == "" {
		t.Skipf("%s is not set", storeTestDSNEnv)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if _, err := OpenStore(ctx, "postgres://nobody:wrong@127.0.0.1:1/none?connect_timeout=1"); err == nil {
		t.Fatal("OpenStore must fail when Postgres is unreachable")
	}
	if _, err := OpenStore(ctx, "::not a dsn::"); err == nil {
		t.Fatal("OpenStore must fail on a malformed DSN")
	}
}
