package reconciler

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/cicd-sensor/cicd-sensor/internal/logtype"
)

//go:embed schema.sql
var schemaSQL string

// Store is the reconciler's Postgres state: one row per job. Every write is
// an idempotent upsert, so redelivered webhooks and Pub/Sub messages are
// harmless and several replicas can share one database.
type Store struct {
	pool *pgxpool.Pool
}

// OpenStore connects to Postgres and creates the schema when missing.
func OpenStore(ctx context.Context, dsn string) (*Store, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("open postgres pool: %w", err)
	}
	store := &Store{pool: pool}
	if err := store.migrate(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) migrate(ctx context.Context) error {
	if _, err := s.pool.Exec(ctx, schemaSQL); err != nil {
		return fmt.Errorf("create schema: %w", err)
	}
	return nil
}

// Close releases the connection pool.
func (s *Store) Close() {
	s.pool.Close()
}

// Ping reports whether Postgres is reachable.
func (s *Store) Ping(ctx context.Context) error {
	return s.pool.Ping(ctx)
}

// statusRank orders workflow_job statuses so an event delivered late cannot
// move a job backwards (GitHub does not guarantee delivery order).
const statusRank = `CASE %s WHEN 'completed' THEN 2 WHEN 'in_progress' THEN 1 ELSE 0 END`

var upsertProviderJobSQL = `
INSERT INTO jobs (
  provider_host, repository, check_run_id, run_id, run_attempt, job_name,
  workflow_name, labels, runner_name, step_count, status, conclusion,
  started_at, completed_at, updated_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
ON CONFLICT (provider_host, repository, check_run_id) DO UPDATE SET
  run_id = EXCLUDED.run_id,
  run_attempt = EXCLUDED.run_attempt,
  job_name = EXCLUDED.job_name,
  workflow_name = EXCLUDED.workflow_name,
  labels = EXCLUDED.labels,
  runner_name = EXCLUDED.runner_name,
  step_count = EXCLUDED.step_count,
  status = EXCLUDED.status,
  conclusion = EXCLUDED.conclusion,
  started_at = EXCLUDED.started_at,
  completed_at = EXCLUDED.completed_at,
  updated_at = EXCLUDED.updated_at
WHERE ` + fmt.Sprintf(statusRank, "EXCLUDED.status") + ` >= ` + fmt.Sprintf(statusRank, "jobs.status")

// UpsertProviderJob stores the provider's view of a job. Sensor columns and
// an existing verdict are left untouched.
func (s *Store) UpsertProviderJob(ctx context.Context, job ProviderJob, now time.Time) error {
	key := job.JobKey.normalized()
	labels := job.Labels
	if labels == nil {
		labels = []string{}
	}
	_, err := s.pool.Exec(ctx, upsertProviderJobSQL,
		key.ProviderHost, key.Repository, key.CheckRunID, job.RunID, job.RunAttempt, job.JobName,
		job.WorkflowName, labels, job.RunnerName, job.StepCount, job.Status, job.Conclusion,
		job.StartedAt, job.CompletedAt, now,
	)
	if err != nil {
		return fmt.Errorf("upsert provider job: %w", err)
	}
	return nil
}

const upsertSensorRecordSQL = `
INSERT INTO jobs (
  provider_host, repository, check_run_id, run_id, run_attempt,
  start_seen_at, summary_seen_at, updated_at
) VALUES ($1, $2, $3, NULLIF($4::bigint, 0), NULLIF($5::int, 0), $6, $7, $8)
ON CONFLICT (provider_host, repository, check_run_id) DO UPDATE SET
  run_id = COALESCE(jobs.run_id, EXCLUDED.run_id),
  run_attempt = COALESCE(jobs.run_attempt, EXCLUDED.run_attempt),
  start_seen_at = COALESCE(jobs.start_seen_at, EXCLUDED.start_seen_at),
  summary_seen_at = COALESCE(jobs.summary_seen_at, EXCLUDED.summary_seen_at),
  updated_at = EXCLUDED.updated_at
RETURNING verdict IS NOT NULL`

// RecordSensorRecord marks a job_start or summary record as seen at now. The
// first record of each kind wins. It reports whether the job already had a
// verdict, which means the record arrived after the grace period.
func (s *Store) RecordSensorRecord(ctx context.Context, record SensorRecord, now time.Time) (afterVerdict bool, err error) {
	key := record.JobKey.normalized()
	var startSeenAt, summarySeenAt *time.Time
	switch record.Kind {
	case logtype.JobStart:
		startSeenAt = &now
	case logtype.Summary:
		summarySeenAt = &now
	default:
		return false, fmt.Errorf("unsupported record kind %q", record.Kind)
	}
	err = s.pool.QueryRow(ctx, upsertSensorRecordSQL,
		key.ProviderHost, key.Repository, key.CheckRunID, record.RunID, record.RunAttempt,
		startSeenAt, summarySeenAt, now,
	).Scan(&afterVerdict)
	if err != nil {
		return false, fmt.Errorf("upsert sensor record: %w", err)
	}
	return afterVerdict, nil
}

const selectPendingSQL = `
SELECT provider_host, repository, check_run_id, COALESCE(run_id, 0), COALESCE(run_attempt, 0),
  COALESCE(job_name, ''), COALESCE(workflow_name, ''), COALESCE(labels, '{}'), COALESCE(runner_name, ''),
  COALESCE(step_count, 0), COALESCE(status, ''), COALESCE(conclusion, ''), started_at, completed_at,
  start_seen_at, summary_seen_at
FROM jobs
WHERE verdict IS NULL AND status = 'completed' AND completed_at < $1
ORDER BY completed_at
LIMIT 1
FOR UPDATE SKIP LOCKED`

// DecidePending gives a verdict to up to limit completed jobs that finished
// before completedBefore and have none yet, oldest first, and returns how
// many it decided. Each job has its own transaction, and decide runs while
// that transaction holds the row lock: if decide fails, only that job stays
// undecided and is retried later, so side effects in decide happen at least
// once. Rows locked by another replica are skipped.
func (s *Store) DecidePending(ctx context.Context, completedBefore, now time.Time, limit int, decide func(context.Context, Job) (Verdict, error)) (int, error) {
	for decided := range limit {
		found, err := s.decideOne(ctx, completedBefore, now, decide)
		if err != nil {
			return decided, err
		}
		if !found {
			return decided, nil
		}
	}
	return limit, nil
}

func (s *Store) decideOne(ctx context.Context, completedBefore, now time.Time, decide func(context.Context, Job) (Verdict, error)) (bool, error) {
	found := false
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, selectPendingSQL, completedBefore)
		if err != nil {
			return fmt.Errorf("select pending job: %w", err)
		}
		job, err := pgx.CollectExactlyOneRow(rows, scanJob)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("scan pending job: %w", err)
		}
		verdict, err := decide(ctx, job)
		if err != nil {
			return fmt.Errorf("decide job %d: %w", job.CheckRunID, err)
		}
		if _, err := tx.Exec(ctx,
			`UPDATE jobs SET verdict = $1, verdict_at = $2 WHERE provider_host = $3 AND repository = $4 AND check_run_id = $5`,
			string(verdict), now, job.ProviderHost, job.Repository, job.CheckRunID,
		); err != nil {
			return fmt.Errorf("store verdict for job %d: %w", job.CheckRunID, err)
		}
		found = true
		return nil
	})
	return found, err
}

func scanJob(row pgx.CollectableRow) (Job, error) {
	var job Job
	err := row.Scan(
		&job.ProviderHost, &job.Repository, &job.CheckRunID, &job.RunID, &job.RunAttempt,
		&job.JobName, &job.WorkflowName, &job.Labels, &job.RunnerName,
		&job.StepCount, &job.Status, &job.Conclusion, &job.StartedAt, &job.CompletedAt,
		&job.StartSeenAt, &job.SummarySeenAt,
	)
	return job, err
}

// DeleteOlderThan removes rows not updated since cutoff and returns how many.
func (s *Store) DeleteOlderThan(ctx context.Context, cutoff time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM jobs WHERE updated_at < $1`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("delete expired jobs: %w", err)
	}
	return tag.RowsAffected(), nil
}

// CountRecordsWithoutProviderJob counts jobs the sensor reported before
// cutoff that the provider never told the reconciler about. A non-zero value
// hints that webhook deliveries are being lost.
func (s *Store) CountRecordsWithoutProviderJob(ctx context.Context, cutoff time.Time) (int64, error) {
	var count int64
	err := s.pool.QueryRow(ctx,
		`SELECT count(*) FROM jobs WHERE status IS NULL AND COALESCE(start_seen_at, summary_seen_at) < $1`,
		cutoff,
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count records without provider job: %w", err)
	}
	return count, nil
}
