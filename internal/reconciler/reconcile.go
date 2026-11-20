package reconciler

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

const (
	// decideBatchSize bounds how many jobs one store call decides.
	decideBatchSize = 100
	// publishTimeout bounds one finding publish, which runs while a row lock
	// and a pool connection are held.
	publishTimeout = 10 * time.Second
)

// verdictStore is the part of Store the verdict loop uses.
type verdictStore interface {
	DecidePending(ctx context.Context, completedBefore, now time.Time, limit int, decide func(context.Context, Job) (Verdict, error)) (int, error)
	DeleteOlderThan(ctx context.Context, cutoff time.Time) (int64, error)
	CountRecordsWithoutProviderJob(ctx context.Context, cutoff time.Time) (int64, error)
}

// FindingPublisher delivers a finding to an extra destination, such as a
// Pub/Sub topic. Publish must return only after the finding is durable.
type FindingPublisher interface {
	Publish(ctx context.Context, finding Finding) error
}

// Reconciler is the verdict loop: it decides completed jobs once their
// grace period has passed, reports findings, and expires old rows.
type Reconciler struct {
	store       verdictStore
	expect      Expectation
	gracePeriod time.Duration
	retention   time.Duration
	publisher   FindingPublisher
	metrics     *Metrics
	logger      *slog.Logger
	now         func() time.Time
}

// ReconcilerConfig carries the inputs for NewReconciler.
type ReconcilerConfig struct {
	Expect      Expectation
	GracePeriod time.Duration
	Retention   time.Duration
	// Publisher is optional. Findings are always logged and counted.
	Publisher FindingPublisher
	Metrics   *Metrics
	Logger    *slog.Logger
}

// NewReconciler builds the verdict loop over store.
func NewReconciler(store verdictStore, cfg ReconcilerConfig) *Reconciler {
	return &Reconciler{
		store:       store,
		expect:      cfg.Expect,
		gracePeriod: cfg.GracePeriod,
		retention:   cfg.Retention,
		publisher:   cfg.Publisher,
		metrics:     cfg.Metrics,
		logger:      cfg.Logger.With("component", "reconciler"),
		now:         time.Now,
	}
}

// Run reconciles every interval until ctx is done. A failed pass is logged
// and retried on the next tick.
//
// The first pass waits one grace period: verdicts are final, and after a
// restart the records of jobs that completed while the reconciler was down
// are still queued in the subscription.
func (r *Reconciler) Run(ctx context.Context, interval time.Duration) error {
	select {
	case <-ctx.Done():
		return nil
	case <-time.After(r.gracePeriod):
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if err := r.ReconcileOnce(ctx); err != nil && ctx.Err() == nil {
			r.metrics.reconcileErrors.Add(1)
			r.logger.ErrorContext(ctx, "reconcile_failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// ReconcileOnce runs one pass: verdicts, retention, and the lost-webhook
// gauge.
func (r *Reconciler) ReconcileOnce(ctx context.Context) error {
	now := r.now().UTC()
	graceCutoff := now.Add(-r.gracePeriod)
	for {
		decided, err := r.store.DecidePending(ctx, graceCutoff, now, decideBatchSize, func(ctx context.Context, job Job) (Verdict, error) {
			return r.decide(ctx, job, now)
		})
		if err != nil {
			return fmt.Errorf("decide pending jobs: %w", err)
		}
		if decided < decideBatchSize {
			break
		}
	}

	deleted, err := r.store.DeleteOlderThan(ctx, now.Add(-r.retention))
	if err != nil {
		return err
	}
	if deleted > 0 {
		r.logger.InfoContext(ctx, "jobs_expired", "count", deleted)
	}

	orphans, err := r.store.CountRecordsWithoutProviderJob(ctx, graceCutoff)
	if err != nil {
		return err
	}
	r.metrics.recordsWithoutProviderJob.Store(orphans)
	return nil
}

func (r *Reconciler) decide(ctx context.Context, job Job, now time.Time) (Verdict, error) {
	verdict := Decide(job, r.expect)
	if !verdict.IsFinding() {
		return verdict, nil
	}
	finding := newFinding(job, verdict, now)
	// Publish first: a failure leaves the verdict unset, so the job is
	// retried instead of being reported in the log only.
	if r.publisher != nil {
		publishCtx, cancel := context.WithTimeout(ctx, publishTimeout)
		err := r.publisher.Publish(publishCtx, finding)
		cancel()
		if err != nil {
			return "", fmt.Errorf("publish finding: %w", err)
		}
	}
	r.metrics.countFinding(verdict)
	r.logger.WarnContext(ctx, "missing_telemetry",
		"verdict", string(verdict),
		"provider_host", finding.ProviderHost,
		"repository", finding.Repository,
		"github_check_run_id", finding.CheckRunID,
		"github_run_id", finding.RunID,
		"github_run_attempt", finding.RunAttempt,
		"job_name", finding.JobName,
		"workflow_name", finding.WorkflowName,
		"runner_name", finding.RunnerName,
		"conclusion", finding.Conclusion,
		"job_link", finding.JobLink,
		"log_id", finding.LogID,
	)
	return verdict, nil
}
