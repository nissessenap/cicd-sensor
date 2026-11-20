package reconciler

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"github.com/cicd-sensor/cicd-sensor/internal/logtype"
	logv1beta1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/log/v1beta1"
)

// Message attributes set by the manager's Pub/Sub sink. The job identity is
// read from here and never from the record body: the manager binds these
// values to the OIDC token, while the body is forwarded unparsed and is
// whatever the job chose to send.
const (
	attrLogType          = "log_type"
	attrProvider         = "provider"
	attrProviderHost     = "provider_host"
	attrProjectPath      = "project_path"
	attrGitHubRunID      = "github_run_id"
	attrGitHubRunAttempt = "github_run_attempt"
	attrGitHubCheckRunID = "github_check_run_id"
)

// sensorRecordStore is the part of Store the record handler uses.
type sensorRecordStore interface {
	RecordSensorRecord(ctx context.Context, record SensorRecord, now time.Time) (afterVerdict bool, err error)
}

// RecordHandler turns sensor log records from the sink into job state.
type RecordHandler struct {
	store   sensorRecordStore
	metrics *Metrics
	logger  *slog.Logger
	now     func() time.Time
}

// NewRecordHandler builds a RecordHandler over a Store.
func NewRecordHandler(store *Store, metrics *Metrics, logger *slog.Logger) *RecordHandler {
	return newRecordHandler(store, metrics, logger)
}

func newRecordHandler(store sensorRecordStore, metrics *Metrics, logger *slog.Logger) *RecordHandler {
	return &RecordHandler{
		store:   store,
		metrics: metrics,
		logger:  logger.With("component", "record_handler"),
		now:     time.Now,
	}
}

// HandleRecord processes one message from the manager's Pub/Sub sink. It
// returns an error only when the message should be redelivered; records
// that can never be used are counted and dropped.
func (h *RecordHandler) HandleRecord(ctx context.Context, attrs map[string]string, body []byte) error {
	var kind RecordKind
	switch attrs[attrLogType] {
	case string(logtype.JobStart):
		kind = RecordJobStart
	case string(logtype.Summary):
		kind = RecordSummary
	default:
		return nil
	}

	checkRunID := attrs[attrGitHubCheckRunID]
	if attrs[attrProvider] != string(jobcontext.ProviderGitHub) || checkRunID == "" {
		h.metrics.unjoinableRecords.Add(1)
		return nil
	}
	record, err := sensorRecordFromAttributes(kind, attrs)
	if err != nil {
		h.metrics.invalidRecords.Add(1)
		h.logger.WarnContext(ctx, "record_attributes_invalid", "log_type", attrs[attrLogType], "error", err)
		return nil
	}
	if kind == RecordSummary {
		// The body is informational only. A Summary that cannot be decoded
		// still proves the sensor finalized, so it is recorded regardless.
		var entry logv1beta1.SummaryLogEntry
		if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(body, &entry); err != nil {
			h.metrics.invalidRecords.Add(1)
			h.logger.WarnContext(ctx, "summary_body_invalid", "github_check_run_id", record.CheckRunID, "error", err)
		} else {
			record.SummaryResult = entry.GetResult()
			record.FinalizeReason = entry.GetFinalizeReason()
		}
	}

	afterVerdict, err := h.store.RecordSensorRecord(ctx, record, h.now().UTC())
	if err != nil {
		return err
	}
	if afterVerdict {
		h.metrics.lateRecords.Add(1)
		h.logger.WarnContext(ctx, "record_after_verdict",
			"log_type", attrs[attrLogType],
			"repository", record.Repository,
			"github_check_run_id", record.CheckRunID,
		)
	}
	return nil
}

func sensorRecordFromAttributes(kind RecordKind, attrs map[string]string) (SensorRecord, error) {
	if attrs[attrProviderHost] == "" || attrs[attrProjectPath] == "" {
		return SensorRecord{}, fmt.Errorf("%s and %s are required", attrProviderHost, attrProjectPath)
	}
	checkRunID, err := positiveInt(attrs[attrGitHubCheckRunID])
	if err != nil {
		return SensorRecord{}, fmt.Errorf("%s: %w", attrGitHubCheckRunID, err)
	}
	record := SensorRecord{
		JobKey: JobKey{
			ProviderHost: attrs[attrProviderHost],
			Repository:   attrs[attrProjectPath],
			CheckRunID:   checkRunID,
		},
		Kind: kind,
	}
	// Run ID and attempt only enrich a row the webhook has not filled yet.
	if runID, err := positiveInt(attrs[attrGitHubRunID]); err == nil {
		record.RunID = runID
	}
	if attempt, err := positiveInt(attrs[attrGitHubRunAttempt]); err == nil && attempt <= 1<<31-1 {
		record.RunAttempt = int(attempt)
	}
	return record, nil
}

func positiveInt(s string) (int64, error) {
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, err
	}
	if n <= 0 {
		return 0, fmt.Errorf("%d is not a positive integer", n)
	}
	return n, nil
}
