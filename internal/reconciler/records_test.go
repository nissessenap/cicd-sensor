package reconciler

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/logtype"
)

type recordingSensorRecordStore struct {
	mu           sync.Mutex
	records      []SensorRecord
	afterVerdict bool
	err          error
}

func (s *recordingSensorRecordStore) RecordSensorRecord(_ context.Context, record SensorRecord, _ time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return false, s.err
	}
	s.records = append(s.records, record)
	return s.afterVerdict, nil
}

func recordAttrs(logType string, mutate func(map[string]string)) map[string]string {
	attrs := map[string]string{
		"content_type":        "application/json",
		"log_type":            logType,
		"scope":               "project",
		"provider":            "github",
		"provider_host":       "github.com",
		"project_path":        "acme/example",
		"github_run_id":       "44798508261",
		"github_run_attempt":  "1",
		"github_check_run_id": "136504227286",
	}
	if mutate != nil {
		mutate(attrs)
	}
	return attrs
}

func TestRecordHandler_HandleRecord(t *testing.T) {
	t.Parallel()

	wantKey := JobKey{ProviderHost: "github.com", Repository: "acme/example", CheckRunID: 136504227286}
	storeErr := errors.New("postgres down")

	cases := []struct {
		name           string
		attrs          map[string]string
		store          *recordingSensorRecordStore
		wantErr        error
		want           *SensorRecord
		wantUnjoinable uint64
		wantInvalid    uint64
		wantLate       uint64
	}{
		{
			name:  "job_start is recorded from the message attributes",
			attrs: recordAttrs("job_start", nil),
			want:  &SensorRecord{JobKey: wantKey, Kind: logtype.JobStart, RunID: 44798508261, RunAttempt: 1},
		},
		{
			name:  "summary is recorded from the message attributes",
			attrs: recordAttrs("summary", nil),
			want:  &SensorRecord{JobKey: wantKey, Kind: logtype.Summary, RunID: 44798508261, RunAttempt: 1},
		},
		{
			name:  "detection records are not the reconciler's business",
			attrs: recordAttrs("detection", nil),
		},
		{
			name:  "runtime events are ignored without being counted",
			attrs: recordAttrs("runtime_event", nil),
		},
		{
			name:  "message without a log_type attribute is ignored",
			attrs: recordAttrs("", func(a map[string]string) { delete(a, "log_type") }),
		},
		{
			name:  "nil attributes are ignored",
			attrs: nil,
		},
		{
			name:           "hook-started job has no check run id and cannot be joined",
			attrs:          recordAttrs("job_start", func(a map[string]string) { delete(a, "github_check_run_id") }),
			wantUnjoinable: 1,
		},
		{
			name: "gitlab records cannot be joined to a GitHub job list",
			attrs: recordAttrs("summary", func(a map[string]string) {
				a["provider"] = "gitlab"
				delete(a, "github_check_run_id")
			}),
			wantUnjoinable: 1,
		},
		{
			name:           "record from a manager that predates identity attributes is unjoinable",
			attrs:          map[string]string{"log_type": "summary", "scope": "project"},
			wantUnjoinable: 1,
		},
		{
			name:        "non-numeric check run id is dropped as invalid",
			attrs:       recordAttrs("job_start", func(a map[string]string) { a["github_check_run_id"] = "abc" }),
			wantInvalid: 1,
		},
		{
			name:        "zero check run id is dropped as invalid",
			attrs:       recordAttrs("job_start", func(a map[string]string) { a["github_check_run_id"] = "0" }),
			wantInvalid: 1,
		},
		{
			name:        "check run id beyond bigint is dropped as invalid",
			attrs:       recordAttrs("job_start", func(a map[string]string) { a["github_check_run_id"] = "99999999999999999999" }),
			wantInvalid: 1,
		},
		{
			name:        "record without a repository cannot be keyed",
			attrs:       recordAttrs("job_start", func(a map[string]string) { delete(a, "project_path") }),
			wantInvalid: 1,
		},
		{
			name: "missing or malformed run id and attempt do not block the join",
			attrs: recordAttrs("job_start", func(a map[string]string) {
				a["github_run_id"] = "not-a-number"
				a["github_run_attempt"] = "99999999999"
			}),
			want: &SensorRecord{JobKey: wantKey, Kind: logtype.JobStart},
		},
		{
			name:     "record arriving after the verdict is stored and counted as late",
			attrs:    recordAttrs("summary", nil),
			store:    &recordingSensorRecordStore{afterVerdict: true},
			want:     &SensorRecord{JobKey: wantKey, Kind: logtype.Summary, RunID: 44798508261, RunAttempt: 1},
			wantLate: 1,
		},
		{
			name:    "store failure is returned so the message is redelivered",
			attrs:   recordAttrs("job_start", nil),
			store:   &recordingSensorRecordStore{err: storeErr},
			wantErr: storeErr,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			store := tc.store
			if store == nil {
				store = &recordingSensorRecordStore{}
			}
			metrics := &Metrics{}
			handler := NewRecordHandler(store, metrics, testLogger)

			err := handler.HandleRecord(t.Context(), tc.attrs)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("HandleRecord error: got %v, want %v", err, tc.wantErr)
			}
			switch {
			case tc.want == nil && len(store.records) != 0:
				t.Fatalf("stored records: got %+v, want none", store.records)
			case tc.want != nil && len(store.records) != 1:
				t.Fatalf("stored records: got %d, want 1", len(store.records))
			case tc.want != nil && store.records[0] != *tc.want:
				t.Fatalf("stored record:\ngot  %+v\nwant %+v", store.records[0], *tc.want)
			}
			if got := metrics.unjoinableRecords.Load(); got != tc.wantUnjoinable {
				t.Errorf("unjoinable counter: got %d, want %d", got, tc.wantUnjoinable)
			}
			if got := metrics.invalidRecords.Load(); got != tc.wantInvalid {
				t.Errorf("invalid counter: got %d, want %d", got, tc.wantInvalid)
			}
			if got := metrics.lateRecords.Load(); got != tc.wantLate {
				t.Errorf("late counter: got %d, want %d", got, tc.wantLate)
			}
		})
	}
}

func TestFindingAttributes(t *testing.T) {
	t.Parallel()

	got := findingAttributes(Finding{Verdict: VerdictNoSummary, ProviderHost: "github.com", Repository: "acme/example"})
	want := map[string]string{
		"content_type":  "application/json",
		"log_type":      "missing_telemetry",
		"verdict":       "no_summary",
		"provider":      "github",
		"provider_host": "github.com",
		"project_path":  "acme/example",
	}
	for key, value := range want {
		if got[key] != value {
			t.Errorf("attribute %s: got %q, want %q", key, got[key], value)
		}
	}
	if len(got) != len(want) {
		t.Errorf("attributes: got %v, want exactly %v", got, want)
	}
}

func TestSecretsValidate(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		secrets Secrets
		wantErr bool
	}{
		{name: "both secrets present", secrets: Secrets{PostgresDSN: "postgres://x", GitHubWebhookSecret: "s"}},
		{name: "missing webhook secret would accept forged deliveries", secrets: Secrets{PostgresDSN: "postgres://x"}, wantErr: true},
		{name: "missing DSN", secrets: Secrets{GitHubWebhookSecret: "s"}, wantErr: true},
		{name: "zero value", secrets: Secrets{}, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if err := tc.secrets.Validate(); (err != nil) != tc.wantErr {
				t.Fatalf("Validate: got %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}
