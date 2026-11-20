package joblogs

import (
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/managerclient"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"github.com/cicd-sensor/cicd-sensor/internal/logtype"
	logv1beta1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/log/v1beta1"
	managerv1beta1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/manager/v1beta1"
	"github.com/cicd-sensor/cicd-sensor/internal/version"
)

func TestMarshalJobStartLogEntry(t *testing.T) {
	t.Parallel()

	startedAt := time.Date(2026, 11, 20, 9, 30, 0, 0, time.UTC)
	cases := []struct {
		name           string
		in             JobStartLogInput
		wantCheckRunID string
		wantRevision   string
		absentJobKeys  []string
	}{
		{
			name: "github action job carries the check run id as the join key",
			in: JobStartLogInput{
				ScopeLogContext: ScopeLogContext{
					Identity:       jobcontext.GitHubJobIdentity("github.com", "acme/example", "44798508261", "matrix", "1", "runner-1"),
					Metadata:       jobcontext.JobMetadata{GitHubCheckRunID: "88812345678"},
					RunnerType:     "machine",
					Scope:          jobcontext.ScopeTypeProject,
					ConfigRevision: "config-sha",
				},
				StartedAt: startedAt,
			},
			wantCheckRunID: "88812345678",
			wantRevision:   "config-sha",
			absentJobKeys:  []string{"gitlab_job_id"},
		},
		{
			name: "hook-started github job has no join key and omits the field",
			in: JobStartLogInput{
				ScopeLogContext: ScopeLogContext{
					Identity:   jobcontext.GitHubJobIdentity("github.com", "acme/example", "44798508261", "build", "1", "runner-1"),
					RunnerType: "machine",
					Scope:      jobcontext.ScopeTypeHost,
				},
				StartedAt: startedAt,
			},
			wantRevision:  AbsentSentinel,
			absentJobKeys: []string{"github_check_run_id", "gitlab_job_id"},
		},
		{
			name: "gitlab job never leaks a github check run id",
			in: JobStartLogInput{
				ScopeLogContext: ScopeLogContext{
					Identity:   jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "14274377073"),
					Metadata:   jobcontext.JobMetadata{GitHubCheckRunID: "88812345678"},
					RunnerType: "kubernetes",
					Scope:      jobcontext.ScopeTypeHost,
				},
				StartedAt: startedAt,
			},
			wantRevision:  AbsentSentinel,
			absentJobKeys: []string{"github_check_run_id", "github_run_id"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			payload, err := MarshalJobStartLogEntry(tc.in)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			var entry logv1beta1.JobStartLogEntry
			if err := protojson.Unmarshal(payload, &entry); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if got, want := entry.GetLogType(), "cicd_sensor.job_start"; got != want {
				t.Fatalf("log_type: got %q, want %q", got, want)
			}
			if got, want := entry.GetSchemaVersion(), logtype.JobStartSchemaVersion; got != want {
				t.Fatalf("schema_version: got %q, want %q", got, want)
			}
			if got, want := entry.GetServiceName(), logtype.ServiceName; got != want {
				t.Fatalf("service_name: got %q, want %q", got, want)
			}
			if got, want := entry.GetServiceVersion(), version.Current; got != want {
				t.Fatalf("service_version: got %q, want %q", got, want)
			}
			if entry.GetLogId() == "" {
				t.Fatal("log_id is empty")
			}
			if !entry.GetTimestamp().AsTime().Equal(startedAt) {
				t.Fatalf("timestamp: got %s, want %s", entry.GetTimestamp().AsTime(), startedAt)
			}
			if got, want := entry.GetScope(), string(tc.in.Scope); got != want {
				t.Fatalf("scope: got %q, want %q", got, want)
			}
			if got, want := entry.GetRunnerType(), tc.in.RunnerType; got != want {
				t.Fatalf("runner_type: got %q, want %q", got, want)
			}
			if got := entry.GetConfigRevision(); got != tc.wantRevision {
				t.Fatalf("config_revision: got %q, want %q", got, tc.wantRevision)
			}
			if got := entry.GetJob().GetGithubCheckRunId(); got != tc.wantCheckRunID {
				t.Fatalf("job.github_check_run_id: got %q, want %q", got, tc.wantCheckRunID)
			}

			var raw struct {
				Job map[string]any `json:"job"`
			}
			if err := json.Unmarshal(payload, &raw); err != nil {
				t.Fatalf("unmarshal raw: %v", err)
			}
			for _, key := range tc.absentJobKeys {
				if _, present := raw.Job[key]; present {
					t.Errorf("job.%s should be omitted: %s", key, payload)
				}
			}
		})
	}
}

func TestMarshalJobStartLogEntry_ZeroStartedAtUsesNow(t *testing.T) {
	t.Parallel()

	before := time.Now().Add(-time.Second)
	payload, err := MarshalJobStartLogEntry(JobStartLogInput{ScopeLogContext: testScopeLogContext()})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var entry logv1beta1.JobStartLogEntry
	if err := protojson.Unmarshal(payload, &entry); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got := entry.GetTimestamp().AsTime(); got.Before(before) {
		t.Fatalf("timestamp: got %s, want a current time", got)
	}
}

func TestManagerJobLogsJobStartIsOptIn(t *testing.T) {
	t.Parallel()

	identity := jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "runner-1")
	oldManagerSettings := func(t *testing.T) *managerv1beta1.OutputSettings {
		t.Helper()
		// Field 5 (job_start) did not exist; re-decoding drops nothing but
		// proves a message built without it leaves the start record off.
		wire, err := proto.Marshal(&managerv1beta1.OutputSettings{
			Detection: &managerv1beta1.OutputSetting{Enabled: true},
			Summary:   &managerv1beta1.OutputSetting{Enabled: true},
		})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var settings managerv1beta1.OutputSettings
		if err := proto.Unmarshal(wire, &settings); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		return &settings
	}

	cases := []struct {
		name     string
		settings func(*testing.T) *managerv1beta1.OutputSettings
		want     int
	}{
		{
			name:     "manager that predates job_start never opts the agent in",
			settings: oldManagerSettings,
			want:     0,
		},
		{
			name: "manager that does not route job_start leaves it off",
			settings: func(*testing.T) *managerv1beta1.OutputSettings {
				return &managerv1beta1.OutputSettings{
					Summary:  &managerv1beta1.OutputSetting{Enabled: true},
					JobStart: &managerv1beta1.OutputSetting{},
				}
			},
			want: 0,
		},
		{
			name: "routed job_start is the only enabled type and still gets a worker",
			settings: func(*testing.T) *managerv1beta1.OutputSettings {
				return &managerv1beta1.OutputSettings{JobStart: &managerv1beta1.OutputSetting{Enabled: true}}
			},
			want: 1,
		},
		{
			name: "a batching policy from the manager cannot delay the start record",
			settings: func(*testing.T) *managerv1beta1.OutputSettings {
				return &managerv1beta1.OutputSettings{JobStart: &managerv1beta1.OutputSetting{
					Enabled:              true,
					FlushThresholdBytes:  4 * 1024 * 1024,
					FlushIntervalSeconds: 3600,
				}}
			},
			want: 1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			poster := &recordingLogBatchSender{}
			logs := newManagerJobLogsWithSender(testLogger, poster.sendBatch, identity, jobcontext.ScopeTypeProject, tc.settings(t))
			if got, want := logs.HasJobStartLog(), tc.want == 1; got != want {
				t.Fatalf("HasJobStartLog: got %v, want %v", got, want)
			}
			if err := logs.EmitJobStartLog(t.Context(), []byte(`{"log_type":"cicd_sensor.job_start"}`)); err != nil {
				t.Fatalf("emit job start: %v", err)
			}
			// No flush and no close: the record must leave on its own.
			waitForBatchCount(t, poster, tc.want)
			if tc.want == 1 {
				poster.mu.Lock()
				got := poster.batches[0].Type
				poster.mu.Unlock()
				if got != managerv1beta1.LogType_LOG_TYPE_JOB_START {
					t.Fatalf("batch type: got %s, want job start", got)
				}
			}
			if err := logs.FinalizeStreamingLogs(t.Context()); err != nil {
				t.Fatalf("finalize: %v", err)
			}
			if got := poster.count(); got != tc.want {
				t.Fatalf("batches after finalize: got %d, want %d (start record must not be resent)", got, tc.want)
			}
		})
	}
}

func TestManagerJobLogsEmitJobStartLog_SurvivesFinishedStartRequest(t *testing.T) {
	t.Parallel()

	entered := make(chan struct{})
	release := make(chan struct{})
	ctxErr := make(chan error, 1)
	sendBatch := func(ctx context.Context, _ managerclient.LogBatch) error {
		close(entered)
		<-release
		ctxErr <- ctx.Err()
		return nil
	}
	logs := newManagerJobLogsWithSender(testLogger, sendBatch,
		jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "runner-1"),
		jobcontext.ScopeTypeProject,
		&managerv1beta1.OutputSettings{JobStart: &managerv1beta1.OutputSetting{Enabled: true}},
	)

	requestCtx, finishRequest := context.WithCancel(t.Context())
	if err := logs.EmitJobStartLog(requestCtx, []byte(`{"n":1}`)); err != nil {
		t.Fatalf("emit job start: %v", err)
	}
	<-entered
	// The start hook has returned while the send is still in flight.
	finishRequest()
	close(release)
	if err := <-ctxErr; err != nil {
		t.Fatalf("send context: got %v, want it to outlive the start request", err)
	}
	if err := logs.FinalizeStreamingLogs(t.Context()); err != nil {
		t.Fatalf("finalize: %v", err)
	}
}

func TestManagerJobLogsEmitJobStartLog_FailedSendIsRetriedAtFinalize(t *testing.T) {
	t.Parallel()

	sendErr := errors.New("manager unavailable")
	poster := &recordingLogBatchSender{}
	poster.setErr(sendErr)
	attempted := make(chan struct{}, 4)
	sendBatch := func(ctx context.Context, batch managerclient.LogBatch) error {
		err := poster.sendBatch(ctx, batch)
		attempted <- struct{}{}
		return err
	}
	logs := newManagerJobLogsWithSender(testLogger, sendBatch,
		jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "runner-1"),
		jobcontext.ScopeTypeHost,
		&managerv1beta1.OutputSettings{JobStart: &managerv1beta1.OutputSetting{Enabled: true}},
	)

	if err := logs.EmitJobStartLog(t.Context(), []byte(`{"n":1}`)); err != nil {
		t.Fatalf("emit must not surface delivery failure to job start: %v", err)
	}
	<-attempted
	if got := poster.count(); got != 0 {
		t.Fatalf("delivered batches while manager is down: got %d, want 0", got)
	}

	poster.setErr(nil)
	if err := logs.FinalizeStreamingLogs(t.Context()); err != nil {
		t.Fatalf("finalize: %v", err)
	}
	if got := poster.count(); got != 1 {
		t.Fatalf("delivered batches after finalize retry: got %d, want 1", got)
	}
}

func TestManagerJobLogsEmitJobStartLog_FailedSendIsRetriedWhileTheJobRuns(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		// recover delivers the buffered record without closing the worker.
		recover func(t *testing.T, logs *ManagerJobLogs)
	}{
		{
			name:    "worker timer resends without any further call",
			recover: func(*testing.T, *ManagerJobLogs) { time.Sleep(jobStartRetrySeconds * time.Second) },
		},
		{
			name: "streaming flush resends before the timer fires",
			recover: func(t *testing.T, logs *ManagerJobLogs) {
				if err := logs.FlushStreamingLogs(t.Context()); err != nil {
					t.Fatalf("flush streaming logs: %v", err)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				poster := &recordingLogBatchSender{}
				poster.setErr(errors.New("manager unavailable"))
				var attempts atomic.Int32
				sendBatch := func(ctx context.Context, batch managerclient.LogBatch) error {
					attempts.Add(1)
					return poster.sendBatch(ctx, batch)
				}
				logs := newManagerJobLogsWithSender(testLogger, sendBatch,
					jobcontext.GitHubJobIdentity("github.com", "acme/example", "123", "build", "1", "runner-1"),
					jobcontext.ScopeTypeProject,
					&managerv1beta1.OutputSettings{JobStart: &managerv1beta1.OutputSetting{Enabled: true}},
				)

				if err := logs.EmitJobStartLog(t.Context(), []byte(`{"n":1}`)); err != nil {
					t.Fatalf("emit job start: %v", err)
				}
				synctest.Wait()
				if attempts.Load() != 1 || poster.count() != 0 {
					t.Fatalf("after the failed send: attempts %d, delivered %d; want 1, 0", attempts.Load(), poster.count())
				}

				poster.setErr(nil)
				tc.recover(t, &logs)
				synctest.Wait()
				if got := poster.count(); got != 1 {
					t.Fatalf("delivered batches before finalize: got %d, want 1 (a killed Agent never finalizes)", got)
				}

				if err := logs.FinalizeStreamingLogs(t.Context()); err != nil {
					t.Fatalf("finalize: %v", err)
				}
				if got := poster.count(); got != 1 {
					t.Fatalf("delivered batches after finalize: got %d, want 1 (start record must not be resent)", got)
				}
			})
		})
	}
}

func TestManagerJobLogsEmitJobStartLog_NilAndUnconfiguredAreNoOps(t *testing.T) {
	t.Parallel()

	var nilLogs *ManagerJobLogs
	if err := nilLogs.EmitJobStartLog(t.Context(), []byte(`{}`)); err != nil {
		t.Fatalf("nil receiver: %v", err)
	}
	if nilLogs.HasJobStartLog() {
		t.Fatal("nil receiver reports a job start log")
	}
	logs := NewForTesting(testLogger, func(context.Context, managerclient.LogBatch) error {
		t.Error("unconfigured job start must not send")
		return nil
	})
	if err := logs.EmitJobStartLog(t.Context(), []byte(`{}`)); err != nil {
		t.Fatalf("unconfigured: %v", err)
	}
	if got := logs.DroppedLogRecords(managerv1beta1.LogType_LOG_TYPE_JOB_START); got != 0 {
		t.Fatalf("dropped: got %d, want 0", got)
	}
}
