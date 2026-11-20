package manager

import (
	"testing"

	"connectrpc.com/connect"

	"github.com/cicd-sensor/cicd-sensor/internal/logtype"
	"github.com/cicd-sensor/cicd-sensor/internal/manager/sink"
	"github.com/cicd-sensor/cicd-sensor/internal/manager/sink/sinktest"
	managerv1beta1 "github.com/cicd-sensor/cicd-sensor/internal/proto/cicd_sensor/manager/v1beta1"
)

func TestOutputRouter_OutputSettings_JobStartIsOptIn(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		routes      map[logtype.LogType]sink.Sink
		wantPresent bool
	}{
		{
			name:   "existing config without a job_start route serves no job_start setting",
			routes: map[logtype.LogType]sink.Sink{logtype.Summary: sinktest.New("summary")},
		},
		{
			name: "routing job_start opts agents in",
			routes: map[logtype.LogType]sink.Sink{
				logtype.Summary:  sinktest.New("summary"),
				logtype.JobStart: sinktest.New("job_start"),
			},
			wantPresent: true,
		},
		{
			name:        "job_start can be the only routed type",
			routes:      map[logtype.LogType]sink.Sink{logtype.JobStart: sinktest.New("job_start")},
			wantPresent: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := newOutputRouterForTest(tc.routes).OutputSettings()
			if present := got.JobStart != nil; present != tc.wantPresent {
				t.Fatalf("job_start setting present: got %v, want %v", present, tc.wantPresent)
			}
			if got.GetJobStart().GetEnabled() != tc.wantPresent {
				t.Fatalf("job_start enabled: got %v, want %v", got.GetJobStart().GetEnabled(), tc.wantPresent)
			}
		})
	}
}

func TestCollectorWire_JobStart(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		route    logtype.LogType
		wantCode connect.Code
	}{
		{name: "routed job_start batch reaches its sink unchanged", route: logtype.JobStart},
		{name: "agent sending job_start to a manager that does not route it is refused", route: logtype.Summary, wantCode: connect.CodeFailedPrecondition},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dst := sinktest.New("dst")
			client, cleanup := newCollectorWireClient(t, testManagerSecret, newOutputRouterForTest(map[logtype.LogType]sink.Sink{
				tc.route: dst,
			}))
			defer cleanup()

			payload := gzipPayload(t, `{"log_type":"cicd_sensor.job_start"}`+"\n")
			batch := validIngestLogBatch(validCollectorIdentity(), payload)
			batch.LogType = managerv1beta1.LogType_LOG_TYPE_JOB_START
			batch.Scope = managerv1beta1.Scope_SCOPE_PROJECT
			_, err := client.send(t.Context(), testManagerSecret, batch)
			if tc.wantCode != 0 {
				if got := connect.CodeOf(err); got != tc.wantCode {
					t.Fatalf("code: got %v, want %v (err=%v)", got, tc.wantCode, err)
				}
				if len(dst.Batches()) != 0 {
					t.Fatal("unrouted batch must not reach another log type's sink")
				}
				return
			}
			if err != nil {
				t.Fatalf("send batch: %v", err)
			}
			batches := dst.Batches()
			if len(batches) != 1 {
				t.Fatalf("batches: got %d, want 1", len(batches))
			}
			if batches[0].LogType != logtype.JobStart || batches[0].Scope != sink.ScopeProject {
				t.Fatalf("batch routing: got %s/%s, want job_start/project", batches[0].LogType, batches[0].Scope)
			}
			if string(batches[0].Body) != string(payload) {
				t.Fatal("body changed in transit")
			}
		})
	}
}

func TestCollectorWire_CheckRunID(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		checkRunID string
		wantCode   connect.Code
	}{
		{name: "check run id travels to the sink next to the identity", checkRunID: "136504227286"},
		{name: "batch from a hook-started job has none", checkRunID: ""},
		{name: "non-numeric check run id never becomes a sink attribute", checkRunID: "1; drop", wantCode: connect.CodeInvalidArgument},
		{name: "zero is not a GitHub id", checkRunID: "0", wantCode: connect.CodeInvalidArgument},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dst := sinktest.New("dst")
			client, cleanup := newCollectorWireClient(t, testManagerSecret, newOutputRouterForTest(map[logtype.LogType]sink.Sink{
				logtype.Summary: dst,
			}))
			defer cleanup()

			identity := validCollectorIdentity()
			identity.GithubCheckRunId = tc.checkRunID
			batch := validIngestLogBatch(identity, gzipPayload(t, `{"log_type":"cicd_sensor.summary"}`+"\n"))
			batch.LogType = managerv1beta1.LogType_LOG_TYPE_SUMMARY
			_, err := client.send(t.Context(), testManagerSecret, batch)
			if tc.wantCode != 0 {
				if got := connect.CodeOf(err); got != tc.wantCode {
					t.Fatalf("code: got %v, want %v (err=%v)", got, tc.wantCode, err)
				}
				if len(dst.Batches()) != 0 {
					t.Fatal("rejected batch must not reach the sink")
				}
				return
			}
			if err != nil {
				t.Fatalf("send batch: %v", err)
			}
			batches := dst.Batches()
			if len(batches) != 1 {
				t.Fatalf("batches: got %d, want 1", len(batches))
			}
			if got := batches[0].GitHubCheckRunID; got != tc.checkRunID {
				t.Fatalf("sink batch check run id: got %q, want %q", got, tc.checkRunID)
			}
		})
	}
}
