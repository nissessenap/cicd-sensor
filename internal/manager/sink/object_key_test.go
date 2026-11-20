package sink

import (
	"encoding/hex"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"github.com/cicd-sensor/cicd-sensor/internal/logtype"
)

func TestObjectKey(t *testing.T) {
	batch := objectKeyTestBatch()

	got, err := objectKey(batch)
	if err != nil {
		t.Fatalf("objectKey: %v", err)
	}
	pattern := `^detection/dt=2026-04-26/hour=07/20260426073045123_github-github-com-acme-example-123-build-1-a28bbc96-b9a8d436bdb471f3_host_[0-9a-f]{8}\.json\.gz$`
	if !regexp.MustCompile(pattern).MatchString(got) {
		t.Fatalf("key: got %q, want pattern %s", got, pattern)
	}
}

func TestObjectKey_RandomSuffixIsLastSegment(t *testing.T) {
	first := objectKeyTestBatch()

	firstKey, err := objectKey(first)
	if err != nil {
		t.Fatalf("first objectKey: %v", err)
	}
	secondKey, err := objectKey(first)
	if err != nil {
		t.Fatalf("second objectKey: %v", err)
	}
	if firstKey == secondKey {
		t.Fatalf("same batch produced duplicate object key: %q", firstKey)
	}
	prefix := "detection/dt=2026-04-26/hour=07/20260426073045123_github-github-com-acme-example-123-build-1-a28bbc96-b9a8d436bdb471f3_host_"
	for _, key := range []string{firstKey, secondKey} {
		if !strings.HasPrefix(key, prefix) || !strings.HasSuffix(key, ".json.gz") {
			t.Fatalf("random suffix is not the final key segment: %q", key)
		}
	}
}

func TestObjectKeySuffix(t *testing.T) {
	got, err := objectKeySuffix()
	if err != nil {
		t.Fatalf("objectKeySuffix: %v", err)
	}
	if len(got) != 8 {
		t.Fatalf("suffix length: got %d, want 8 (%q)", len(got), got)
	}
	if _, err := hex.DecodeString(got); err != nil {
		t.Fatalf("suffix is not hex: %q", got)
	}
}

func TestPubSubAttributes(t *testing.T) {
	got := pubsubAttributes(objectKeyTestBatch())

	if _, ok := got["object_key"]; ok {
		t.Fatalf("object_key attribute should not be emitted: %+v", got)
	}
	want := map[string]string{
		"content_type": "application/json",
		"flush_at":     "20260426073045123",
		"log_type":     string(logtype.Detection),
		"scope":        string(ScopeHost),
		// Identity attributes let a consumer join records without trusting
		// the record body.
		"provider":           "github",
		"provider_host":      "github.com",
		"project_path":       "acme/example",
		"github_run_id":      "123",
		"github_run_attempt": "1",
	}
	for key, value := range want {
		if got[key] != value {
			t.Fatalf("attribute %s: got %q, want %q", key, got[key], value)
		}
	}
	for _, absent := range []string{"github_check_run_id", "gitlab_job_id"} {
		if _, ok := got[absent]; ok {
			t.Fatalf("%s attribute should be omitted when the batch has none: %+v", absent, got)
		}
	}
	if _, ok := got["content_encoding"]; ok {
		t.Fatalf("content_encoding attribute should not be emitted: %+v", got)
	}
}

func TestFormatFlushAt(t *testing.T) {
	tests := []struct {
		name  string
		value time.Time
		want  string
	}{
		{
			name:  "formats millisecond precision",
			value: time.Date(2026, 4, 26, 7, 30, 45, 123_000_000, time.UTC),
			want:  "20260426073045123",
		},
		{
			name:  "truncates sub-millisecond precision",
			value: time.Date(2026, 4, 26, 7, 30, 45, 999_999_999, time.UTC),
			want:  "20260426073045999",
		},
		{
			name:  "zero pads missing milliseconds",
			value: time.Date(2026, 4, 26, 7, 30, 45, 0, time.UTC),
			want:  "20260426073045000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatFlushAt(tt.value); got != tt.want {
				t.Fatalf("formatFlushAt: got %q, want %q", got, tt.want)
			}
		})
	}
}

func objectKeyTestBatch() IngestLogBatch {
	return IngestLogBatch{
		LogType: logtype.Detection,
		Identity: jobcontext.GitHubJobIdentity(
			"github.com",
			"acme/example",
			"123",
			"build",
			"1",
			"runner-1",
		),
		Scope:      ScopeHost,
		FlushAt:    time.Date(2026, 4, 26, 7, 30, 45, 123_000_000, time.UTC),
		ReceivedAt: time.Date(2026, 4, 26, 7, 0, 0, 0, time.UTC),
		Body:       []byte{0x1f, 0x8b},
	}
}

func TestPubSubAttributes_JobIdentityByProvider(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		batch      IngestLogBatch
		want       map[string]string
		wantAbsent []string
	}{
		{
			name: "action-started GitHub job carries its check run id",
			batch: IngestLogBatch{
				LogType:          logtype.JobStart,
				Identity:         jobcontext.GitHubJobIdentity("github.com", "acme/example", "44798508261", "matrix", "2", "runner-1"),
				GitHubCheckRunID: "136504227286",
				Scope:            ScopeProject,
			},
			want: map[string]string{
				"log_type":            "job_start",
				"scope":               "project",
				"provider":            "github",
				"project_path":        "acme/example",
				"github_run_id":       "44798508261",
				"github_run_attempt":  "2",
				"github_check_run_id": "136504227286",
			},
			wantAbsent: []string{"gitlab_job_id", "github_job", "github_runner_tracking_id"},
		},
		{
			name: "GitLab job carries its job id and no GitHub fields",
			batch: IngestLogBatch{
				LogType:  logtype.Summary,
				Identity: jobcontext.GitLabJobIdentity("gitlab.com", "group/project", "14274377073"),
				Scope:    ScopeHost,
			},
			want: map[string]string{
				"provider":      "gitlab",
				"provider_host": "gitlab.com",
				"project_path":  "group/project",
				"gitlab_job_id": "14274377073",
			},
			wantAbsent: []string{"github_run_id", "github_run_attempt", "github_check_run_id"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := pubsubAttributes(tc.batch)
			for key, value := range tc.want {
				if got[key] != value {
					t.Errorf("attribute %s: got %q, want %q", key, got[key], value)
				}
			}
			for _, key := range tc.wantAbsent {
				if _, ok := got[key]; ok {
					t.Errorf("attribute %s should be absent: %+v", key, got)
				}
			}
		})
	}
}
