package reconciler

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadConfig(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		body    string
		wantErr string
		assert  func(*testing.T, Config)
	}{
		{
			name: "minimal config gets documented defaults",
			body: `
pubsub:
  project_id: security-prod
  subscription: cicd-sensor-reconciler
`,
			assert: func(t *testing.T, cfg Config) {
				t.Helper()
				if got, want := cfg.BindAddress(), "0.0.0.0:8080"; got != want {
					t.Errorf("bind address: got %q, want %q", got, want)
				}
				if cfg.GracePeriod != 5*time.Minute {
					t.Errorf("grace_period: got %s, want 5m", cfg.GracePeriod)
				}
				if cfg.ReconcileInterval != 30*time.Second {
					t.Errorf("reconcile_interval: got %s, want 30s", cfg.ReconcileInterval)
				}
				if cfg.Retention != 30*24*time.Hour {
					t.Errorf("retention: got %s, want 720h", cfg.Retention)
				}
				if cfg.Findings.PubSubTopic != "" {
					t.Errorf("findings topic: got %q, want disabled", cfg.Findings.PubSubTopic)
				}
				if !cfg.Expect.Expects("any/repo", []string{"ubuntu-latest"}) {
					t.Error("empty expectation must expect every job")
				}
			},
		},
		{
			name: "full config is read as written",
			body: `
bind:
  address: 127.0.0.1
  port: 9090
pubsub:
  project_id: security-prod
  subscription: cicd-sensor-reconciler
findings:
  pubsub_topic: cicd-sensor-findings
grace_period: 90s
reconcile_interval: 5s
retention: 48h
expect:
  repositories:
    include: ["acme/*"]
    exclude: ["acme/sandbox-*"]
  exclude_runner_labels: [macos-latest]
`,
			assert: func(t *testing.T, cfg Config) {
				t.Helper()
				if got, want := cfg.BindAddress(), "127.0.0.1:9090"; got != want {
					t.Errorf("bind address: got %q, want %q", got, want)
				}
				if cfg.GracePeriod != 90*time.Second || cfg.ReconcileInterval != 5*time.Second || cfg.Retention != 48*time.Hour {
					t.Errorf("durations: got %s/%s/%s", cfg.GracePeriod, cfg.ReconcileInterval, cfg.Retention)
				}
				if cfg.Findings.PubSubTopic != "cicd-sensor-findings" {
					t.Errorf("findings topic: got %q", cfg.Findings.PubSubTopic)
				}
				if cfg.Expect.Expects("acme/sandbox-1", nil) || !cfg.Expect.Expects("acme/api", nil) {
					t.Error("repository filter not applied")
				}
			},
		},
		{
			name:    "a typo in a key fails instead of silently disabling an exclusion",
			body:    "pubsub:\n  project_id: p\n  subscription: s\nexpect:\n  exclude_runner_label: [macos-latest]\n",
			wantErr: "exclude_runner_label",
		},
		{
			name:    "subscription is required because it is the only record input",
			body:    "pubsub:\n  project_id: p\n",
			wantErr: "pubsub.subscription is required",
		},
		{
			name:    "project is required",
			body:    "pubsub:\n  subscription: s\n",
			wantErr: "pubsub.project_id is required",
		},
		{
			name:    "malformed glob is rejected at startup",
			body:    "pubsub:\n  project_id: p\n  subscription: s\nexpect:\n  repositories:\n    exclude: [\"acme/[\"]\n",
			wantErr: `pattern "acme/["`,
		},
		{
			name:    "empty runner label would never match and is rejected",
			body:    "pubsub:\n  project_id: p\n  subscription: s\nexpect:\n  exclude_runner_labels: [\"\"]\n",
			wantErr: "empty label",
		},
		{
			name:    "retention shorter than grace would delete jobs before their verdict",
			body:    "pubsub:\n  project_id: p\n  subscription: s\ngrace_period: 2h\nretention: 1h\n",
			wantErr: "retention must be longer than grace_period",
		},
		{
			name:    "negative grace period is rejected",
			body:    "pubsub:\n  project_id: p\n  subscription: s\ngrace_period: -1s\n",
			wantErr: "grace_period must not be negative",
		},
		{
			name:    "negative interval cannot drive a ticker",
			body:    "pubsub:\n  project_id: p\n  subscription: s\nreconcile_interval: -5s\n",
			wantErr: "reconcile_interval must be positive",
		},
		{
			name:    "port out of range is rejected",
			body:    "bind:\n  port: 70000\npubsub:\n  project_id: p\n  subscription: s\n",
			wantErr: "bind.port must be between 0 and 65535",
		},
		{
			name:    "invalid YAML is rejected",
			body:    "pubsub: [",
			wantErr: "parse config",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			configPath := filepath.Join(t.TempDir(), "reconciler.yaml")
			if err := os.WriteFile(configPath, []byte(tc.body), 0o600); err != nil {
				t.Fatalf("write config: %v", err)
			}
			cfg, err := LoadConfig(configPath)
			if tc.wantErr != "" {
				// Error text is the operator-facing contract here; there is
				// no sentinel to match with errors.Is.
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("LoadConfig error: got %v, want it to mention %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("LoadConfig: %v", err)
			}
			tc.assert(t, cfg)
		})
	}
}

func TestLoadConfig_MissingFile(t *testing.T) {
	t.Parallel()

	_, err := LoadConfig(filepath.Join(t.TempDir(), "absent.yaml"))
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("LoadConfig error: got %v, want fs.ErrNotExist", err)
	}
}

func TestExpectationExpects(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		expect     Expectation
		repository string
		labels     []string
		want       bool
	}{
		{name: "no config expects everything", repository: "acme/api", labels: []string{"ubuntu-latest"}, want: true},
		{name: "no config expects a job with no labels", repository: "acme/api", want: true},
		{
			name:       "include glob matches within the owner only",
			expect:     Expectation{Repositories: RepositoryFilter{Include: []string{"acme/*"}}},
			repository: "acme/api", want: true,
		},
		{
			name:       "include glob does not cross the owner separator",
			expect:     Expectation{Repositories: RepositoryFilter{Include: []string{"acme*"}}},
			repository: "acme/api", want: false,
		},
		{
			name:       "repository not included is not expected",
			expect:     Expectation{Repositories: RepositoryFilter{Include: []string{"acme/*"}}},
			repository: "other/api", want: false,
		},
		{
			name:       "exclude wins over include",
			expect:     Expectation{Repositories: RepositoryFilter{Include: []string{"acme/*"}, Exclude: []string{"acme/api"}}},
			repository: "acme/api", want: false,
		},
		{
			name:       "exclude alone leaves other repositories expected",
			expect:     Expectation{Repositories: RepositoryFilter{Exclude: []string{"acme/legacy-*"}}},
			repository: "acme/api", want: true,
		},
		{
			name:       "repository match ignores case on both sides",
			expect:     Expectation{Repositories: RepositoryFilter{Include: []string{"Acme/API"}}},
			repository: "acme/Api", want: true,
		},
		{
			name:       "one excluded label among several excludes the job",
			expect:     Expectation{ExcludeRunnerLabels: []string{"windows-latest"}},
			repository: "acme/api", labels: []string{"self-hosted", "Windows-Latest"}, want: false,
		},
		{
			name:       "labels that are not excluded keep the job expected",
			expect:     Expectation{ExcludeRunnerLabels: []string{"windows-latest"}},
			repository: "acme/api", labels: []string{"ubuntu-latest"}, want: true,
		},
		{
			name:       "label exclusion is exact, not a prefix match",
			expect:     Expectation{ExcludeRunnerLabels: []string{"macos"}},
			repository: "acme/api", labels: []string{"macos-latest"}, want: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.expect.Expects(tc.repository, tc.labels); got != tc.want {
				t.Fatalf("Expects(%q, %v): got %v, want %v", tc.repository, tc.labels, got, tc.want)
			}
		})
	}
}
