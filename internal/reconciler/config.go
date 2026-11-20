// Package reconciler joins the CI provider's job list against cicd-sensor
// job_start and summary records and reports jobs whose telemetry is missing.
// It runs downstream of the manager's sink and holds the only state.
package reconciler

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"go.yaml.in/yaml/v4"
)

const (
	defaultBindAddress       = "0.0.0.0"
	defaultBindPort          = 8080
	defaultGracePeriod       = 5 * time.Minute
	defaultReconcileInterval = 30 * time.Second
	defaultRetention         = 30 * 24 * time.Hour
)

// Config is the reconciler startup config. Secrets (webhook secret, Postgres
// DSN) are not part of the file; they come from the environment.
type Config struct {
	Bind     BindConfig     `yaml:"bind,omitempty"`
	PubSub   PubSubConfig   `yaml:"pubsub"`
	Findings FindingsConfig `yaml:"findings,omitempty"`
	// GracePeriod is how long after a job completes its records may still
	// arrive before the job gets a verdict.
	GracePeriod       time.Duration `yaml:"grace_period,omitempty"`
	ReconcileInterval time.Duration `yaml:"reconcile_interval,omitempty"`
	// Retention is how long a job row is kept after its last update.
	Retention time.Duration `yaml:"retention,omitempty"`
	Expect    Expectation   `yaml:"expect,omitempty"`
}

type BindConfig struct {
	Address string `yaml:"address,omitempty"`
	Port    *int   `yaml:"port,omitempty"`
}

// PubSubConfig names the subscription that receives job_start and summary
// records from the manager's Pub/Sub sink.
type PubSubConfig struct {
	ProjectID    string `yaml:"project_id"`
	Subscription string `yaml:"subscription"`
}

// FindingsConfig configures the optional Pub/Sub output for findings.
type FindingsConfig struct {
	// PubSubTopic lives in pubsub.project_id. Empty disables the output.
	PubSubTopic string `yaml:"pubsub_topic,omitempty"`
}

// Expectation says which jobs are expected to run the sensor. A job outside
// it never produces a finding.
type Expectation struct {
	Repositories RepositoryFilter `yaml:"repositories,omitempty"`
	// ExcludeRunnerLabels lists runner labels that cannot run the sensor,
	// such as macos-latest. A job requesting any of them is not expected.
	ExcludeRunnerLabels []string `yaml:"exclude_runner_labels,omitempty"`
}

// RepositoryFilter holds path.Match globs over "owner/repo". An empty Include
// matches every repository. Exclude wins over Include.
type RepositoryFilter struct {
	Include []string `yaml:"include,omitempty"`
	Exclude []string `yaml:"exclude,omitempty"`
}

// LoadConfig reads and validates the reconciler config file.
func LoadConfig(configPath string) (Config, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return Config{}, fmt.Errorf("read config %s: %w", configPath, err)
	}
	var cfg Config
	if err := yaml.Load(data, &cfg, yaml.WithKnownFields()); err != nil {
		return Config{}, fmt.Errorf("parse config %s: %w", configPath, err)
	}
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (cfg *Config) applyDefaults() {
	if cfg.Bind.Address == "" {
		cfg.Bind.Address = defaultBindAddress
	}
	if cfg.Bind.Port == nil {
		port := defaultBindPort
		cfg.Bind.Port = &port
	}
	if cfg.GracePeriod == 0 {
		cfg.GracePeriod = defaultGracePeriod
	}
	if cfg.ReconcileInterval == 0 {
		cfg.ReconcileInterval = defaultReconcileInterval
	}
	if cfg.Retention == 0 {
		cfg.Retention = defaultRetention
	}
}

// Validate checks a config after defaults are applied.
func (cfg Config) Validate() error {
	var errs []error
	if cfg.Bind.Port == nil || *cfg.Bind.Port < 0 || *cfg.Bind.Port > 65535 {
		errs = append(errs, errors.New("bind.port must be between 0 and 65535"))
	}
	if strings.TrimSpace(cfg.PubSub.ProjectID) == "" {
		errs = append(errs, errors.New("pubsub.project_id is required"))
	}
	if strings.TrimSpace(cfg.PubSub.Subscription) == "" {
		errs = append(errs, errors.New("pubsub.subscription is required"))
	}
	if cfg.GracePeriod < 0 {
		errs = append(errs, errors.New("grace_period must not be negative"))
	}
	if cfg.ReconcileInterval <= 0 {
		errs = append(errs, errors.New("reconcile_interval must be positive"))
	}
	if cfg.Retention <= cfg.GracePeriod {
		errs = append(errs, errors.New("retention must be longer than grace_period"))
	}
	if err := cfg.Expect.Validate(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// BindAddress returns the net/http listen address.
func (cfg Config) BindAddress() string {
	return net.JoinHostPort(cfg.Bind.Address, strconv.Itoa(*cfg.Bind.Port))
}

// Validate rejects malformed globs up front so a typo cannot silently turn
// an exclusion into "matches nothing".
func (e Expectation) Validate() error {
	var errs []error
	for _, pattern := range slices.Concat(e.Repositories.Include, e.Repositories.Exclude) {
		if _, err := path.Match(pattern, ""); err != nil {
			errs = append(errs, fmt.Errorf("expect.repositories pattern %q: %w", pattern, err))
		}
	}
	for _, label := range e.ExcludeRunnerLabels {
		if strings.TrimSpace(label) == "" {
			errs = append(errs, errors.New("expect.exclude_runner_labels must not contain an empty label"))
		}
	}
	return errors.Join(errs...)
}

// Expects reports whether a job in repository requesting labels is expected
// to run the sensor. Repository and label comparison is case-insensitive,
// like GitHub's own handling of both.
func (e Expectation) Expects(repository string, labels []string) bool {
	repository = strings.ToLower(repository)
	if matchesAnyGlob(e.Repositories.Exclude, repository) {
		return false
	}
	if len(e.Repositories.Include) > 0 && !matchesAnyGlob(e.Repositories.Include, repository) {
		return false
	}
	return !slices.ContainsFunc(labels, func(label string) bool {
		return slices.ContainsFunc(e.ExcludeRunnerLabels, func(excluded string) bool {
			return strings.EqualFold(label, excluded)
		})
	})
}

func matchesAnyGlob(patterns []string, repository string) bool {
	return slices.ContainsFunc(patterns, func(pattern string) bool {
		// Patterns are validated at load; a bad one here matches nothing.
		matched, err := path.Match(strings.ToLower(pattern), repository)
		return err == nil && matched
	})
}
