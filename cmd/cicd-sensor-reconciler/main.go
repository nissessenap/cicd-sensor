// Command cicd-sensor-reconciler flags completed CI jobs whose cicd-sensor
// telemetry is missing. It is optional and runs downstream of the manager.
package main

import (
	"cmp"
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/cicd-sensor/cicd-sensor/internal/reconciler"
	"github.com/cicd-sensor/cicd-sensor/internal/slogid"
	"github.com/cicd-sensor/cicd-sensor/internal/version"
)

const (
	configFileEnv    = "CICD_SENSOR_RECONCILER_CONFIG_FILE"
	postgresDSNEnv   = "CICD_SENSOR_RECONCILER_POSTGRES_DSN"
	webhookSecretEnv = "CICD_SENSOR_RECONCILER_GITHUB_WEBHOOK_SECRET"
)

func main() {
	var configFile string
	var showVersion bool
	flag.Usage = func() {
		out := flag.CommandLine.Output()
		fmt.Fprintln(out, "usage: cicd-sensor-reconciler [flags]")
		fmt.Fprintln(out)
		fmt.Fprintln(out, "Required:")
		fmt.Fprintln(out, "  --config-file PATH or "+configFileEnv)
		fmt.Fprintln(out, "        Reconciler config YAML.")
		fmt.Fprintln(out, "  "+postgresDSNEnv)
		fmt.Fprintln(out, "        Postgres connection string.")
		fmt.Fprintln(out, "  "+webhookSecretEnv)
		fmt.Fprintln(out, "        Secret configured on the GitHub workflow_job webhook.")
		fmt.Fprintln(out)
		fmt.Fprintln(out, "Optional:")
		fmt.Fprintln(out, "  --version, -v")
		fmt.Fprintln(out, "        Print version and exit.")
	}
	flag.StringVar(&configFile, "config-file", "", "Path to the reconciler config file.")
	flag.BoolVar(&showVersion, "version", false, "Print version and exit.")
	flag.BoolVar(&showVersion, "v", false, "Print version and exit.")
	flag.Parse()
	if showVersion {
		fmt.Fprintln(os.Stdout, version.Current)
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	logger := slog.New(slogid.Wrap(slog.NewJSONHandler(os.Stderr, nil))).With("component", "cicd-sensor-reconciler")
	slog.SetDefault(logger)

	if err := run(ctx, logger, cmp.Or(configFile, os.Getenv(configFileEnv))); err != nil {
		logger.ErrorContext(ctx, "reconciler_failed", "error", err)
		os.Exit(1)
	}
	logger.InfoContext(ctx, "reconciler_stopped")
}

func run(ctx context.Context, logger *slog.Logger, configFile string) error {
	if configFile == "" {
		return errors.New("--config-file or " + configFileEnv + " is required")
	}
	cfg, err := reconciler.LoadConfig(configFile)
	if err != nil {
		return err
	}
	logger.InfoContext(ctx, "reconciler_started",
		"version", version.Current,
		"addr", cfg.BindAddress(),
		"config_file", configFile,
		"grace_period", cfg.GracePeriod.String(),
	)
	return reconciler.Run(ctx, logger, cfg, reconciler.Secrets{
		PostgresDSN:         os.Getenv(postgresDSNEnv),
		GitHubWebhookSecret: os.Getenv(webhookSecretEnv),
	})
}
