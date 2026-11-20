package jobregistry

import (
	"context"

	"github.com/cicd-sensor/cicd-sensor/internal/agent/job"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/joblogs"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/jobscope"
	"github.com/cicd-sensor/cicd-sensor/internal/agent/managerclient"
	"github.com/cicd-sensor/cicd-sensor/internal/jobcontext"
	"github.com/cicd-sensor/cicd-sensor/internal/rulesource"
)

// GitHubProjectStartConfig carries the inputs for a GitHub project/start request.
type GitHubProjectStartConfig struct {
	Identity                jobcontext.JobIdentity
	Metadata                jobcontext.JobMetadata
	RunnerType              string
	PeerPID                 int32
	DefaultMaxAlertsPerRule int
	DisableBaselineRules    bool
	MonitorMode             bool
	RuleSources             []rulesource.LoadedRules
	ManagerConnection       managerclient.Connection
	ManagerClient           ManagerConfigFetcher
	DebugEnabled            bool
}

// ApplyGitHubProjectStart registers the GitHub project scope. Hosted jobs can
// start here; self-hosted jobs attach to an existing GitHub host scope.
func (jr *JobRegistry) ApplyGitHubProjectStart(ctx context.Context, cfg GitHubProjectStartConfig) (*job.Job, error) {
	// Project/start peer authorization lives here because existing-host and
	// hosted project-only flows use different Job/BPF state.
	reservation := jr.reserveJobStart(cfg.Identity)
	if reservation.existing != nil {
		return jr.attachGitHubProjectScopeToExistingJob(ctx, reservation.existing, cfg)
	}
	if reservation.inFlight() {
		return nil, ErrJobAlreadyRegistered
	}
	defer reservation.done()

	return jr.startGitHubProjectOnlyJob(ctx, cfg)
}

func (jr *JobRegistry) attachGitHubProjectScopeToExistingJob(
	ctx context.Context,
	existing *job.Job,
	cfg GitHubProjectStartConfig,
) (*job.Job, error) {
	if existing.ProjectScope() != nil {
		return nil, job.ErrProjectScopeAlreadySet
	}
	if err := jr.verifyPeerPIDBelongsToJob(ctx, cfg.PeerPID, cfg.Identity); err != nil {
		return nil, err
	}

	// Self-hosted GitHub builds project scope, then attaches it to the host-created Job.
	var projectScope *jobscope.JobScopeState
	var err error
	if cfg.ManagerClient != nil {
		projectScope, err = jr.buildProjectScopeFromManagerConfig(ctx, cfg.Identity, cfg.Metadata, cfg.RunnerType, cfg.ManagerConnection, cfg.ManagerClient)
	} else {
		projectScope, err = jr.buildProjectScopeFromLocalConfig(ctx, cfg.Identity, cfg)
	}
	if err != nil {
		return nil, err
	}
	jr.attachDebugOutput(ctx, projectScope, cfg.DebugEnabled)
	// SetProjectScope swaps in the host+project evaluation bundle atomically.
	if err := existing.SetProjectScope(ctx, projectScope); err != nil {
		return nil, err
	}
	// The Job is already running, so a failure here cannot undo the attach:
	// the start fails loudly, and the scope's block rules keep recording
	// hits without being enforced.
	if err := jr.installNetworkBlockProgram(ctx, existing); err != nil {
		return nil, err
	}
	return existing, nil
}

func (jr *JobRegistry) startGitHubProjectOnlyJob(
	ctx context.Context,
	cfg GitHubProjectStartConfig,
) (*job.Job, error) {
	var projectScope *jobscope.JobScopeState
	var err error
	if cfg.ManagerClient != nil {
		projectScope, err = jr.buildProjectScopeFromManagerConfig(ctx, cfg.Identity, cfg.Metadata, cfg.RunnerType, cfg.ManagerConnection, cfg.ManagerClient)
	} else {
		projectScope, err = jr.buildProjectScopeFromLocalConfig(ctx, cfg.Identity, cfg)
	}
	if err != nil {
		return nil, err
	}
	jr.attachDebugOutput(ctx, projectScope, cfg.DebugEnabled)

	// Hosted Actions without host/start create the Job runtime here.
	job, err := jr.registerJobRuntime(ctx, cfg.Identity, cfg.Metadata, cfg.RunnerType)
	if err != nil {
		return nil, err
	}

	// SetProjectScope installs evaluation before the hosted cgroup starts routing.
	if err := job.SetProjectScope(ctx, projectScope); err != nil {
		return nil, err
	}
	// Install before the first cgroup is bound so no tracked process ever
	// runs without the Job's block rules.
	if err := jr.installNetworkBlockProgram(ctx, job); err != nil {
		jr.removeJobAfterStartFailure(ctx, cfg.Identity, "github_project_start")
		return nil, err
	}
	if jr.kernelTracker != nil {
		// project_start peer is the root cgroup for hosted project-only jobs.
		if err := jr.bindStartProcessCgroupToJob(ctx, cfg.Identity, cfg.PeerPID, "github_project_start"); err != nil {
			return nil, err
		}
	}
	return job, nil
}

func (jr *JobRegistry) attachDebugOutput(ctx context.Context, scope *jobscope.JobScopeState, debugEnabled bool) {
	if scope == nil || !debugEnabled {
		return
	}
	output, err := joblogs.NewGitHubActionsDebugOutput(jr.logger)
	if err != nil {
		jr.logger.WarnContext(ctx, "debug_output_unavailable",
			"debug_output_root", joblogs.GitHubActionsDebugOutputDir,
			"error", err,
		)
		return
	}
	scope.SetDebugOutput(output)
}

// buildProjectScopeFromManagerConfig builds a resolved project scope from manager config.
func (jr *JobRegistry) buildProjectScopeFromManagerConfig(ctx context.Context, identity jobcontext.JobIdentity, metadata jobcontext.JobMetadata, runnerType string, projectManagerConnection managerclient.Connection, projectManagerClient ManagerConfigFetcher) (*jobscope.JobScopeState, error) {
	projectScope := jobscope.NewProject()
	managerConfig, err := jr.fetchManagerConfig(ctx, identity, metadata, runnerType, projectManagerClient, "project_manager_config_fetched")
	if err != nil {
		return nil, err
	}
	if err := projectScope.ApplyManagerConfig(managerConfig); err != nil {
		return nil, err
	}
	projectScope.ResolveRules(identity)
	if err := jr.validateNetworkBlockRules(projectScope); err != nil {
		return nil, err
	}
	jr.startManagerJobLogs(projectScope, identity, projectManagerConnection)
	return projectScope, nil
}

// buildProjectScopeFromLocalConfig builds a resolved project scope from project-local config.
func (jr *JobRegistry) buildProjectScopeFromLocalConfig(ctx context.Context, identity jobcontext.JobIdentity, cfg GitHubProjectStartConfig) (*jobscope.JobScopeState, error) {
	projectScope := jobscope.NewProject()
	if !cfg.DisableBaselineRules {
		baselineSource, err := jr.loadBaselineRules(ctx, identity)
		if err != nil {
			return nil, err
		}
		if err := projectScope.ApplyBaselineRules(baselineSource); err != nil {
			return nil, err
		}
	}
	if err := projectScope.ApplyProjectLocalConfig(jobscope.ProjectLocalConfig{
		RuleSources:             cfg.RuleSources,
		DefaultMaxAlertsPerRule: cfg.DefaultMaxAlertsPerRule,
		MonitorMode:             cfg.MonitorMode,
	}); err != nil {
		return nil, err
	}
	projectScope.ResolveRules(identity)
	if err := jr.validateNetworkBlockRules(projectScope); err != nil {
		return nil, err
	}
	return projectScope, nil
}
