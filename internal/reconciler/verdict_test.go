package reconciler

import (
	"testing"
	"time"
)

func TestDecide(t *testing.T) {
	t.Parallel()

	seen := time.Date(2026, 11, 20, 19, 3, 20, 0, time.UTC)
	// ranJob mirrors a hosted job that a runner picked up.
	ranJob := func(mutate func(*Job)) Job {
		job := Job{ProviderJob: ProviderJob{
			JobKey:     JobKey{ProviderHost: "github.com", Repository: "acme/api", CheckRunID: 136504227286},
			Labels:     []string{"ubuntu-latest"},
			RunnerName: "GitHub Actions 1001602055",
			StepCount:  3,
			Status:     "completed",
			Conclusion: "success",
		}}
		if mutate != nil {
			mutate(&job)
		}
		return job
	}
	onboarded := Expectation{
		Repositories:        RepositoryFilter{Include: []string{"acme/*"}, Exclude: []string{"acme/sandbox-*"}},
		ExcludeRunnerLabels: []string{"macos-latest", "windows-latest"},
	}

	cases := []struct {
		name   string
		job    Job
		expect Expectation
		want   Verdict
	}{
		{
			name: "start and summary: the sensor covered the whole job",
			job:  ranJob(func(j *Job) { j.StartSeenAt, j.SummarySeenAt = &seen, &seen }),
			want: VerdictOK,
		},
		{
			name: "summary without start is ok because the start record is opt-in",
			job:  ranJob(func(j *Job) { j.SummarySeenAt = &seen }),
			want: VerdictOK,
		},
		{
			name: "start without summary: the sensor died mid-job",
			job:  ranJob(func(j *Job) { j.StartSeenAt = &seen }),
			want: VerdictNoSummary,
		},
		{
			name: "nothing seen: the sensor never ran",
			job:  ranJob(nil),
			want: VerdictNoStart,
		},
		{
			name: "failed job with no telemetry is still a finding",
			job:  ranJob(func(j *Job) { j.Conclusion = "failure" }),
			want: VerdictNoStart,
		},
		{
			name: "job cancelled after a runner picked it up is judged like any other",
			job:  ranJob(func(j *Job) { j.Conclusion, j.StartSeenAt = "cancelled", &seen }),
			want: VerdictNoSummary,
		},
		{
			name: "skipped job never reached a runner (runner_name null, no steps)",
			job:  ranJob(func(j *Job) { j.Conclusion, j.RunnerName, j.StepCount = "skipped", "", 0 }),
			want: VerdictNotExpected,
		},
		{
			name: "skipped wins even if GitHub reports a runner name",
			job:  ranJob(func(j *Job) { j.Conclusion = "skipped" }),
			want: VerdictNotExpected,
		},
		{
			name: "cancelled while queued never reached a runner (runner_name empty, no steps)",
			job:  ranJob(func(j *Job) { j.Conclusion, j.RunnerName, j.StepCount = "cancelled", "", 0 }),
			want: VerdictNotExpected,
		},
		{
			name: "steps without a runner name still mean the job ran",
			job:  ranJob(func(j *Job) { j.RunnerName = "" }),
			want: VerdictNoStart,
		},
		{
			name: "a runner name without steps still means the job ran",
			job:  ranJob(func(j *Job) { j.StepCount = 0 }),
			want: VerdictNoStart,
		},
		{
			name:   "repository outside the include list is not expected",
			job:    ranJob(func(j *Job) { j.Repository = "other/api" }),
			expect: onboarded,
			want:   VerdictNotExpected,
		},
		{
			name:   "excluded repository is not expected even when included by a broader glob",
			job:    ranJob(func(j *Job) { j.Repository = "acme/sandbox-1" }),
			expect: onboarded,
			want:   VerdictNotExpected,
		},
		{
			name:   "runner label that cannot run the sensor is not expected",
			job:    ranJob(func(j *Job) { j.Labels = []string{"self-hosted", "macOS-latest"} }),
			expect: onboarded,
			want:   VerdictNotExpected,
		},
		{
			name:   "excluded job stays not_expected even if records arrived",
			job:    ranJob(func(j *Job) { j.Labels, j.SummarySeenAt = []string{"macos-latest"}, &seen }),
			expect: onboarded,
			want:   VerdictNotExpected,
		},
		{
			name:   "onboarded repository on a supported runner with no telemetry is a finding",
			job:    ranJob(nil),
			expect: onboarded,
			want:   VerdictNoStart,
		},
		{
			name: "zero job: no runner evidence at all is not expected, never a finding",
			job:  Job{},
			want: VerdictNotExpected,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := Decide(tc.job, tc.expect); got != tc.want {
				t.Fatalf("Decide: got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestVerdictIsFinding(t *testing.T) {
	t.Parallel()

	for verdict, want := range map[Verdict]bool{
		VerdictOK:          false,
		VerdictNotExpected: false,
		VerdictNoStart:     true,
		VerdictNoSummary:   true,
		Verdict(""):        false,
	} {
		if got := verdict.IsFinding(); got != want {
			t.Errorf("Verdict(%q).IsFinding(): got %v, want %v", verdict, got, want)
		}
	}
}
