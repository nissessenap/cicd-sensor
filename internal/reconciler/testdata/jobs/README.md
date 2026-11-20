# GitHub job objects

Responses from `GET /repos/{owner}/{repo}/actions/runs/{run_id}/attempts/{n}/jobs`
on github.com, captured 2026-11-20. The `workflow_job` webhook payload carries
the same job object (see `../webhooks/`), so tests also wrap these in a
webhook envelope.

The repository slug, `node_id`, and `head_sha` are replaced. Everything else,
including IDs, timestamps, `runner_name`, and `steps`, is as GitHub returned it.

| File | Content |
| --- | --- |
| `main-jobs.json` | One run: four jobs that ran on a hosted runner and one skipped job (`if: false`). |
| `queued-before-cancel.json` | A job waiting for a runner that does not exist. |
| `queued-after-cancel.json` | The same job after its run was cancelled while it was still queued. |
