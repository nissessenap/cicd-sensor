CREATE TABLE IF NOT EXISTS jobs (
  provider_host    text        NOT NULL,
  repository       text        NOT NULL,
  check_run_id     bigint      NOT NULL,
  run_id           bigint,
  run_attempt      int,
  job_name         text,
  workflow_name    text,
  labels           text[],
  runner_name      text,
  step_count       int,
  status           text,
  conclusion       text,
  started_at       timestamptz,
  completed_at     timestamptz,
  start_seen_at    timestamptz,
  summary_seen_at  timestamptz,
  summary_result   text,
  finalize_reason  text,
  verdict          text,
  verdict_at       timestamptz,
  updated_at       timestamptz NOT NULL,
  PRIMARY KEY (provider_host, repository, check_run_id)
);

CREATE INDEX IF NOT EXISTS jobs_pending_verdict
  ON jobs (completed_at)
  WHERE verdict IS NULL AND status = 'completed';

CREATE INDEX IF NOT EXISTS jobs_updated_at ON jobs (updated_at);
