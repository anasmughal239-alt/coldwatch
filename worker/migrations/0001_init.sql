-- coldwatch M2 schema (Cloudflare D1 / SQLite).
-- Timestamps are ISO-8601 UTC strings, computed by the app; the DEFAULTs are
-- only a fallback.

CREATE TABLE domain (
  id                     INTEGER PRIMARY KEY AUTOINCREMENT,
  domain                 TEXT    NOT NULL UNIQUE,
  label                  TEXT,
  dkim_selectors         TEXT    NOT NULL DEFAULT '[]',   -- JSON array
  check_interval_seconds INTEGER NOT NULL DEFAULT 21600,  -- 6h
  enabled                INTEGER NOT NULL DEFAULT 1,
  next_check_at          TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
  created_at             TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);
CREATE INDEX idx_domain_due ON domain (enabled, next_check_at);

-- One row per (domain, time-slot). The UNIQUE constraint is the idempotency
-- key: an at-least-once cron double-fire cannot create a second run for the
-- same slot.
CREATE TABLE check_run (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  domain_id   INTEGER NOT NULL REFERENCES domain(id) ON DELETE CASCADE,
  slot_ts     TEXT    NOT NULL,
  started_at  TEXT    NOT NULL,
  finished_at TEXT,
  status      TEXT,      -- worst across checks: ok|info|warn|unknown|crit
  score       INTEGER,
  grade       TEXT,
  readiness   TEXT,
  error       TEXT,
  UNIQUE (domain_id, slot_ts)
);
CREATE INDEX idx_check_run_domain ON check_run (domain_id, started_at DESC);

-- Append-only history.
CREATE TABLE check_result (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id      INTEGER NOT NULL REFERENCES check_run(id) ON DELETE CASCADE,
  domain_id   INTEGER NOT NULL,
  check_type  TEXT    NOT NULL,   -- spf|dkim|dmarc|mx
  status      TEXT    NOT NULL,
  findings    TEXT    NOT NULL,   -- JSON array
  data        TEXT,               -- JSON object
  observed_at TEXT    NOT NULL
);
CREATE INDEX idx_check_result_domain
  ON check_result (domain_id, check_type, observed_at DESC);

-- Current status per (domain, check_type). Read by the dashboard/API; written
-- transactionally with the check_result that changed it. `since` and
-- `consecutive_count` feed the alert hysteresis in M4.
CREATE TABLE domain_check_state (
  domain_id         INTEGER NOT NULL REFERENCES domain(id) ON DELETE CASCADE,
  check_type        TEXT    NOT NULL,
  status            TEXT    NOT NULL,
  score             INTEGER,
  since             TEXT    NOT NULL,
  last_ok_at        TEXT,
  consecutive_count INTEGER NOT NULL DEFAULT 1,
  last_run_id       INTEGER,
  updated_at        TEXT    NOT NULL,
  PRIMARY KEY (domain_id, check_type)
);
