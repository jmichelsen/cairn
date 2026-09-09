-- backup-monitor Phase 1 schema (SQLite). Collector writes; API reads.
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS targets (
  id            INTEGER PRIMARY KEY,
  name          TEXT UNIQUE NOT NULL,
  type          TEXT NOT NULL,          -- zfs-repl | zfs-local | borg-repo | backupninja-handler
  source        TEXT,
  dest          TEXT,
  tier          TEXT,                   -- A = irreplaceable
  transport     TEXT,                   -- local | tailscale-pull | n/a
  location      TEXT,                   -- onsite | onsite-secondary | offsite
  cadence       TEXT,
  encrypted     INTEGER DEFAULT 0,
  meta_json     TEXT,                   -- full target dict (thresholds, notes)
  enabled       INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS status (
  id            INTEGER PRIMARY KEY,
  ts            INTEGER NOT NULL,       -- unix epoch of collection
  target_id     INTEGER NOT NULL REFERENCES targets(id),
  severity      TEXT NOT NULL,          -- OK | WARN | CRIT | UNKNOWN
  -- common
  snap_age_src_s   INTEGER,
  snap_age_dst_s   INTEGER,
  repl_lag_s       INTEGER,             -- age of newest snapshot common to src+dst
  pool_health      TEXT,
  pool_cap_pct     INTEGER,
  last_scrub_ts    INTEGER,
  usedbysnapshots  INTEGER,
  compressratio    REAL,
  key_status       TEXT,
  -- borg
  archive_count    INTEGER,
  dedup_ratio      REAL,
  logical_size     INTEGER,
  physical_size    INTEGER,
  last_check_ts    INTEGER,
  last_check_result TEXT,
  lock_state       TEXT,
  -- backupninja
  handler_type     TEXT,
  handler_result   TEXT,
  last_run_ts      INTEGER,
  -- freeform
  detail_json      TEXT,
  last_error       TEXT
);
CREATE INDEX IF NOT EXISTS idx_status_target_ts ON status(target_id, ts);

CREATE TABLE IF NOT EXISTS intents (
  id            INTEGER PRIMARY KEY,
  target_id     INTEGER REFERENCES targets(id),
  action        TEXT NOT NULL,          -- sync | scrub | status | restore
  state         TEXT NOT NULL DEFAULT 'pending', -- pending|claimed|running|done|failed|stalled
  requested_by  TEXT,
  created_ts    INTEGER NOT NULL,
  claimed_ts    INTEGER,
  claimed_by    TEXT,
  result        TEXT,
  result_ts     INTEGER,
  notified      INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_intents_state ON intents(state);

-- Vault self-reports (call-home payloads), append-only. Doubles as heartbeat.
CREATE TABLE IF NOT EXISTS vault_reports (
  id            INTEGER PRIMARY KEY,
  ts            INTEGER NOT NULL,
  agent         TEXT NOT NULL,
  payload_json  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_vault_reports_ts ON vault_reports(agent, ts);
