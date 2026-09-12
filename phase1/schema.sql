-- cairn Phase 1 schema (SQLite). Collector writes; API reads.
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS targets (
  id            INTEGER PRIMARY KEY,
  name          TEXT NOT NULL,
  type          TEXT NOT NULL,          -- zfs-repl | zfs-local | borg-repo | backupninja-handler
  source        TEXT,
  dest          TEXT,
  tier          TEXT,                   -- A = irreplaceable
  transport     TEXT,                   -- local | vpn-pull | n/a
  location      TEXT,                   -- onsite | onsite-secondary | offsite
  cadence       TEXT,
  encrypted     INTEGER DEFAULT 0,
  agent         TEXT,                   -- which agent reported/owns this target (routes intents)
  meta_json     TEXT,                   -- full target dict (thresholds, notes)
  enabled       INTEGER DEFAULT 1,
  -- identity is per-AGENT: two agents (e.g. home + an off-site vault) may legitimately report a
  -- target with the same name without clobbering each other's row. Ingest upserts ON CONFLICT(agent,name).
  UNIQUE(agent, name)
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
  action        TEXT NOT NULL,          -- snapshot | sync | scrub | restore
  opts          TEXT,                   -- JSON action options, e.g. {"create_snapshot": true}
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

-- Agents that have reported, and whether they can execute actions (report-only agents can't).
-- Lets the dashboard hide action buttons and the API reject actions for report-only agents.
CREATE TABLE IF NOT EXISTS agents (
  name         TEXT PRIMARY KEY,
  can_execute  INTEGER DEFAULT 0,
  last_report_ts INTEGER
);

-- Auth credentials, HASH-AT-REST: only sha256(secret) is stored, never the secret.
-- Two-tier: an 'enroll' secret (long-lived, proves a box's identity) mints short-lived 'access'
-- tokens; 'admin' is a human dashboard credential. role = what it may do (admin|agent);
-- kind = credential type (admin|enroll|access). Per-agent rows are individually revocable.
CREATE TABLE IF NOT EXISTS auth_tokens (
  hash        TEXT PRIMARY KEY,       -- sha256 hex of the secret/token
  role        TEXT NOT NULL,          -- admin | agent
  kind        TEXT NOT NULL DEFAULT 'access',  -- admin | enroll | access
  label       TEXT UNIQUE,            -- human name, e.g. 'vault', 'local', 'bootstrap-admin'
  parent      TEXT,                   -- for access tokens: the enroll label that issued it
  expires_ts  INTEGER,                -- access tokens expire; NULL = never (static/admin/enroll)
  created_ts  INTEGER,
  last_used_ts INTEGER,
  active      INTEGER DEFAULT 1
);

-- acknowledgements: silence a known/transient WARN|CRIT until the condition changes or it expires.
-- sig = "<severity>|<reasons with digits masked>" so "resilvered 25h ago" and "...26h ago" match,
-- but a genuinely different condition (or a worse severity) does NOT - the ack auto-lapses.
CREATE TABLE IF NOT EXISTS acks (
  target  TEXT PRIMARY KEY,
  sig     TEXT NOT NULL,
  ts      INTEGER NOT NULL,
  note    TEXT
);

-- Reconciliation of cross-agent target overlaps (e.g. home's `zfs-repl -> iwolf/X` and a vault's
-- `zfs-local iwolf/X` are two ends of one relationship). Surfaced in the dashboard for the user to
-- resolve, rather than auto-hidden.
CREATE TABLE IF NOT EXISTS reconcile_dismissed (   -- "keep both": stop warning about this pair
  pair    TEXT PRIMARY KEY,
  ts      INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS target_retired (        -- user-retired target: stays disabled even if its
  agent   TEXT NOT NULL,                            -- agent keeps reporting it (survives re-ingest)
  name    TEXT NOT NULL,
  ts      INTEGER NOT NULL,
  PRIMARY KEY(agent, name)
);
