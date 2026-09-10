# The agent

`agent.py` is the **one** program that runs on every host - the local machine and any remote
vault - and talks to the API over HTTP. There is no separate local vs remote design and no
file-based path.

Two capabilities:
- **report** (always): collect this host's backup status and POST it to the API.
- **execute** (opt-in, `BM_CAN_EXECUTE=1`): poll the API for intents assigned to this agent, run
  them, POST results. Commands are built from **this agent's trusted local `targets.yaml`**,
  never from the wire.

Intent routing is self-organizing: whatever an agent reports, it owns - the API routes that
target's action intents back to it (`targets.agent`).

## Auth (zero-trust)

Every API request needs a token - no request is trusted for being local. Two roles:
- **agent token** (`BM_API_TOKEN` on the agent) - may only `report` / poll `intents` / post
  `results`. A leaked agent token (e.g. from the remote vault) **cannot** read the dashboard or
  queue actions.
- **admin token** (`BM_ADMIN_TOKEN` on the API) - dashboard login + read views + queueing actions.

Everything is **hash-at-rest** (the API stores only `sha256(secret)`) and **per-agent** (one
credential per box, individually revocable). Two ways an agent authenticates:

**A. Enrollment (recommended - supports rotation).** Each agent holds a long-lived **enrollment
secret** and trades it for a **short-lived access token** via `/enroll`; it re-enrolls
automatically on any `401`. Mint the secret per box:
```
# admin API (from anywhere with the admin token):
curl -X POST -H "X-Backup-Token: $ADMIN" -H 'Content-Type: application/json' \
     -d '{"role":"agent","label":"vault"}' https://backups.example.com/api/v1/backup/tokens
# or offline on the API host:
BM_DB=/data/backup-monitor.db phase1/bmtoken.py mint --role agent --label vault
```
Put the secret in the agent's **`BM_ENROLL_SECRET`**. The access token lives only in memory and
expires (`BM_ACCESS_TTL`, default 24h) - the agent refreshes it silently.

**B. Static token (simplest).** Put a fixed access token in `BM_API_TOKEN` (add it to the API's
`BM_AGENT_TOKENS`). No rotation. Fine for a trusted local agent.

### The three admin operations

| Operation | Command | Effect |
| --- | --- | --- |
| **Scheduled rotation** | (automatic) | access tokens expire; the agent re-enrolls. Nothing to do. |
| **Forced rotation** (a token *leaked*, box is fine) | `POST /api/v1/backup/tokens/<label>/rotate` | kills the current access token now; the leaked copy is dead; the box re-enrolls with its (non-leaked) enrollment secret and resumes. An attacker holding the leaked token is locked out. |
| **Revoke** (box *compromised* / decommissioned) | `DELETE /api/v1/backup/tokens/<label>` | kills the enrollment secret **and** its access tokens - terminal; the box cannot self-heal. Provision a new credential out-of-band. |

`GET /api/v1/backup/tokens` lists labels/roles/kind/last-used (never the secret). A lockout guard
refuses to revoke the last active admin. The bootstrap admin comes from `BM_ADMIN_TOKEN` (hashed
at startup); mint more admins via `POST /tokens {role:"admin", label:"…"}`.

## Config (env)

| var | meaning |
| --- | --- |
| `BM_API_URL` | base URL of the API (`http://api:8929` locally, `https://host/api/v1/backup`… no - the base, e.g. `https://backups.example.com`) |
| `BM_API_TOKEN` | bearer token this agent presents (`X-Backup-Token`) |
| `BM_AGENT_NAME` | unique name (`local`, `vault`, …) - this is the ownership key |
| `BM_TARGETS` | path to the targets.yaml this agent manages |
| `BM_CAN_EXECUTE` | `1` to run actions (needs privilege), `0` = report-only |
| `BM_INTERVAL` | seconds between report+poll cycles |
| `BM_DRYRUN` | `1` = log the action command instead of running it |

## Local agent (main host)

The default `docker-compose.yml` runs it (`agent` service, report-only, ZFS reads via
`/dev/zfs`). To let the **local** agent execute actions you need ZFS write privilege:
- **Recommended:** run `agent.py` on the host as root (or with `zfs allow` delegation) instead of
  in the container - `BM_CAN_EXECUTE=1 BM_API_URL=http://localhost:8929 … python3 agent.py`.
- **Or** add `cap_add: [SYS_ADMIN]` to the agent container and set `BM_CAN_EXECUTE=1` (a heavier
  trust grant on a container).

Read-only monitoring needs neither - the container agent reports fine unprivileged.

## Upgrading past read-only (RO container → host agent)

The default stack runs the agent as an unprivileged **container** - great for monitoring, but its
action buttons are hidden, SMART is `UNKNOWN`, and kernel-watch needs a log mount. To unlock
actions / SMART / native journald, replace it with the agent running **on the host**.

**Two things the RO→host switch turns on that aren't obvious:**

1. **Stop the container agent first.** Both report under the same `BM_AGENT_NAME` (`local`). If you
   run *both*, each report flips the target's `can_execute` and ownership on every poll - buttons
   flicker and intents route unpredictably. The host agent must *replace* the container one, not
   run alongside it. (The `api` container keeps running - only `agent` stops.)
2. **`zpool scrub` needs real root; everything else doesn't.** `zfs allow` can delegate
   snapshot / send / receive / mount, but pool operations (`zpool scrub`) are not delegatable. So a
   **non-root host agent running as your normal user** already unlocks snapshot, replicate,
   recovery, and (via the `smart-probe.sh` sudoers wrapper) SMART + kernel-watch - the *only* thing
   that still needs root is the Scrub button. Prefer the user agent; reach for root only if you want
   Scrub under the app (or add a single `NOPASSWD: /usr/sbin/zpool scrub *` sudoers line and have
   `build_command` prefix `sudo`).

**Least-privilege check (do this once):** confirm your user holds the delegations the actions need -
`zfs allow <srcpool>` should list `send,snapshot,mount`; `zfs allow <dstpool>` should list
`receive,create,mount`. Missing pieces are granted with `zfs allow -u <you> <perms> <pool>` (needs
root once).

**The switch (user agent - recommended):**

```
cd ~/backup-monitor
docker compose stop agent               # 1. drop the RO container agent (api stays up)
./run-local-agent.sh report             # 2. report once, report-only - proves clean takeover
./run-local-agent.sh dry                # 3. execute+DRYRUN: buttons appear; a click only LOGS the command
                                        #    (click one in the UI, verify the [DRYRUN] line, Ctrl-C)
install -Dm644 backup-monitor-agent.service ~/.config/systemd/user/backup-monitor-agent.service
systemctl --user daemon-reload          # 4. install the persistent unit (shipped: backup-monitor-agent.service)
systemctl --user enable --now backup-monitor-agent.service
loginctl enable-linger "$USER"          #    keep it running across logout/reboot (may need root once)
```

Then click a **safe real action** (e.g. Snapshot on one dataset) and watch it reach `done`. The
unit reads the token from `config/backup-monitor.env`; flip `BM_DRYRUN=1` in it (then
`systemctl --user restart`) any time you want a rehearsal. `systemctl --user status
backup-monitor-agent` / `journalctl --user -u backup-monitor-agent -f` for logs.

**Rolling back** is symmetric: `systemctl --user disable --now backup-monitor-agent.service` then
`docker compose start agent` returns you to the RO container.

## Remote agent (the off-site vault)

Same `agent.py`, on the vault box, pointed at the API's public URL:
```
BM_API_URL=https://backups.example.com \
BM_API_TOKEN=<vault-token> \
BM_AGENT_NAME=vault \
BM_TARGETS=/etc/backup-monitor/vault-targets.yaml \
BM_CAN_EXECUTE=1 \
python3 agent.py          # or run it under systemd; it loops on BM_INTERVAL
```
- Only **outbound HTTPS** from the vault - nothing inbound at the remote site.
- The vault agent carries **no SMTP/Gotify creds** - the API does all alerting centrally.
- Its `vault-targets.yaml` defines what it manages (its local pool, its pull jobs) and the fixed
  commands it will run. A compromised API can only enqueue menu actions; it can't inject commands.
- Encrypted zero-knowledge replicas stay ciphertext: the agent reports snapshot timestamps + pool
  health without the key; it never needs to unlock anything.

## Buttons → agent

Dashboard buttons (Snapshot / Replicate +snap / Replicate existing / Scrub) `POST
/api/v1/backup/actions`. The API queues an intent routed to the target's owning agent; that agent
picks it up on its next poll, runs it, and the outcome flows back (email on done, email+Gotify on
fail). Latency to *start* = one poll interval; latency to *know the outcome* = the run itself
(the agent posts the result immediately).

## Recovery (Phase 4 - httm)

Recovery is exposed as agent actions (same intent/allowlist path, so it inherits auth + routing).
Buttons per dataset target: **Points / Deleted / Versions**, plus `restore` via the API.

| Action | Command the agent runs | Notes |
| --- | --- | --- |
| `recover-points` | `zfs list -t snapshot` | **fast** - no snapshot automount; the quick "when can I recover from" browse |
| `recover-search {path}` | `httm --json --recursive <mp>/<path>` | versions of a file/dir across snapshots |
| `recover-deleted {path?}` | `httm --deleted=only --recursive --json …` | files gone from live but present in snapshots |
| `restore {version, dest?}` | `cp -a --no-clobber` snapshot→staging | **copy-only**, never overwrites live; defaults to `<mp>/.bm-restores/` |

Guardrails: user-supplied paths are joined onto the target's dataset mountpoint and **rejected if
they escape it** (`../`, absolute paths outside the dataset); restore is copy-only to staging.

**Perf caveat:** `httm` (search/deleted) browses `.zfs/snapshot`, which **auto-mounts every
snapshot** - slow on datasets with many sanoid snapshots (tens of seconds to minutes the first
time). That's why recovery runs as async agent actions (never blocking the API) with a long
timeout; use **Points** (instant) for the common browse and reserve search/deleted for when you
actually need file-level history. The vault contributes recovery-point *timestamps* only
(ciphertext at rest; file-level recovery from it means pulling a snapshot home).

## Testing safely - the photos example

photos is in sync with backup but stopped being snapshotted 2025-12-05 (not in sanoid.conf), so its
"lag" is a snapshotting gap. To exercise the button end to end:
1. Run the owning agent with `BM_DRYRUN=1 BM_CAN_EXECUTE=1` and click **photos → Replicate +snap** -
   the result shows `[DRYRUN] would run: syncoid --no-privilege-elevation --no-stream
   tank/yourhost/photos backup/photos` (verified).
2. Drop `BM_DRYRUN`, click again - syncoid takes a fresh snapshot, sends it to backup, lag resets.
3. Real fix for the gap: add photos (+ laptop) to `sanoid.conf` + `syncoid.service`.

## Troubleshooting

**Borg repos show UNKNOWN / "Restore points: 0".** The nightly borg runs as **root** (via
`/etc/cron.d/backupninja`); with root's default umask it writes new repo segment files mode `0600`,
unreadable by the non-root agent - so every borg repo degrades to UNKNOWN and the restore-point
count drops to 0 (the card's reason says so). **Fix: re-run `sudo phase1/grant-access.sh`** - it
chmod's the existing files group-readable *and* sets `umask 0027` on the backupninja cron so future
segments stay readable. (Running the agent as root avoids this but gives up least privilege.)

**Borg still UNKNOWN after grant-access.sh, yet `borg info` works in your shell.** The
`systemd --user` agent isn't carrying the `backup` group: a user manager started *before* you joined
the group can't gain it, and a user unit can't add a group its manager lacks. The shipped unit works
around this by wrapping the agent in `sg backup` (re-reads the group list at exec). The clean
alternative is to restart the user manager so it re-reads membership - `sudo systemctl restart
user@$(id -u).service` (or reboot) - after which the `sg` wrapper is redundant.

**Replicate warns `cannot destroy snapshots: permission denied`.** The replication still succeeds;
syncoid just can't prune its old sync-snapshots on the source because the agent user lacks `destroy`
on that pool (intentional - see the tank read-only rule). Either use **no-snap** replication (sends
existing sanoid snapshots, creates none to prune), or delegate `destroy` *scoped to the replicated
datasets only* (`zfs allow -u <user> destroy pool/dataset`), never pool-wide.

**SMART all UNKNOWN as a non-root agent.** SMART reads through a scoped sudoers wrapper - run
`grant-access.sh`. The agent calls the root-owned `/opt/backup-monitor/phase1/smart-probe.sh` (not
the user-writable repo copy, which sudoers won't allow); set `BM_SMART_WRAPPER` if you deployed it
elsewhere.

**A target is stuck at an old status, or a renamed target lingers as UNKNOWN.** A target an agent
stops reporting (a rename like `smart` → `smart:sda`, a removed dataset) freezes at its last status
forever. Retire it: `UPDATE targets SET enabled=0 WHERE name='<name>'` in the DB (report ingest
never re-enables it).

**Encrypted replica fails: "cannot receive incremental stream: inherited key must be loaded".** The
destination is a zero-knowledge copy (its key is deliberately unavailable). Flag the target
`encrypted: true` so the agent sends **raw** (`--sendoptions=w`); a non-raw send needs the dest key
loaded and would defeat the zero-knowledge property.

**Action buttons hang / say "report-only".** The target is owned by a report-only agent
(`BM_CAN_EXECUTE=0`). Run an execute-capable agent on the owning host - see *Upgrading past
read-only* above. `zpool scrub` additionally needs real root (pool ops aren't `zfs allow`-able).
