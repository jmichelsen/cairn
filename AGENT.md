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

The agent presents its token via the `X-Backup-Token` header on every call.

**Per-agent tokens, hash-at-rest.** Each agent gets its OWN token (one row, individually
revocable) and the API stores only `sha256(token)` - never the token. Mint one per box:

```
# via the admin API (from anywhere, with the admin token):
curl -X POST -H "X-Backup-Token: $ADMIN" -H 'Content-Type: application/json' \
     -d '{"role":"agent","label":"vault"}' https://backups.example.com/api/v1/backup/tokens
# or offline on the API host (direct DB):
BM_DB=/data/backup-monitor.db phase1/bmtoken.py mint --role agent --label vault
```
The token is shown **once**; put it in the agent's `BM_API_TOKEN`. Revoke a single box without
touching the others: `DELETE /api/v1/backup/tokens/vault` (or `bmtoken.py revoke --label vault`).
`GET /api/v1/backup/tokens` lists labels/roles/last-used (never the secret). The bootstrap admin
comes from `BM_ADMIN_TOKEN` (hashed at startup); mint more admins the same way.

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

## Testing safely - the photos example

photos is in sync with backup but stopped being snapshotted 2025-12-05 (not in sanoid.conf), so its
"lag" is a snapshotting gap. To exercise the button end to end:
1. Run the owning agent with `BM_DRYRUN=1 BM_CAN_EXECUTE=1` and click **photos → Replicate +snap** -
   the result shows `[DRYRUN] would run: syncoid --no-privilege-elevation --no-stream
   tank/yourhost/photos backup/photos` (verified).
2. Drop `BM_DRYRUN`, click again - syncoid takes a fresh snapshot, sends it to backup, lag resets.
3. Real fix for the gap: add photos (+ laptop) to `sanoid.conf` + `syncoid.service`.
