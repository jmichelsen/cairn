# Cairn

*A cairn marks the safe path and endures the weather - so you always know your way back to your data.*

One dashboard for the health of every backup on a ZFS host - **ZFS replication lag, pool
health/capacity/scrub, borg repos, backupninja handlers, and SMART** - with email + Gotify
alerts and **push-button on-demand actions** (snapshot / replicate / scrub). Self-hosted,
single small container + SQLite. No agent phone-home, no cloud.

Why it's different from a generic uptime monitor: it understands *backups specifically* - it
computes real **replication lag** (newest snapshot common to source and destination), a
**3-2-1 compliance scorecard**, a **coverage-gap** view ("what is backed up by nothing"), and
respects zero-knowledge encrypted replicas (flags a destination whose key unexpectedly loads).

## Quick start (`./install.sh`)

One entry point. It **installs any missing prerequisites** (docker, compose, python3-yaml, …),
asks a few questions, elevates **once** (a single sudo for prerequisites + borg/backupninja read
access + linger), then builds, configures, and starts everything - control plane, dashboard, and
the execute-capable local agent. Re-running is idempotent (your tokens/config are kept).

```bash
# one-liner - self-clones, then installs:
curl -fsSL https://raw.githubusercontent.com/youruser/cairn/main/install.sh | bash
```
or clone first:
```bash
git clone https://github.com/jmichelsen/cairn && cd cairn
./install.sh            # answer: role=home, alert email, (optional) Gotify, (optional) add a vault
```
Open `http://<host>:8929/` and log in with the `CAIRN_ADMIN_TOKEN` it prints. `./install.sh --check`
runs preflight only (changes nothing). Prompts read from your terminal even under `curl … | bash`.
The bootstrap clones to `~/cairn` (override with `CAIRN_DIR=` / `CAIRN_REPO=`).

**Remote off-site vault.** When `install.sh` (on home) asks *"add a remote vault?"*, it mints a
per-vault enrollment secret and either writes a `vault-install.conf` bundle to copy over, **or** -
if the vault is reachable by SSH - offers `ssh-copy-id` (so home always connects by key) and then
pushes + runs the vault install for you. On the vault, the same script consumes the bundle:
`./install.sh vault --config vault-install.conf`.

<details><summary>Manual Docker setup (what install.sh automates)</summary>

```bash
cp config/cairn.env.example config/cairn.env   # 3 tokens (openssl rand -hex 32) + SMTP/Gotify
cp config/targets.example.yaml config/targets.yaml               # list YOUR pools / datasets / repos
docker compose up -d --build                                     # api + report-only container agent
```
For **actions** you run the execute-capable host agent (`phase1/grant-access.sh` + the host agent
unit, see `AGENT.md`) - and in that case bring up **`docker compose up -d --build api`** (api only),
NOT the whole stack, or you end up with two agents reporting for the same host. `install.sh home`
does this for you (api-only container + host agent).
</details>

**Read-only first (recommended).** The default compose runs an **unprivileged, report-only**
container agent - great for kicking the tires. What you get vs. what needs the host agent:

| Works in the default RO container | Needs the host/execute agent |
| --- | --- |
| ZFS pool health, capacity, scrub age, **replication lag**, **resilver / vdev-error detection** | **action buttons** (replicate/scrub/snapshot/restore) - `CAIRN_CAN_EXECUTE=1` + ZFS write |
| borg repos, backupninja handlers, 3-2-1 scorecard, coverage-gap, timeline | **SMART** (needs disk passthrough) and **kernel-error watch** (needs journald access) |

Targets owned by a report-only agent show **"report-only"** instead of action buttons, and the
API refuses to queue actions for them - so nothing hangs. When you're ready for actions/SMART/
kernel-watch, run the agent on the host (see `AGENT.md`). The **`api`** service is a pure control plane (stores state, serves
the dashboard, dispatches alerts - it never touches ZFS). The **`agent`** service reads *this*
host's ZFS (via mounted `/dev/zfs`, unprivileged) + borg/backupninja and reports to the API every
`CAIRN_INTERVAL` seconds. **Monitoring needs no root.**

**One agent, any distance.** The same `agent.py` runs on a remote **off-site vault** pointed at
the API's public URL + a token - outbound HTTPS only, no separate design. See `AGENT.md`.

**On-demand actions** (Replicate/Snapshot/Scrub buttons) are executed by an agent running with
`CAIRN_CAN_EXECUTE=1` (needs ZFS write privilege - run it on the host as root, or grant the container
`SYS_ADMIN`). Commands are built from the agent's trusted local config, never from the wire.

## What runs where

| Piece | Component | Privilege |
| --- | --- | --- |
| API + dashboard, SQLite, alert dispatch (**no host access**) | **api** (container) | unprivileged; holds the SMTP/Gotify creds |
| ZFS/borg/backupninja **reads** → report to API | **agent** (container or host) | `/dev/zfs` mounted; matching ZFS major (or mount host binaries) |
| SMART | **agent** | disk device passthrough + `SYS_RAWIO` (optional) |
| On-demand **actions** (`syncoid`/`zfs snapshot`/`zpool scrub`) | **agent** with `CAIRN_CAN_EXECUTE=1` | ZFS write → host root or container `SYS_ADMIN` |
| Off-site **vault** reporting + pulls | **same agent**, remote | outbound HTTPS + token; no inbound, no creds |

**One uniform agent** does all host work - locally and remotely - talking only HTTP to the API.
The API never touches ZFS. A ZFS *action* tool can't avoid *some* write privilege where actions
run, but it lives only in an agent you opt into (`CAIRN_CAN_EXECUTE`); monitoring-only agents and the
API are unprivileged.

## Status

| Phase | What | State |
| --- | --- | --- |
| 0 | Alerting now, no app: sanoid/pool/scrub checks → email + Gotify, hourly timer | **built + tested** (deploy: `phase0/INSTALL.md`) |
| 1 | Collector → SQLite → JSON API + derived views (badge, 3-2-1, coverage-gap, timeline) | **built + tested vs live data** (deploy: `phase1/DEPLOY.md`) |
| 2 | Homepage widget + fuller dashboard | pending |
| 3 | **Actions** (snapshot / replicate / scrub) - buttons → intent → owning agent executes | **built + dry-run tested** (`AGENT.md`) |
| ✔ | **Control-plane + uniform agent** - one HTTP agent, local or remote vault; API touches no host | **built + end-to-end tested** |
| ✔ | **Zero-trust auth** - every endpoint; hash-at-rest; two-tier enroll+access with rotation/revoke | **built + tested** |
| 4 | **Recovery-point catalog via `httm`** - points / deleted-file / version search + guarded restore, as agent actions | **built + tested** |

## Layout

```
Dockerfile  docker-compose.yml  entrypoint.sh   container build (api + agent)
agent.py                        the ONE uniform agent (report + execute over HTTP)
AGENT.md                        how to run it: local, vault, execute mode
config/  *.example              generic env + targets templates (copy to real, edit)
phase0/  notify.sh              notifier: email (SMTP) + Gotify on CRIT, per-key cooldown
         check_backups.sh + units    standalone host alerting (Phase 0, optional)
phase1/  schema.sql             SQLite schema (targets, status, intents)
         collector.py           adapter library (zfs/borg/backupninja/smart) + collect_all()
         api.py                 control plane: report ingest, intent routing, views, dashboard
```

## Notes

- **Runs as `youruser` (least-privilege, default).** `grant-access.sh` opens *read* access to
  the root-owned bits: `backup` group for the borg repos (backups keep running as root;
  `encryption=none`), `adm` for backupninja log/reports, and a **scoped `smartctl` sudoers**
  wrapper for SMART. Backups themselves are unchanged. (The grant script adds you to `backup`+`adm`
  if needed.) Root mode is a documented fallback.
- **Do NOT add your user to the `disk` group** for SMART - it grants raw read/write to every
  block device (read any FS bypassing perms, wipe pools). The scoped `smartctl` wrapper is the
  safe equivalent.
- **Mail via a local SMTP relay** (e.g. an `msmtpd` sidecar on `127.0.0.1:2500`, `MAIL_MODE=relay`)
  - no creds, no root, no widening `/etc/msmtprc`. With a plain relay, `NOTIFY_EMAIL` must be a real
  address (the relay ignores `/etc/aliases`).
- **Read-only against all backups.** No prune/scrub/restore here; those are Phase-3 actions
  behind the intent queue. Your source pool stays read-only. Every unreadable signal degrades to
  `UNKNOWN`, never crashes.
- Phase 1 reuses phase0's `notify.sh` + env file - nothing in Phase 0 is throwaway.
