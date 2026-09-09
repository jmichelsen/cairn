# backup-monitor

One dashboard for the health of every backup on a ZFS host - **ZFS replication lag, pool
health/capacity/scrub, borg repos, backupninja handlers, and SMART** - with email + Gotify
alerts and **push-button on-demand actions** (snapshot / replicate / scrub). Self-hosted,
single small container + SQLite. No agent phone-home, no cloud.

Why it's different from a generic uptime monitor: it understands *backups specifically* - it
computes real **replication lag** (newest snapshot common to source and destination), a
**3-2-1 compliance scorecard**, a **coverage-gap** view ("what is backed up by nothing"), and
respects zero-knowledge encrypted replicas (flags a destination whose key unexpectedly loads).

## Quick start (Docker)

```bash
git clone https://github.com/jmichelsen/backup-monitor && cd backup-monitor
cp config/backup-monitor.env.example config/backup-monitor.env   # set SMTP + (optional) Gotify
cp config/targets.example.yaml       config/targets.yaml         # list YOUR pools/datasets/repos
# edit the collector mounts in docker-compose.yml to your borg/backupninja paths, then:
docker compose up -d --build
```
Open `http://<host>:8929/`. The `api` service serves the dashboard; the `collector` service
polls every `BM_INTERVAL` seconds. **Monitoring needs no root** - the collector reads ZFS via a
mounted `/dev/zfs` and reads borg/backupninja paths read-only.

**On-demand actions** (the Replicate/Snapshot/Scrub buttons) run a tiny **host-side** root
runner - the one privileged piece - so the network-facing container never has pool-destroying
rights. Add it only if you want actions: see `phase3/DEPLOY.md`.

## What runs where

| Piece | Where | Privilege |
| --- | --- | --- |
| API + dashboard, collector, SQLite, notifications, borg + backupninja reads | **container** | unprivileged |
| ZFS reads (`zpool`/`zfs list`) | **container** | needs `/dev/zfs` mounted; matching ZFS major version (or mount host binaries) |
| SMART | **container** | needs disk device passthrough + `SYS_RAWIO` (optional) |
| On-demand actions (`syncoid`/`zfs snapshot`/`zpool scrub`) | **host** | one small root systemd runner - the only privileged component |

A ZFS *action* tool can't fully avoid host root; the design shrinks that to one auditable
~200-line runner and keeps everything else in an unprivileged container. Monitoring-only users
never install it.

## Status

| Phase | What | State |
| --- | --- | --- |
| 0 | Alerting now, no app: sanoid/pool/scrub checks → email + Gotify, hourly timer | **built + tested** (deploy: `phase0/INSTALL.md`) |
| 1 | Collector → SQLite → JSON API + derived views (badge, 3-2-1, coverage-gap, timeline) | **built + tested vs live data** (deploy: `phase1/DEPLOY.md`) |
| 2 | Homepage widget + fuller dashboard | pending |
| 3 | **Local actions** (snapshot / replicate / scrub) - UI buttons → intent → root path-unit runner | **built + dry-run tested** (`phase3/DEPLOY.md`) |
| 3b | Vault poll agent + guarded restore | endpoints stubbed |
| 4 | Recovery-point catalog via `httm` | pending |

## Layout

```
backup-monitor.env.example   shared config (email, Gotify, paths, thresholds)
targets.yaml                 monitored backups + thresholds (source of truth for phase1)
phase0/  notify.sh           shared notifier: email always, Gotify on CRIT, per-key cooldown
         check_backups.sh    coarse all-pool check (snapshots, health, capacity, scrub)
         backup-check.{service,timer}   systemd units
         INSTALL.md
phase1/  schema.sql          SQLite schema (targets, status, intents, vault_reports)
         collector.py        4 adapters (zfs-local, zfs-repl, borg, backupninja) → SQLite
         api.py              read-only views + minimal HTML dashboard + vault/intent stubs
         requirements.txt    PyYAML, FastAPI, uvicorn
         DEPLOY.md
```

## Example findings

- **CRIT `photos`** - a snapshot may be stale; its off-site copy is
  also stale (not in `syncoid.service`). **Real problem.**
- **WARN `Pics` / `docs`** - some replication lag under the current *weekly* cadence;
  clears once cadence → nightly.
- **3-2-1 scorecard**: Tier-A datasets can FAIL (too few copies, no off-site) - the vault isn't
  built yet. Exactly the signal the scorecard exists to give.

## Notes

- **Runs as `jmichelsen` (least-privilege, default).** `grant-access.sh` opens *read* access to
  the root-owned bits: `backup` group for the borg repos (backups keep running as root;
  `encryption=none`), `adm` for backupninja log/reports, and a **scoped `smartctl` sudoers**
  wrapper for SMART. Backups themselves are unchanged. (You're already in `backup`+`adm`.) Root
  mode is a documented fallback.
- **Do NOT add your user to the `disk` group** for SMART - it grants raw read/write to every
  block device (read any FS bypassing perms, wipe pools). The scoped `smartctl` wrapper is the
  safe equivalent.
- **Mail via a local SMTP relay** (`127.0.0.1:2500`, `MAIL_MODE=relay`) - no creds, no
  root, no widening `/etc/msmtprc`. `NOTIFY_EMAIL` must be a real address (relay ignores
  `/etc/aliases`).
- **Read-only against all backups.** No prune/scrub/restore here; those are Phase-3 actions
  behind the intent queue. tank stays read-only (design §3). Every unreadable signal degrades to
  `UNKNOWN`, never crashes.
- Phase 1 reuses phase0's `notify.sh` + env file - nothing in Phase 0 is throwaway.
