# Phase 3 deploy - on-demand actions (snapshot / replicate / scrub)

Adds push-button actions to the dashboard. Flow:

```
UI button ──POST /api/v1/backup/actions──▶ API (jmichelsen, unprivileged)
   inserts an intents row + writes /run/backup-intents/<id>.intent (atomic)
        │
   backup-action.path (root) sees the *.intent file
        ▼
   backup-action.service ─▶ backup-action-runner.py (ROOT)
   builds the command from targets.yaml (trusted) via a FIXED allowlist,
   runs it, updates the intents row, fires the outcome notification.
```

**Security:** the intent carries only `{id, target, action, create_snapshot}` - never a command.
The runner maps `(action, target-type)` to argv from the **root-owned `targets.yaml`**; arbitrary
strings are never executed. Allowlist: `snapshot` (any dataset) → `zfs snapshot`; `sync`
(zfs-repl only) → `syncoid --no-privilege-elevation --no-stream [--no-sync-snap] src dst`;
`scrub` (zfs-local only) → `zpool scrub`. Keep the `/actions` API PRIVATE (reverse proxy / VPN) - never
the public token path.

Prereq: Phase 1 deployed (collector populating the DB, API serving). The **API must run as
`jmichelsen` on the host** (or, if containerized, bind-mount `/run/backup-intents` rw and the DB)
so it can drop run-files the host path-unit sees.

## 1. Install files

```
sudo mkdir -p /opt/backup-monitor/phase3 && sudo cp /home/jmichelsen/backup-monitor/phase3/backup-action-runner.py /opt/backup-monitor/phase3/ && sudo chmod 755 /opt/backup-monitor/phase3/backup-action-runner.py
```
```
sudo cp /home/jmichelsen/backup-monitor/phase3/backup-monitor-tmpfiles.conf /etc/tmpfiles.d/backup-monitor.conf && sudo systemd-tmpfiles --create /etc/tmpfiles.d/backup-monitor.conf
```
```
sudo cp /home/jmichelsen/backup-monitor/phase3/backup-action.{service,path} /etc/systemd/system/ && sudo systemctl daemon-reload
```

## 2. TEST SAFELY FIRST - dry-run (no real syncoid)

Enable dry-run in the service, then arm the watcher:
```
sudo systemctl edit backup-action.service   # add:  [Service]\n Environment=BM_DRYRUN=1
```
```
sudo systemctl enable --now backup-action.path
```
Open the dashboard, click **photos → Replicate +snap**. The status line should walk
`pending → running → done`, and the journal shows the command it *would* run:
```
journalctl -u backup-action.service -n 20 --no-pager
```
Expect: `[DRYRUN] would run: syncoid --no-privilege-elevation --no-stream tank/yourhost/photos backup/photos`.
You'll also get the outcome email (INFO). Verified in scratch: all four actions build the right
command and the allowlist rejects invalid combos (e.g. scrub on a zfs-repl target).

## 3. Go live

Remove dry-run and reload:
```
sudo systemctl revert backup-action.service && sudo systemctl daemon-reload
```
Click **photos → Replicate +snap** again. This time syncoid takes a fresh `syncoid_...` snapshot on
`tank/yourhost/photos`, sends the incremental to `backup/photos`, and photos's replication lag resets to ~0.
Watch it:
```
journalctl -u backup-action.service -f
```
The dashboard's photos row should flip from CRIT to OK on the next collector run.

### Button reference
- **Snapshot** - `zfs snapshot <src>@bm-manual-<ts>` (capture a recovery point now; no send).
- **Replicate +snap** - new snapshot **then** replicate (catches current state; use this for photos).
- **Replicate existing** - replicate only existing snapshots (`--no-sync-snap`; nothing to do if
  the newest snapshot is already on the dest).
- **Scrub** (pools) - `zpool scrub <pool>`.

## 4. Don't forget the root cause

The button is manual catch-up. photos stopped being snapshotted on 2025-12-05 (not in
`sanoid.conf`) and isn't in `syncoid.service`. For ongoing protection, add photos (and laptop) to
both - otherwise you'll be clicking the button forever.
