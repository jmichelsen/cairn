# Phase 1 deploy - collector + API (least-privilege / user mode = default)

The collector runs as **`jmichelsen`**, not root. A one-time grant script opens *read* access to
the root-owned bits (borg repos, backupninja reports) and installs a scoped `smartctl` sudoers
rule. Backups themselves keep running as root (unchanged). Mail goes through the existing
a local SMTP relay (`127.0.0.1:2500`) - no credentials, no root, no widening `/etc/msmtprc`.

Do Phase 0 (`../phase0/INSTALL.md`) first - Phase 1 reuses its `notify.sh` + env file.

## 1. One-time access grant (run once, with sudo)

```
sudo /home/jmichelsen/backup-monitor/phase1/grant-access.sh
```
This: confirms you're in `backup`+`adm` (you already are), group-reads the borg repos
(`chgrp backup` + setgid), makes backupninja reports `adm`-readable, and installs
`/etc/sudoers.d/backup-monitor-smart` (scoped to the read-only SMART wrapper only).

Then log out/in (or `exec su - jmichelsen`) so the groups apply, and sanity-check:
```
sudo -u jmichelsen borg info --bypass-lock /mnt/backups/home | head
```

## 2. Install the collector

```
sudo mkdir -p /opt/backup-monitor/phase1 && sudo cp /home/jmichelsen/backup-monitor/phase1/{collector.py,schema.sql,smart-probe.sh} /opt/backup-monitor/phase1/ && sudo cp /home/jmichelsen/backup-monitor/targets.yaml /opt/backup-monitor/ && sudo chmod 755 /opt/backup-monitor/phase1/*.py /opt/backup-monitor/phase1/*.sh
```

Point `BM_TARGETS` at the installed copy in the env file, then test once as your user:
```
BACKUP_MONITOR_ENV=/etc/backup-monitor/backup-monitor.env BM_TARGETS=/opt/backup-monitor/targets.yaml python3 /opt/backup-monitor/phase1/collector.py --print
```
Expect: borg + backupninja + SMART now **OK/WARN/CRIT** (not UNKNOWN). If SMART is still
UNKNOWN, re-check the sudoers install.

## 3. Install the timer (runs as jmichelsen)

```
sudo cp /home/jmichelsen/backup-monitor/phase1/backup-collect.{service,timer} /etc/systemd/system/
```
```
sudo systemctl daemon-reload && sudo systemctl enable --now backup-collect.timer
```
```
systemctl list-timers backup-collect.timer
```

## 4. Alerting - run ONE alerter (avoid double-sends)

Phase 0's `check_backups.sh` and the collector both alert via `notify.sh`. Choose one:
- **Keep Phase 0** as the alerter; run the collector for the dashboard only (no `--alert`). ← default
- **Or** add `--alert` to the collector's `ExecStart` and `sudo systemctl disable --now backup-check.timer`.

## 5. The API / dashboard

Containerize under `docker/` (behind your own reverse proxy) - ships its own deps
(`requirements.txt`), so nothing lands on the host Python. Quick host smoke-test needs FastAPI in a
venv:
```
python3 -m venv /tmp/bmvenv && /tmp/bmvenv/bin/pip install -r /home/jmichelsen/backup-monitor/phase1/requirements.txt
```
```
BM_DB=/var/lib/backup-monitor/backup-monitor.db BM_API_TOKEN=$(openssl rand -hex 32) /tmp/bmvenv/bin/uvicorn api:app --app-dir /opt/backup-monitor/phase1 --host 127.0.0.1 --port 8929
```
Open `http://localhost:8929/` (HTML dashboard) and `curl -s localhost:8929/api/v1/backup/health | jq`.

Public control path (Phase 3): expose only `/api/v1/backup/{report,intents}` at
`your-host/api/v1/backup` with the per-vault token; keep the read-only views private.

---

### Root mode (alternative)

If you'd rather not grant group access, run the collector as root instead: drop
`User=`/`Group=`/`SupplementaryGroups=` from the service, set `MAIL_MODE=sendmail` +
`NOTIFY_EMAIL=root` in the env, and skip `grant-access.sh`. Everything else is identical.
