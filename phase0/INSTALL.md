# Phase 0 install - legacy standalone alerter

> **Legacy and optional. You do not need this with cairn.** The cairn API alerts on its own from
> agent reports. This is the original standalone hourly checker, kept for hosts that run no cairn
> at all. Running it alongside cairn double-alerts on pool health, capacity and scrub findings.

Hourly checks of snapshot freshness (`sanoid --monitor-snapshots`), pool health/capacity, and scrub
age → email (WARN/CRIT) + Gotify push (CRIT).

The install steps need root (`sudo`). The service itself runs as a regular user by default (see
step 6). One command per block.

## 1. Create the Gotify application token

Skip this section if you aren't using Gotify. Otherwise create an application token, either:

**UI:** Gotify → Apps → Create Application → name `cairn` → copy the token.

**or CLI** (replace `<gotify-host>` and the admin credentials with your own):
```
curl -s -u admin:admin -H 'Content-Type: application/json' -d '{"name":"cairn","description":"backup alerts"}' http://<gotify-host>/application
```
Copy the `"token"` value from the JSON response. (Change the admin password afterward if it's still `admin`.)

## 2. Install files

```
sudo mkdir -p /opt/cairn/phase0 /etc/cairn /var/lib/cairn
```
```
sudo cp ~/cairn/phase0/{notify.sh,check_backups.sh} /opt/cairn/phase0/ && sudo chmod 755 /opt/cairn/phase0/*.sh
```
```
sudo cp ~/cairn/config/cairn.env.example /etc/cairn/cairn.env && sudo chmod 640 /etc/cairn/cairn.env
```

The unit runs as a regular user, which must be able to read the env file and write the log and
the cooldown state (`/var/log/cairn.log`, `/var/lib/cairn`). Replace `youruser` with that user:
```
sudo chgrp youruser /etc/cairn/cairn.env && sudo chown youruser: /var/lib/cairn && sudo touch /var/log/cairn.log && sudo chown youruser: /var/log/cairn.log
```
Without this the script still runs, but silently: it skips an unreadable env file, and drops log
lines and cooldown state it can't write (so findings re-alert every hour).

## 3. Configure

Put the Gotify token in the env file (and confirm the email/URL):
```
sudo vi /etc/cairn/cairn.env
```
Set `GOTIFY_TOKEN=` to the token from step 1 (or leave it blank to skip Gotify). Set
`NOTIFY_EMAIL` to a real address. `MAIL_MODE` accepts `smtp` (`relay` is an alias) or `sendmail`.
Only `MAIL_MODE=sendmail` resolves `/etc/aliases` (e.g. `NOTIFY_EMAIL=root`), and it needs a working
`/usr/sbin/sendmail` for the user the service runs as.

The env file is sourced by bash, so keep values free of spaces or quote them. Also set
`NOTIFY_LOG=/var/log/cairn.log` and `STATE_DIR=/var/lib/cairn` (the example's `/data/...` paths are
for the cairn container).

## 4. Test the notification path itself (before trusting it)

With `MAIL_MODE=smtp` through a local unauthenticated relay (`SMTP_HOST=127.0.0.1`,
`SMTP_PORT=2500`, `SMTP_TLS=off`, no `SMTP_USER`) no creds or root are needed, so this works as your
user. It needs `msmtp` installed.

```
CAIRN_ENV=/etc/cairn/cairn.env /opt/cairn/phase0/notify.sh CRIT "cairn test" "If you got this by email AND Gotify, the alert path works."
```
You should get an email **and** a Gotify push. If only email arrives, re-check `GOTIFY_URL`/`GOTIFY_TOKEN`.
(The service runs as `youruser`; mail goes via SMTP, and the snapshot/pool checks are
user-readable.)

## 5. Run the check once, manually

```
CAIRN_ENV=/etc/cairn/cairn.env /opt/cairn/phase0/check_backups.sh; echo "exit=$?"
```
Run it as the same user the service uses. Exit 1 means at least one CRIT finding.
Review `/var/log/cairn.log`. Expect it to flag any real problems it finds - a pool that's
nearly full, or one that's overdue for a scrub - and stay quiet otherwise.

## 6. Install the timer

Edit `backup-check.service` first: replace `User=youruser` / `Group=youruser` with the service
user. The script runs fine as root too: drop `User=`/`Group=` (it then defaults to root).
```
sudo cp ~/cairn/phase0/backup-check.{service,timer} /etc/systemd/system/
```
```
sudo systemctl daemon-reload && sudo systemctl enable --now backup-check.timer
```
```
systemctl list-timers backup-check.timer
```

## 7. (Optional) uptime-kuma dead-man's switch

In uptime-kuma create a **Push** monitor named `backup-check`, heartbeat interval ~7200s,
retries 1. Copy its push URL into `KUMA_PUSH_BACKUP_CHECK=` in the env file. The check pings it at
the end of every run (the message carries the crit/warn counts); if the check itself stops running,
kuma alerts. `KUMA_PUSH_BACKUP_CHECK` is this legacy script's heartbeat only. Cairn's own
heartbeat is `CAIRN_KUMA_PUSH_URL`.

---

**Tuning:** cooldowns (`COOLDOWN_CRIT` 6h / `COOLDOWN_WARN` 24h) throttle repeat alerts per
finding. `POOL_EXCLUDE=nvme` skips scratch pools. `NOTIFY_GOTIFY_WARN=1` also pushes WARN.

Cairn's API supersedes this with per-target status, replication lag, and the other adapters. It
uses the same `notify.sh` for delivery.
