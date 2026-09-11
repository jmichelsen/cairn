# Phase 0 install - alerting now, no app

Closes the "I won't know if a backup silently stops" gap: snapshot freshness, pool
health/capacity, and scrub age → email (WARN/CRIT) + Gotify push (CRIT), on an hourly timer.

All commands are run **by you** (need root). One command per block.

## 1. Create the Gotify application token

Create an application token, either:

**UI:** Gotify → Apps → Create Application → name `cairn` → copy the token.

**or CLI:**
```
curl -s -u admin:admin -H 'Content-Type: application/json' -d '{"name":"cairn","description":"backup alerts"}' http://gotify.example.com/application
```
Copy the `"token"` value from the JSON response. (Change the admin password afterward if it's still `admin`.)

## 2. Install files

```
sudo mkdir -p /opt/cairn/phase0 /etc/cairn /var/lib/cairn
```
```
sudo cp /home/jmichelsen/cairn/phase0/{notify.sh,check_backups.sh} /opt/cairn/phase0/ && sudo chmod 755 /opt/cairn/phase0/*.sh
```
```
sudo cp /home/jmichelsen/cairn/cairn.env.example /etc/cairn/cairn.env && sudo chmod 640 /etc/cairn/cairn.env
```

## 3. Configure

Put the Gotify token in the env file (and confirm the email/URL):
```
sudo vi /etc/cairn/cairn.env
```
Set `GOTIFY_TOKEN=` to the token from step 1. `NOTIFY_EMAIL=root` routes root via `/etc/aliases`.

## 4. Test the notification path itself (before trusting it)

Mail defaults to `MAIL_MODE=relay` - through a local SMTP relay (`127.0.0.1:2500`), which
needs no creds or root, so this works as your user. `NOTIFY_EMAIL` must be a **real address**
(the relay doesn't resolve `/etc/aliases`).

```
CAIRN_ENV=/etc/cairn/cairn.env /opt/cairn/phase0/notify.sh CRIT "cairn test" "If you got this by email AND Gotify, the alert path works."
```
You should get an email **and** a Gotify push. If only email arrives, re-check `GOTIFY_URL`/`GOTIFY_TOKEN`.
(The service runs as `jmichelsen`; mail via relay, snapshot/pool checks are user-readable.)

## 5. Run the check once, manually

```
sudo CAIRN_ENV=/etc/cairn/cairn.env /opt/cairn/phase0/check_backups.sh; echo "exit=$?"
```
Review `/var/log/cairn.log`. It may flag a pool that is nearly full
or overdue for a scrub.

## 6. Install the timer

```
sudo cp /home/jmichelsen/cairn/phase0/backup-check.{service,timer} /etc/systemd/system/
```
```
sudo systemctl daemon-reload && sudo systemctl enable --now backup-check.timer
```
```
systemctl list-timers backup-check.timer
```

## 7. (Optional) uptime-kuma dead-man's switch

In uptime-kuma create a **Push** monitor named `backup-check`, heartbeat interval ~7200s,
retries 1. Copy its push URL into `KUMA_PUSH_BACKUP_CHECK=` in the env file. The check pings it
on every clean run; if the check itself stops running, kuma alerts. (Add one Push monitor per
backup **job** later - each syncoid/borg run pings on success.)

---

**Tuning:** cooldowns (`COOLDOWN_CRIT` 6h / `COOLDOWN_WARN` 24h) throttle repeat alerts per
finding. `POOL_EXCLUDE=nvme` skips scratch pools. `NOTIFY_GOTIFY_WARN=1` also pushes WARN.

Phase 1 (collector + API + dashboard) supersedes the coarse all-pools view with per-target
status, replication lag, borg/backupninja adapters, and the derived views - but it reuses this
same `notify.sh` and env file, so nothing here is throwaway.
