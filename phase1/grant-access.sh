#!/usr/bin/env bash
# grant-access.sh - one-time setup so the collector can run as jmichelsen (least privilege).
# Run with sudo. Idempotent. Makes NO backups run as the user (they stay root); only opens
# READ access + a scoped smartctl sudoers. Mail uses a local SMTP relay (no widening needed).
set -euo pipefail
U=jmichelsen
BORG_REPOS=(/mnt/backups/docker_data /mnt/backups/home /mnt/backups/var /srv/borg-pre)
BN_REPORTS=/var/lib/backupninja/reports
OPT=/opt/backup-monitor/phase1

echo "== groups (already members here, but idempotent) =="
getent group backup >/dev/null || groupadd -f backup
id -nG "$U" | tr ' ' '\n' | grep -qx backup || usermod -aG backup "$U"
id -nG "$U" | tr ' ' '\n' | grep -qx adm    || usermod -aG adm "$U"

echo "== borg repos: group-read (backups keep running as root; encryption=none) =="
for r in "${BORG_REPOS[@]}"; do
  [ -e "$r" ] || { echo "  skip (missing): $r"; continue; }
  chgrp -R backup "$r"
  chmod -R g+rX "$r"
  find "$r" -type d -exec chmod g+s {} +   # setgid: new files inherit group 'backup'
  echo "  opened: $r"
done

echo "== backupninja cron: umask 0027 so NEW nightly segments are group-readable, not root-only =="
# The setgid dirs above fix the GROUP of new files, but root's default umask (0077) still writes
# them mode 0600 -> the non-root agent can't read them and every borg repo goes UNKNOWN after the
# next run. Set umask 0027 on the invocation so root creates 0640 (group-readable) files.
CRON=/etc/cron.d/backupninja
if [ -f "$CRON" ]; then
  if grep -q 'umask' "$CRON"; then
    echo "  already sets umask: $CRON"
  else
    cp -a "$CRON" "$CRON.bm-bak"
    sed -i -E '/backupninja/ s#(^[0-9*/, ]+root )#\1umask 0027; #' "$CRON"
    grep -q 'umask 0027' "$CRON" && echo "  applied umask 0027 (backup: $CRON.bm-bak)" \
      || { echo "  WARN: could not patch $CRON automatically - add 'umask 0027;' after 'root' by hand"; cp -a "$CRON.bm-bak" "$CRON"; }
  fi
else
  echo "  no $CRON - if backupninja runs via systemd, add 'UMask=0027' to its unit instead"
fi

echo "== backupninja reports/log: adm-readable =="
[ -d "$BN_REPORTS" ] && { chgrp -R adm "$BN_REPORTS"; chmod -R g+rX "$BN_REPORTS"; echo "  opened: $BN_REPORTS"; }
if [ -f /var/log/backupninja.log ]; then
  chgrp adm /var/log/backupninja.log 2>/dev/null || true   # ensure group=adm, not just g+r
  chmod g+r  /var/log/backupninja.log 2>/dev/null || true
fi

echo "== smartctl: scoped sudoers for the read-only probe wrapper =="
SRC_WRAPPER="$(dirname "$0")/smart-probe.sh"
[ -f "$SRC_WRAPPER" ] || { echo "  ERROR: $SRC_WRAPPER not found (run from the phase1 dir)" >&2; exit 1; }
install -D -o root -g root -m 0755 "$SRC_WRAPPER" "$OPT/smart-probe.sh"
# Validate a TEMP copy first - a broken file in /etc/sudoers.d can wedge all sudo.
SUDO_TMP="$(mktemp)"
cat >"$SUDO_TMP" <<EOF
# backup-monitor: allow jmichelsen to run ONLY the read-only SMART probe wrapper as root.
Defaults:$U !requiretty
$U ALL=(root) NOPASSWD: $OPT/smart-probe.sh
EOF
if visudo -cf "$SUDO_TMP" >/dev/null; then
  install -o root -g root -m 0440 "$SUDO_TMP" /etc/sudoers.d/backup-monitor-smart
  echo "  sudoers installed + validated"
else
  echo "  ERROR: generated sudoers failed validation - NOT installing" >&2
  rm -f "$SUDO_TMP"; exit 1
fi
rm -f "$SUDO_TMP"

cat <<EOF

DONE. Notes:
  * Log out/in (or 'exec su - $U') for group membership to take effect in your shell.
  * Mail: uses a local SMTP relay on 127.0.0.1:2500 (MAIL_MODE=relay) - no msmtprc widening.
  * borg repos: this run chmod'd EXISTING files group-readable and set 'umask 0027' in
    /etc/cron.d/backupninja so FUTURE nightly segments stay group-readable. Verify after the
    next run (restore-points should be non-zero on the dashboard):
      sudo -u $U borg info --bypass-lock /mnt/backups/home | head
  * Re-run this script any time the borg repos show UNKNOWN - it re-opens new root-only files.
EOF
