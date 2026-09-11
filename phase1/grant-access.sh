#!/usr/bin/env bash
# grant-access.sh - one-time setup so the collector can run as jmichelsen with NO runtime sudo.
# Run with sudo. Idempotent. Makes NO backups run as the user (they stay root); it only grants
# durable READ access (group membership + group-readable borg segments via borg's own --umask), so
# the agent afterwards elevates nothing. SMART attribute-table detail is OPT-IN (--smart-detail),
# the one thing that needs a privileged probe. Mail uses a local SMTP relay (no widening needed).
set -euo pipefail
U=jmichelsen
# SMART detail (identity + attribute table) needs a privileged smartctl and is therefore OPT-IN -
# the default install elevates NOTHING at runtime (disk health comes from smartd's journal). Pass
# --smart-detail (or SMART_DETAIL=1) to also install the scoped read-only smartctl sudo wrapper.
SMART_DETAIL="${SMART_DETAIL:-0}"
for a in "$@"; do [ "$a" = "--smart-detail" ] && SMART_DETAIL=1; done
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

echo "== borg handlers: 'create_options = --umask 0027' so nightly segments are group-readable =="
# WHY a shell/cron umask does NOT work here: /usr/sbin/backupninja hard-sets 'umask 077', and borg's
# own default is --umask 0077 -> segment files land 0600 (no group read) regardless of the shell umask,
# so every repo goes UNKNOWN after the next run. The real, one-time fix is borg's OWN --umask, set once
# per handler. Then every future run (root's EXISTING backupninja cron) writes 0640 group-readable files
# and the unprivileged agent reads them with NO runtime sudo, forever. Install-time only; sudoless after.
shopt -s nullglob
for h in /etc/backup.d/*.borg; do
  if grep -Eq '^[[:space:]]*create_options[[:space:]]*=.*--umask' "$h"; then
    echo "  already sets --umask: $h"; continue
  fi
  cp -a "$h" "$h.bm-bak"
  # NB: the backupninja borg handler reads create_options from the [source] section
  # (setsection source -> getconf create_options), so it MUST live under [source], not EOF.
  if grep -Eq '^[[:space:]]*create_options[[:space:]]*=' "$h"; then
    sed -i -E 's#^([[:space:]]*create_options[[:space:]]*=[[:space:]]*)#\1--umask 0027 #' "$h"
  elif grep -Eq '^[[:space:]]*\[source\]' "$h"; then
    sed -i -E '/^[[:space:]]*\[source\]/a create_options = --umask 0027   # backup-monitor: group-readable segments' "$h"
  else
    echo "  WARN: no [source] section in $h - add 'create_options = --umask 0027' under [source] by hand"
    rm -f "$h.bm-bak"; continue
  fi
  if grep -Eq '^[[:space:]]*create_options[[:space:]]*=.*--umask 0027' "$h"; then
    echo "  patched: $h (backup: $h.bm-bak)"
  else
    echo "  WARN: could not patch $h - add 'create_options = --umask 0027' by hand"; cp -a "$h.bm-bak" "$h"
  fi
done
shopt -u nullglob
# undo the old, INEFFECTIVE cron-umask patch a prior version of this script may have added
CRON=/etc/cron.d/backupninja
if [ -f "$CRON" ] && grep -q 'umask 0027; ' "$CRON"; then
  cp -a "$CRON" "$CRON.bm-bak"
  sed -i -E 's#umask 0027; ##' "$CRON"
  echo "  removed the old no-op cron umask patch from $CRON (backup: $CRON.bm-bak)"
fi

echo "== backupninja reports/log: adm-readable =="
[ -d "$BN_REPORTS" ] && { chgrp -R adm "$BN_REPORTS"; chmod -R g+rX "$BN_REPORTS"; echo "  opened: $BN_REPORTS"; }
if [ -f /var/log/backupninja.log ]; then
  chgrp adm /var/log/backupninja.log 2>/dev/null || true   # ensure group=adm, not just g+r
  chmod g+r  /var/log/backupninja.log 2>/dev/null || true
fi

if [ "$SMART_DETAIL" = 1 ]; then
  echo "== smartctl: scoped sudoers for the read-only probe wrapper (OPT-IN --smart-detail) =="
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
    echo "  sudoers installed + validated - now set BM_SMART_DETAIL=1 on the agent + restart it"
  else
    echo "  ERROR: generated sudoers failed validation - NOT installing" >&2
    rm -f "$SUDO_TMP"; exit 1
  fi
  rm -f "$SUDO_TMP"
else
  echo "== smartctl: SKIPPED (default) - disk health comes from smartd's journal, no runtime sudo =="
  echo "   to add the full attribute table later: re-run with --smart-detail, then set"
  echo "   BM_SMART_DETAIL=1 on the agent and restart it. To REMOVE a previously-installed wrapper:"
  echo "     rm -f /etc/sudoers.d/backup-monitor-smart $OPT/smart-probe.sh"
fi

cat <<EOF

DONE. Notes:
  * Log out/in (or 'exec su - $U') for group membership to take effect in your shell.
  * Mail: uses a local SMTP relay on 127.0.0.1:2500 (MAIL_MODE=relay) - no msmtprc widening.
  * borg repos: this run chmod'd EXISTING files group-readable AND set 'create_options = --umask
    0027' in each /etc/backup.d/*.borg so FUTURE nightly segments are written 0640 (group-readable).
    That's a ONE-TIME setup change - the agent then reads borg with NO runtime sudo, and it won't
    regress every night. Verify after the next backupninja run (restore-points non-zero on the
    dashboard):
      sudo -u $U borg info --bypass-lock /mnt/backups/home | head
  * No cron and no per-night chmod: the --umask fix is permanent once set. If a repo ever still
    shows UNKNOWN, it's leftover 0600 files from before the fix - re-run this once to chmod them.
EOF
