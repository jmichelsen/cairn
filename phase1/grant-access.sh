#!/usr/bin/env bash
# grant-access.sh - one-time setup so the collector can run as youruser with NO runtime sudo.
# Run with sudo. Idempotent. Makes NO backups run as the user (they stay root); it only grants
# durable READ access (group membership + group-readable borg segments via borg's own --umask), so
# the agent afterwards elevates nothing. SMART attribute-table detail is OPT-IN (--smart-detail),
# the one thing that needs a privileged probe. Mail uses a local SMTP relay (no widening needed).
set -euo pipefail
# The unprivileged user the monitor runs as. Derived from whoever invoked sudo (so it works for any
# user, not just the author); override with CAIRN_USER=... if needed.
U="${CAIRN_USER:-${SUDO_USER:-$(id -un)}}"
[ "$U" = root ] && { echo "FATAL: run me via sudo as your normal user (or set CAIRN_USER=<user>), not as root directly" >&2; exit 1; }
# SMART detail (identity + attribute table) needs a privileged smartctl and is therefore OPT-IN -
# the default install elevates NOTHING at runtime (disk health comes from smartd's journal). Pass
# --smart-detail (or SMART_DETAIL=1) to also install the scoped read-only smartctl sudo wrapper.
SMART_DETAIL="${SMART_DETAIL:-0}"
for a in "$@"; do [ "$a" = "--smart-detail" ] && SMART_DETAIL=1; done
BN_REPORTS=/var/lib/backupninja/reports
OPT=/opt/cairn/phase1

# Borg repos to open for group-read. Set CAIRN_BORG_REPOS="<path> <path> ..." to list them
# explicitly; otherwise we auto-discover local repo paths from the backupninja handlers in
# /etc/backup.d/*.borg (the 'repository'/'BORG_REPO'/'directory' lines). Remote (ssh://) repos and
# any path that doesn't exist locally are skipped.
if [ -n "${CAIRN_BORG_REPOS:-}" ]; then
  read -r -a BORG_REPOS <<< "$CAIRN_BORG_REPOS"
else
  BORG_REPOS=()
  shopt -s nullglob
  for h in /etc/backup.d/*.borg; do
    while IFS= read -r p; do
      [ -n "$p" ] && [ "${p#ssh://}" = "$p" ] && BORG_REPOS+=("$p")
    done < <(sed -nE 's/^[[:space:]]*(repository|BORG_REPO|directory)[[:space:]]*=[[:space:]]*//p' "$h" | tr -d '"'"'"'')
  done
fi

echo "== groups (already members here, but idempotent) =="
getent group backup >/dev/null || groupadd -f backup
id -nG "$U" | tr ' ' '\n' | grep -qx backup || usermod -aG backup "$U"
id -nG "$U" | tr ' ' '\n' | grep -qx adm    || usermod -aG adm "$U"

OPENED_BORG=0; FIRST_BORG=""
echo "== borg repos: group-read (backups keep running as root; encryption=none) =="
for r in "${BORG_REPOS[@]}"; do
  [ -e "$r" ] || { echo "  skip (missing): $r"; continue; }
  chgrp -R backup "$r"
  chmod -R g+rX "$r"
  find "$r" -type d -exec chmod g+s {} +   # setgid: new files inherit group 'backup'
  echo "  opened: $r"; OPENED_BORG=$((OPENED_BORG+1)); [ -n "$FIRST_BORG" ] || FIRST_BORG="$r"
done
[ "$OPENED_BORG" = 0 ] && echo "  (no local borg repos found on this host - nothing to open)"

echo "== borg handlers: 'create_options = --umask 0027' so nightly segments are group-readable =="
# WHY a shell/cron umask does NOT work here: /usr/sbin/backupninja hard-sets 'umask 077', and borg's
# own default is --umask 0077 -> segment files land 0600 (no group read) regardless of the shell umask,
# so every repo goes UNKNOWN after the next run. The real, one-time fix is borg's OWN --umask, set once
# per handler. Then every future run (root's EXISTING backupninja cron) writes 0640 group-readable files
# and the unprivileged agent reads them with NO runtime sudo, forever. Install-time only; sudoless after.
# Handler backups live OUTSIDE /etc/backup.d - backupninja processes EVERY file in that dir and errors
# ("no handler script for suffix 'bm-bak'") on any it doesn't recognize, which fails the whole run. A
# sibling dir is never scanned. Also migrate any *.bm-bak an older version of this script left in place.
HBAK=/etc/backup.d.cairn-bak
mkdir -p "$HBAK"
bakof() { echo "$HBAK/$(basename "$1").bm-bak"; }
shopt -s nullglob
for stray in /etc/backup.d/*.bm-bak; do
  mv -f "$stray" "$HBAK/$(basename "$stray")"; echo "  moved stray backup out of /etc/backup.d: $(basename "$stray")"
done
for h in /etc/backup.d/*.borg; do
  # REPAIR: an earlier version added an inline '# ...' comment to create_options. backupninja
  # interpolates the value into a shell command, so the '#' comments out the archive name + paths
  # and `borg create` fails ("the following arguments are required: ARCHIVE, PATH"). Strip any
  # trailing comment from a create_options line so the handler runs again. Must run BEFORE the
  # "already sets --umask" skip, since a broken line still contains --umask.
  if grep -Eq '^[[:space:]]*create_options[[:space:]]*=[^#]*#' "$h"; then
    b="$(bakof "$h")"; [ -e "$b" ] || cp -a "$h" "$b"
    sed -i -E 's/^([[:space:]]*create_options[[:space:]]*=[^#]*[^#[:space:]])[[:space:]]*#.*$/\1/' "$h"
    echo "  repaired create_options (removed an inline comment that broke borg create): $h"
  fi
  if grep -Eq '^[[:space:]]*create_options[[:space:]]*=.*--umask' "$h"; then
    echo "  already sets --umask: $h"; continue
  fi
  b="$(bakof "$h")"; cp -a "$h" "$b"
  # NB: the backupninja borg handler reads create_options from the [source] section
  # (setsection source -> getconf create_options), so it MUST live under [source], not EOF.
  # NEVER put an inline '# comment' on this line - it is interpolated into a shell command.
  if grep -Eq '^[[:space:]]*create_options[[:space:]]*=' "$h"; then
    sed -i -E 's#^([[:space:]]*create_options[[:space:]]*=[[:space:]]*)#\1--umask 0027 #' "$h"
  elif grep -Eq '^[[:space:]]*\[source\]' "$h"; then
    sed -i -E '/^[[:space:]]*\[source\]/a create_options = --umask 0027' "$h"
  else
    echo "  WARN: no [source] section in $h - add 'create_options = --umask 0027' under [source] by hand"
    rm -f "$b"; continue
  fi
  if grep -Eq '^[[:space:]]*create_options[[:space:]]*=.*--umask 0027' "$h"; then
    echo "  patched: $h (backup: $b)"
  else
    echo "  WARN: could not patch $h - add 'create_options = --umask 0027' by hand"; cp -a "$b" "$h"
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
  # `Defaults:$U !requiretty` lets the tty-less agent run the wrapper via sudo. Classic sudo needs it
  # where the system sets a global `requiretty`; sudo-rs (newer Debian/Ubuntu) doesn't know the setting
  # ("unknown setting: requiretty") AND never requires a tty - so build WITH the line, and if that fails
  # validation, drop it and validate again rather than aborting.
  write_sudoers() {
    { echo "# cairn: allow $U to run ONLY the read-only SMART probe wrapper as root."
      [ "${1:-1}" = 1 ] && echo "Defaults:$U !requiretty"
      echo "$U ALL=(root) NOPASSWD: $OPT/smart-probe.sh"; } > "$SUDO_TMP"
  }
  write_sudoers 1
  visudo -cf "$SUDO_TMP" >/dev/null 2>&1 || { echo "  (this sudo rejects !requiretty - omitting it; it isn't needed here)"; write_sudoers 0; }
  if visudo -cf "$SUDO_TMP" >/dev/null; then
    install -o root -g root -m 0440 "$SUDO_TMP" /etc/sudoers.d/cairn-smart
    echo "  sudoers installed + validated - now set CAIRN_SMART_DETAIL=1 on the agent + restart it"
  else
    echo "  ERROR: generated sudoers failed validation - NOT installing" >&2
    rm -f "$SUDO_TMP"; exit 1
  fi
  rm -f "$SUDO_TMP"
else
  echo "== smartctl: SKIPPED (default) - disk health comes from smartd's journal, no runtime sudo =="
  echo "   to add the full attribute table later: re-run with --smart-detail, then set"
  echo "   CAIRN_SMART_DETAIL=1 on the agent and restart it. To REMOVE a previously-installed wrapper:"
  echo "     rm -f /etc/sudoers.d/cairn-smart $OPT/smart-probe.sh"
fi

# Build the closing notes from what actually happened on THIS host, so a box with no borg/backupninja
# (e.g. a vault) doesn't get guidance about repos it doesn't have.
echo ""
echo "DONE. Notes:"
echo "  * Log out/in (or run 'exec su - \"\$USER\"') for the new group membership to take effect in your shell."
if [ "$OPENED_BORG" -gt 0 ]; then
  echo "  * borg repos: opened $OPENED_BORG repo(s) for group-read AND set 'create_options = --umask 0027' in"
  echo "    each /etc/backup.d/*.borg, so FUTURE nightly segments are written group-readable. One-time change -"
  echo "    the agent then reads borg with NO runtime sudo and won't regress nightly. Verify after the next run"
  echo "    (restore-points non-zero on the dashboard):  sudo -u \"\$USER\" borg info --bypass-lock '$FIRST_BORG' | head"
  echo "  * If a borg repo ever shows UNKNOWN again, it's leftover 0600 files from before the fix - re-run this once."
fi
if [ "$SMART_DETAIL" = 1 ]; then
  echo "  * SMART detail: wrapper + sudoers installed. Set CAIRN_SMART_DETAIL=1 on the agent unit and restart it"
  echo "    (the installer does this for you). To remove later: rm -f /etc/sudoers.d/cairn-smart $OPT/smart-probe.sh"
fi
echo "  * Alert email is optional and configured in cairn.env, not here (a local SMTP relay avoids widening msmtprc)."
