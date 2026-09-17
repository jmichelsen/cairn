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
# Execute-capable hosts (e.g. a vault that runs its own scrubs) need one narrow privileged verb:
# `zpool scrub`. It is NOT covered by ZFS delegation (zpool sub-commands never are), so OPT-IN via
# --scrub installs a root-owned, tightly-scoped scrub wrapper + sudoers rule. Report-only hosts skip it.
SCRUB_EXEC="${SCRUB_EXEC:-0}"
for a in "$@"; do [ "$a" = "--scrub" ] && SCRUB_EXEC=1; done
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
# Set --umask 0027 on ONE option key of a handler (create_options / prune_options / compact_options).
# WHY all three, not just create: borg runs create, prune and compact as SEPARATE processes, and each
# reads only its OWN *_options; create_options does NOT carry to prune/compact. So `borg create` writes
# 0640 group-readable segments while the prune/compact step (default --umask 0077) writes 0600 ones -
# and since the repo index points at the NEWEST (prune/compact) segment, the agent hits EACCES on it and
# the whole repo reads UNKNOWN. A retroactive chmod fixes it only until the next nightly prune. Setting
# --umask on every borg subcommand is the durable fix. Adding an unused key is harmless: backupninja
# ignores an unknown config key, and prune_options/compact_options on a handler that doesn't prune/compact
# is simply never used.
ensure_umask_opt() {   # $1=handler file, $2=option key
  local h="$1" key="$2" b
  # REPAIR: an earlier version could leave an inline '# ...' comment on the line. backupninja interpolates
  # the value into a shell command, so a '#' comments out everything after it and borg fails. Strip it
  # FIRST, before the "already has --umask" skip (a broken line still contains --umask).
  if grep -Eq "^[[:space:]]*${key}[[:space:]]*=[^#]*#" "$h"; then
    b="$(bakof "$h")"; [ -e "$b" ] || cp -a "$h" "$b"
    sed -i -E "s/^([[:space:]]*${key}[[:space:]]*=[^#]*[^#[:space:]])[[:space:]]*#.*$/\1/" "$h"
    echo "  repaired ${key} (removed an inline comment that broke borg): $h"
  fi
  if grep -Eq "^[[:space:]]*${key}[[:space:]]*=.*--umask" "$h"; then
    echo "  already sets --umask on ${key}: $h"; return 0
  fi
  b="$(bakof "$h")"; [ -e "$b" ] || cp -a "$h" "$b"
  # NB: the borg handler reads *_options from the [source] section (setsection source), so it MUST live
  # under [source], not EOF. NEVER put an inline '# comment' on the line - it is shell-interpolated.
  if grep -Eq "^[[:space:]]*${key}[[:space:]]*=" "$h"; then
    sed -i -E "s#^([[:space:]]*${key}[[:space:]]*=[[:space:]]*)#\1--umask 0027 #" "$h"
  elif grep -Eq '^[[:space:]]*\[source\]' "$h"; then
    sed -i -E "/^[[:space:]]*\[source\]/a ${key} = --umask 0027" "$h"
  else
    echo "  WARN: no [source] section in $h - add '${key} = --umask 0027' under [source] by hand"; return 0
  fi
  if grep -Eq "^[[:space:]]*${key}[[:space:]]*=.*--umask 0027" "$h"; then
    echo "  patched ${key}: $h"
  else
    echo "  WARN: could not patch ${key} in $h - add '${key} = --umask 0027' by hand"
  fi
}
for h in /etc/backup.d/*.borg; do
  ensure_umask_opt "$h" create_options
  ensure_umask_opt "$h" prune_options
  ensure_umask_opt "$h" compact_options
done
shopt -u nullglob
# undo the old, INEFFECTIVE cron-umask patch a prior version of this script may have added.
# The backup MUST go to the sibling dir, never $CRON.bm-bak: cron runs EVERY file in /etc/cron.d
# regardless of extension, so a .bm-bak copy there fires backupninja a SECOND time each hour and the
# two runs race on the borg repo locks -> intermittent "FAILED". Migrate any such stray a prior
# version left behind, then back up out-of-tree.
CRON=/etc/cron.d/backupninja
if [ -f "$CRON.bm-bak" ]; then
  mv -f "$CRON.bm-bak" "$(bakof "$CRON")"
  echo "  moved stray cron backup out of /etc/cron.d (was double-triggering backupninja): $CRON.bm-bak"
fi
if [ -f "$CRON" ] && grep -q 'umask 0027; ' "$CRON"; then
  cp -a "$CRON" "$(bakof "$CRON")"
  sed -i -E 's#umask 0027; ##' "$CRON"
  echo "  removed the old no-op cron umask patch from $CRON (backup: $(bakof "$CRON"))"
fi

# `!requiretty` is meaningful ONLY to classic sudo, and only where a global `requiretty` is set.
# sudo-rs (Ubuntu 26.04+) has no such setting: it warns "unknown setting: requiretty" on EVERY sudo
# invocation if the line appears in any sudoers file, and it never requires a tty. So decide by the
# RUNTIME sudo (not whichever visudo is in PATH) - emit the line only for classic sudo. The visudo -cf
# checks below stay as a second safety net.
if sudo --version 2>/dev/null | grep -qi 'sudo-rs'; then USE_REQTTY=0; else USE_REQTTY=1; fi

if [ "$SCRUB_EXEC" = 1 ]; then
  echo "== zpool scrub: scoped sudoers for the scrub wrapper (OPT-IN --scrub, execute-capable hosts) =="
  SCRUB_SRC="$(dirname "$0")/zpool-scrub.sh"
  [ -f "$SCRUB_SRC" ] || { echo "  ERROR: $SCRUB_SRC not found (run from the phase1 dir)" >&2; exit 1; }
  install -D -o root -g root -m 0755 "$SCRUB_SRC" "$OPT/zpool-scrub.sh"
  # Validate a TEMP copy first - a broken file in /etc/sudoers.d can wedge all sudo. Same !requiretty
  # handling as the SMART wrapper (classic sudo needs it tty-less; sudo-rs rejects the setting).
  SUDO_TMP="$(mktemp)"
  write_scrub_sudoers() {
    { echo "# cairn: allow $U to run ONLY the scoped zpool-scrub wrapper as root."
      [ "${1:-1}" = 1 ] && echo "Defaults:$U !requiretty"
      echo "$U ALL=(root) NOPASSWD: $OPT/zpool-scrub.sh"; } > "$SUDO_TMP"
  }
  write_scrub_sudoers "$USE_REQTTY"
  visudo -cf "$SUDO_TMP" >/dev/null 2>&1 || { echo "  (this sudo rejects !requiretty - omitting it; it isn't needed here)"; write_scrub_sudoers 0; }
  if visudo -cf "$SUDO_TMP" >/dev/null; then
    install -o root -g root -m 0440 "$SUDO_TMP" /etc/sudoers.d/cairn-scrub
    echo "  sudoers installed + validated - the Scrub button now works on this host's pools"
  else
    echo "  ERROR: generated sudoers failed validation - NOT installing" >&2
    rm -f "$SUDO_TMP"; exit 1
  fi
  rm -f "$SUDO_TMP"
else
  echo "== zpool scrub: SKIPPED (report-only host) - to enable the Scrub button, re-run with --scrub =="
  echo "   to REMOVE a previously-installed scrub wrapper: rm -f /etc/sudoers.d/cairn-scrub $OPT/zpool-scrub.sh"
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
  write_sudoers "$USE_REQTTY"
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
  echo "  * borg repos: opened $OPENED_BORG repo(s) for group-read AND set '--umask 0027' on create_options,"
  echo "    prune_options AND compact_options in each /etc/backup.d/*.borg, so EVERY borg subcommand (not just"
  echo "    create) writes group-readable segments. WHY all three: create/prune/compact are separate borg"
  echo "    processes; create_options alone left the newest (prune/compact) segment 0600 and the repo index"
  echo "    points AT that segment -> the agent got EACCES on it and the repo read UNKNOWN, regressing every"
  echo "    night no matter how often this script ran. Verify after the next nightly run (restore-points"
  echo "    non-zero on the dashboard):  sudo -u \"\$USER\" borg info --bypass-lock '$FIRST_BORG' | head"
  echo "  * If a borg repo still shows UNKNOWN after the NEXT run, check for a 0600 segment:"
  echo "      find '$FIRST_BORG'/data -type f ! -perm -040 -printf '%M %p\\n'"
fi
if [ "$SMART_DETAIL" = 1 ]; then
  echo "  * SMART detail: wrapper + sudoers installed. Set CAIRN_SMART_DETAIL=1 on the agent unit and restart it"
  echo "    (the installer does this for you). To remove later: rm -f /etc/sudoers.d/cairn-smart $OPT/smart-probe.sh"
fi
echo "  * Alert email is optional and configured in cairn.env, not here (a local SMTP relay avoids widening msmtprc)."
