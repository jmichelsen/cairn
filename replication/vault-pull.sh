#!/usr/bin/env bash
# cairn replication - vault PULL runner.
#
# Pulls the configured datasets FROM home INTO this vault's pool over the dedicated restricted key.
# Delegation-only (no sudo): home has send/snapshot/hold on the sources, the vault has receive on its
# pool. syncoid runs normally (compression + mbuffer buffering + resume) - home's pull-command.sh is
# pipeline-aware and permits the `zfs send | lzop | mbuffer` pipeline while still allowing nothing else.
#
# Config (default ~/.config/cairn/replication.conf), whitespace-separated, '#' comments ok:
#   HOME_SSH  user@home-host-or-vpn-addr
#   KEY       /path/to/the/pull/private/key
#   SET       <name> <source-dataset> <dest-dataset> [raw]     # 'raw' => encrypted raw send (-w)
set -u
CONF="${1:-$HOME/.config/cairn/replication.conf}"
[ -f "$CONF" ] || { echo "cairn-pull: no config at $CONF" >&2; exit 2; }

HOME_SSH=""; KEY=""; SETS=()
while read -r kw a b c d _; do
  case "$kw" in
    HOME_SSH) HOME_SSH="$a" ;;
    KEY)      KEY="$a" ;;
    SET)      SETS+=("$a|$b|$c|${d:-}") ;;
    ""|\#*)   : ;;
  esac
done < "$CONF"
[ -n "$HOME_SSH" ] && [ -n "$KEY" ] && [ "${#SETS[@]}" -gt 0 ] \
  || { echo "cairn-pull: config incomplete (need HOME_SSH, KEY, and at least one SET)" >&2; exit 2; }
command -v syncoid >/dev/null || { echo "cairn-pull: syncoid not installed (apt install sanoid)" >&2; exit 2; }

COMMON=(--no-privilege-elevation --no-sync-snap --no-stream --sshkey "$KEY")
rc=0
for s in "${SETS[@]}"; do
  IFS='|' read -r name src dst raw <<<"$s"
  opts=("${COMMON[@]}"); [ "$raw" = raw ] && opts+=(--sendoptions=w)
  echo "== pull $name: $HOME_SSH:$src -> $dst ${raw:+(raw)} =="
  if syncoid "${opts[@]}" "$HOME_SSH:$src" "$dst"; then echo "  ok"; else echo "  FAILED ($name)"; rc=1; fi
done
[ "$rc" = 0 ] && echo "cairn-pull: all sets current" || echo "cairn-pull: one or more sets FAILED"
exit "$rc"
