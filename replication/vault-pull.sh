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
# Args: [CONF] [--only NAME] [--conf CONF]. --only pulls just ONE configured SET (the dashboard's
# per-dataset "Replicate now"); no --only pulls every SET (the nightly timer).
CONF="$HOME/.config/cairn/replication.conf"; ONLY=""
while [ $# -gt 0 ]; do case "$1" in
  --only) ONLY="${2:-}"; shift ;;
  --conf) CONF="${2:-}"; shift ;;
  --*)    echo "cairn-pull: unknown option '$1'" >&2; exit 2 ;;
  *)      CONF="$1" ;;
esac; shift; done
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

# Warm up the link + verify we can actually reach home BEFORE syncoid's own preflight echo test.
# A lazy VPN (e.g. netbird `Lazy connection`) drops the FIRST packet on a cold/idle tunnel, so a single
# unretried ssh - which is exactly what syncoid's echo test is - spuriously fails ("Connection closed by
# <peer> port 22") even when home is up and healthy. Retry a few times to absorb that cold-start; if
# EVERY try fails, home is genuinely unreachable (VPN down) - exit 3, distinct from a data-send failure.
# `true` is permitted by the pull forced-command (pull-command.sh), so this tests the full path:
# VPN route -> sshd -> key auth -> forced command.
probe_home() {
  local tries="${PULL_PROBE_TRIES:-4}" wait="${PULL_PROBE_WAIT:-5}" i=1
  while [ "$i" -le "$tries" ]; do
    if ssh -o BatchMode=yes -o ConnectTimeout=10 -i "$KEY" "$HOME_SSH" true 2>/dev/null; then
      [ "$i" -gt 1 ] && echo "cairn-pull: reached $HOME_SSH on attempt $i/$tries"
      return 0
    fi
    echo "cairn-pull: cannot reach $HOME_SSH (attempt $i/$tries) - retrying in ${wait}s" >&2
    sleep "$wait"; i=$((i+1))
  done
  return 1
}
if ! probe_home; then
  echo "cairn-pull: UNREACHABLE - $HOME_SSH did not answer after ${PULL_PROBE_TRIES:-4} tries (VPN/netbird down?)" >&2
  exit 3
fi

COMMON=(--no-privilege-elevation --no-sync-snap --no-stream --sshkey "$KEY")
rc=0; ran=0
for s in "${SETS[@]}"; do
  IFS='|' read -r name src dst raw <<<"$s"
  [ -n "$ONLY" ] && [ "$name" != "$ONLY" ] && continue
  ran=$((ran+1))
  opts=("${COMMON[@]}"); [ "$raw" = raw ] && opts+=(--sendoptions=w)
  echo "== pull $name: $HOME_SSH:$src -> $dst ${raw:+(raw)} =="
  if syncoid "${opts[@]}" "$HOME_SSH:$src" "$dst"; then echo "  ok"; else echo "  FAILED ($name)"; rc=1; fi
done
[ -n "$ONLY" ] && [ "$ran" = 0 ] && { echo "cairn-pull: no configured SET named '$ONLY'" >&2; exit 2; }
[ "$rc" = 0 ] && echo "cairn-pull: ${ONLY:-all sets} current" || echo "cairn-pull: one or more sets FAILED"
exit "$rc"
