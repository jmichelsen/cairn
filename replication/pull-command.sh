#!/bin/sh
# cairn replication - forced-command wrapper for the PULL key (runs on the SEND side = home).
#
# The dedicated vault->home pull key is added to home's authorized_keys as:
#   restrict,command="/home/<user>/cairn/replication/pull-command.sh" ssh-ed25519 AAAA... cairn-pull
# so the key can do NOTHING but what this script allows.
#
# It permits syncoid's NORMAL send pipeline - `zfs send ... | lzop | mbuffer ...` - so compression and
# buffering work over the restricted key (important for a remote vault). It does this safely:
#   1. `restrict` in authorized_keys: no shell, no pty, no port/agent/X11 forwarding.
#   2. Reject every metacharacter that could chain / substitute / redirect / subshell / escape
#      (`; & ` $ < > ( ) \` + newline). The ONE control char left is the pipe `|`.
#   3. Split on `|` and validate EVERY stage: stage command must be read-only zfs/zpool, a stream
#      filter (lzop/mbuffer/pv/zstd/gzip/lz4), or a harmless probe (echo/exit/which/`command -v`).
#      Stream filters are additionally denied any file read/write (-o/-i/--output/--input or a path
#      token), so `mbuffer -o /home/.../evil` can't write and `mbuffer -i /etc/shadow` can't read.
#   4. Only then run via the shell (eval) so quoted dataset/snapshot names parse. Because every
#      dangerous metacharacter is gone and every stage is whitelisted, eval can run ONLY a zfs-send
#      data pipeline - no arbitrary command, no file access, no shell.
#   5. The user's zfs delegation (send/snapshot/hold, no destroy/receive) is the backstop under it all.
# Every attempt (allowed + denied) is logged to $CAIRN_PULL_LOG.
set -u
cmd="${SSH_ORIGINAL_COMMAND:-}"
log="${CAIRN_PULL_LOG:-$HOME/.cairn-pull.log}"
printf '%s  %s\n' "$(date -Is 2>/dev/null || date)" "$cmd" >> "$log" 2>/dev/null || true

deny() { printf '%s  DENIED: %s\n' "$(date -Is 2>/dev/null || date)" "$cmd" >> "$log" 2>/dev/null || true
         echo "cairn-pull: only a read-only zfs send pipeline is permitted" >&2; exit 1; }

# 1) reject every metacharacter except the pipe (no chaining / substitution / redirection / subshell)
case "$cmd" in
  *';'*|*'&'*|*'`'*|*'$'*|*'<'*|*'>'*|*'('*|*')'*|*'\'*) deny ;;
esac
nl='
'
case "$cmd" in *"$nl"*) deny ;; esac

# a single pipeline stage is valid if it is a read-only zfs/zpool verb, a stream filter with no file
# access, or a harmless probe. Called unquoted so the stage word-splits into $1,$2,... here.
valid_stage() {
  vw1="${1:-}"; vw2="${2:-}"
  case "$vw1" in
    zfs)   case "$vw2" in send|list|get|holds) return 0 ;; esac ;;
    zpool) case "$vw2" in get|list|status) return 0 ;; esac ;;
    lzop|mbuffer|pv|zstd|zstdmt|gzip|lz4)   # stream filters: deny any file read/write or path token
      for a in "$@"; do
        case "$a" in
          -o|-O|--output|-i|--input|-o*|-O*|--output=*|--input=*|*/*|/*) return 1 ;;
        esac
      done
      return 0 ;;
    echo|exit|true|:|which|type) return 0 ;;          # syncoid probes / connection test
    command) [ "$vw2" = "-v" ] && return 0 ;;          # only `command -v X` (lookup), never `command X`
  esac
  return 1
}

# 2) validate each pipeline stage
oIFS=$IFS; set -f; IFS='|'
for stage in $cmd; do
  IFS=$oIFS; set +f
  # shellcheck disable=SC2086
  valid_stage $stage || deny
  set -f; IFS='|'
done
IFS=$oIFS; set +f

# 3) run it (shell parses quotes + the validated pipeline)
eval "$cmd"
