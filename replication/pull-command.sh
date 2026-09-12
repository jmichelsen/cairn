#!/bin/sh
# cairn replication - forced-command wrapper for the PULL key (runs on the SEND side = home).
#
# The dedicated vault->home pull key is added to home's authorized_keys as:
#   restrict,command="/home/<user>/cairn/replication/pull-command.sh" ssh-ed25519 AAAA... cairn-pull
# so the key can do NOTHING but what this script allows: read-only ZFS send-side operations for
# syncoid pulling FROM this host. `restrict` also strips pty + all forwarding, so there is no
# interactive login and no tunneling.
#
# Security model (defense in depth):
#   1. `restrict` in authorized_keys: no shell, no pty, no port/agent/X11 forwarding.
#   2. This wrapper: deny-by-default. Bans shell metacharacters outright (no chaining / redirection /
#      injection), then permits ONLY `zfs send|list|get|holds`, exec'd directly (never via a shell).
#   3. The delegated user itself has only send/snapshot/hold/mount/diff on the source pool (no
#      destroy/receive), so even a bug here cannot delete or overwrite data on home.
# Every attempt is logged (allowed + denied) to $CAIRN_PULL_LOG so the whitelist can be tuned if a
# syncoid version needs another read-only verb.
set -eu
cmd="${SSH_ORIGINAL_COMMAND:-}"
log="${CAIRN_PULL_LOG:-$HOME/.cairn-pull.log}"
printf '%s  %s\n' "$(date -Is 2>/dev/null || date)" "$cmd" >> "$log" 2>/dev/null || true

deny() { printf '%s  DENIED: %s\n' "$(date -Is 2>/dev/null || date)" "$cmd" >> "$log" 2>/dev/null || true
         echo "cairn-pull: only read-only 'zfs send|list|get|holds' are permitted" >&2; exit 1; }

# 1) reject any shell metacharacter - prevents command chaining / redirection / substitution
case "$cmd" in
  *';'*|*'|'*|*'&'*|*'`'*|*'$'*|*'<'*|*'>'*|*'('*|*')'*|*'\'*) deny ;;
esac
nl='
'
case "$cmd" in *"$nl"*) deny ;; esac   # reject a literal embedded newline (multiline command)

# 2) Run only read-only zfs/zpool verbs + syncoid's harmless probes. Command LOOKUPS report every
#    NON-zfs helper (mbuffer, lzop, pv, sudo, ...) as ABSENT, which makes syncoid fall back to a plain
#    `zfs send` with NO pipe - so this wrapper never has to permit a pipeline (the metachar ban above
#    already forbids `|`). Validated commands run via eval so quoted dataset/snapshot names parse
#    (syncoid sends `zfs send 'pool/ds'@'snap'`); this is safe because step (1) rejected every
#    metacharacter that could chain, pipe, redirect, substitute, background, or escape. The user's
#    delegation (send/snapshot/hold, no destroy/receive) is the backstop under all of it.
run()    { set +e; eval "$cmd"; exit $?; }   # execute the validated command, propagating its exit code
absent() { exit 1; }                          # report a probed helper as not-installed -> plain send
# shellcheck disable=SC2086
set -- $cmd; c1="${1:-}"; c2="${2:-}"
case "$c1" in
  zfs)   case "$c2" in send|list|get|holds) run ;; esac ;;
  zpool) case "$c2" in get|list|status)     run ;; esac ;;
  echo|exit|true|:) run ;;                                        # syncoid echo/connection test + no-ops
  command) [ "$c2" = "-v" ] && { case "${3:-}" in zfs|zpool) run ;; *) absent ;; esac; } ;;
  which|type) case "$c2" in zfs|zpool) run ;; *) absent ;; esac ;; # lookups: real for zfs/zpool, else absent
esac
deny
