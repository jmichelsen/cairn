#!/usr/bin/env bash
# cairn: scoped root wrapper to START a scrub on ONE pool. Granted to youruser via a narrow
# sudoers rule (see grant-access.sh --scrub) so the user-mode agent can trigger a scrub without
# broad root. `zpool` sub-commands are NOT covered by ZFS delegation (`zfs allow` is dataset-only),
# so a scrub genuinely needs root - this wrapper is the one, tightly-constrained way to get it.
# HARD-CONSTRAINED to `zpool scrub <existing-pool>`: no `-s` (stop), no other verb, no extra args.
# A scrub is a read/verify pass (reads every block, repairs from redundancy); it never destroys data.
#   zpool-scrub.sh <pool>
set -u
pool="${1:?pool}"
[ "$#" -eq 1 ] || { echo "cairn-scrub: exactly one arg (pool) expected" >&2; exit 2; }
# Reject anything that could smuggle a flag or extra token: only real pool-name characters.
case "$pool" in
  -*|*[!A-Za-z0-9_.:-]*) echo "cairn-scrub: invalid pool name '$pool'" >&2; exit 2 ;;
esac
ZP=""; for c in /usr/sbin/zpool /sbin/zpool; do [ -x "$c" ] && { ZP="$c"; break; }; done
[ -n "$ZP" ] || { echo "cairn-scrub: zpool binary not found" >&2; exit 2; }
# Must be an EXISTING pool - so the wire can't ask us to scrub something arbitrary.
"$ZP" list -H -o name "$pool" >/dev/null 2>&1 || { echo "cairn-scrub: no such pool: $pool" >&2; exit 2; }
exec "$ZP" scrub "$pool"
