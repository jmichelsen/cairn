#!/usr/bin/env bash
# Read-only SMART probe for backup-monitor. Granted to jmichelsen via a scoped sudoers
# rule so the user-mode collector can read disk health without broad root. HARD-CODED to
# read-only flags (-H health, -A attributes, -j json) - no self-tests, no writes.
#   smart-probe.sh /dev/sdX <type>
set -u
dev="${1:?device}"; typ="${2:-auto}"
case "$dev" in /dev/*) ;; *) echo '{"error":"device must be /dev/*"}'; exit 2 ;; esac
exec /usr/sbin/smartctl -j -H -A -d "$typ" "$dev"
