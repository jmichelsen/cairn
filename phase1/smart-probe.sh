#!/usr/bin/env bash
# Read-only SMART probe for backup-monitor. Granted to jmichelsen via a scoped sudoers
# rule so the user-mode collector can read disk health without broad root. HARD-CODED to
# read-only flags (-a = all SMART info: health + identity + attributes + logs, -j json).
# -a is read-only (no self-tests, no writes) and adds model/serial/capacity/power-on/temp
# that the richer per-drive view needs. NVMe drives return their health-log block too.
#   smart-probe.sh /dev/sdX <type>
set -u
dev="${1:?device}"; typ="${2:-auto}"
case "$dev" in /dev/*) ;; *) echo '{"error":"device must be /dev/*"}'; exit 2 ;; esac
exec /usr/sbin/smartctl -j -a -d "$typ" "$dev"
