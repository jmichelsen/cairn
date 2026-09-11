#!/usr/bin/env bash
# check_backups.sh - Phase 0 alerting (no app). Runs on a timer as root.
#   - snapshot freshness  : sanoid --monitor-snapshots (policy-driven)
#   - pool health         : zpool health != ONLINE  -> CRIT
#   - pool capacity        : >= cap_crit -> CRIT, >= cap_warn -> WARN
#   - scrub age            : per-pool cadence (weekly for pools in SCRUB_WEEKLY_POOLS, else monthly)
# Emits via notify.sh (email always for WARN/CRIT, Gotify on CRIT), with per-finding
# cooldown. Pings a uptime-kuma push URL when the run completes with no CRIT (dead-man).
#
# SANOID_IGNORE: extra regex of sanoid --monitor lines to filter (e.g. a dataset that lives in
# sanoid.conf but isn't imported on this host). Combined with the built-in "does not exist" filter.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ENV_FILE="${CAIRN_ENV:-/etc/cairn/cairn.env}"
[ -r "$ENV_FILE" ] && . "$ENV_FILE"
NOTIFY="$HERE/notify.sh"
LOG="${NOTIFY_LOG:-/var/log/cairn.log}"
CAP_WARN="${cap_warn_pct:-85}"; CAP_CRIT="${cap_crit_pct:-92}"

log(){ printf '%s [check] %s\n' "$(date '+%F %T')" "$*" >>"$LOG" 2>/dev/null; }
# POOL_EXCLUDE: space/comma-separated pool names to skip (e.g. scratch pools). Default: nvme.
EXCL=" ${POOL_EXCLUDE:-nvme} "; EXCL="${EXCL//,/ }"
excluded(){ case "$EXCL" in *" $1 "*) return 0;; *) return 1;; esac; }
crit=0; warn=0
emit(){ # emit SEV KEY TITLE BODY
  local sev="$1" key="$2" title="$3" body="$4"
  [ "$sev" = CRIT ] && crit=$((crit+1)); [ "$sev" = WARN ] && warn=$((warn+1))
  log "$sev $key :: $title"
  "$NOTIFY" "$sev" "$title" "$body" "$key" || true
}

# --- 1. snapshot freshness via sanoid (filter not-imported-here noise) ---
if command -v sanoid >/dev/null 2>&1; then
  snap_filter="does not exist${SANOID_IGNORE:+|$SANOID_IGNORE}"
  snap_out="$(sanoid --monitor-snapshots 2>&1 | grep -viE "$snap_filter")"
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    case "$line" in
      CRITICAL*|*CRITICAL*) emit CRIT "snap-crit" "Snapshot freshness CRITICAL" "$line" ;;
      WARNING*|*WARNING*)   emit WARN "snap-warn" "Snapshot freshness WARNING" "$line" ;;
    esac
  done <<< "$snap_out"
else
  emit WARN "sanoid-missing" "sanoid not found" "Cannot check snapshot freshness."
fi

# --- 2 & 3. pool health + capacity ---
while IFS=$'\t' read -r name health cap size alloc free; do
  [ -z "$name" ] && continue
  excluded "$name" && continue
  if [ "$health" != "ONLINE" ]; then
    emit CRIT "pool-health-$name" "Pool $name is $health" \
      "zpool $name health=$health (expected ONLINE). Check: zpool status -v $name"
  fi
  if [ "$cap" -ge "$CAP_CRIT" ] 2>/dev/null; then
    emit CRIT "pool-cap-$name" "Pool $name ${cap}% full (CRIT>=${CAP_CRIT}%)" \
      "zpool $name at ${cap}% capacity."
  elif [ "$cap" -ge "$CAP_WARN" ] 2>/dev/null; then
    emit WARN "pool-cap-$name" "Pool $name ${cap}% full (WARN>=${CAP_WARN}%)" \
      "zpool $name at ${cap}% capacity."
  fi
done < <(zpool list -Hp -o name,health,capacity,size,alloc,free 2>/dev/null)

# --- 4. scrub age ---
# SCRUB_WEEKLY_POOLS: space/comma-separated pools you scrub weekly (WARN>10d/CRIT>24d);
# everything else is treated as monthly (WARN>40d/CRIT>70d).
now=$(date +%s)
WEEKLY=" ${SCRUB_WEEKLY_POOLS:-} "; WEEKLY="${WEEKLY//,/ }"
for pool in $(zpool list -H -o name 2>/dev/null); do
  excluded "$pool" && continue
  case "$WEEKLY" in
    *" $pool "*) sw=10; sc=24 ;;       # weekly
    *)           sw=40; sc=70 ;;       # monthly
  esac
  scan="$(zpool status "$pool" 2>/dev/null | grep -E 'scan:')"
  case "$scan" in
    *"in progress"*) continue ;;                       # scrub/resilver running now
    *"none requested"*|"") emit WARN "scrub-$pool" "Pool $pool never scrubbed" "$scan"; continue ;;
  esac
  # date is everything after the last ' on '
  sdate="${scan##* on }"
  sepoch="$(date -d "$sdate" +%s 2>/dev/null || echo 0)"
  [ "$sepoch" -eq 0 ] && continue
  age_d=$(( (now - sepoch) / 86400 ))
  if [ "$age_d" -ge "$sc" ]; then
    emit CRIT "scrub-$pool" "Pool $pool scrub ${age_d}d old (CRIT>=${sc}d)" "Last scrub: $sdate"
  elif [ "$age_d" -ge "$sw" ]; then
    emit WARN "scrub-$pool" "Pool $pool scrub ${age_d}d old (WARN>=${sw}d)" "Last scrub: $sdate"
  fi
done

# --- dead-man heartbeat: ping kuma only if the run itself completed with no CRIT ---
if [ -n "${KUMA_PUSH_BACKUP_CHECK:-}" ]; then
  msg="ok crit=$crit warn=$warn"
  curl -s -m 8 -o /dev/null "${KUMA_PUSH_BACKUP_CHECK}&status=up&msg=${msg// /%20}" 2>/dev/null || true
fi

log "run complete: crit=$crit warn=$warn"
# exit non-zero on CRIT so a manual/interactive run signals status too
[ "$crit" -eq 0 ]
