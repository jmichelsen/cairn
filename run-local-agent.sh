#!/usr/bin/env bash
# run-local-agent.sh - run the host agent by hand for the RO->host upgrade walkthrough.
# It loads the token from config/backup-monitor.env (via BACKUP_MONITOR_ENV) and points the
# agent at the local API. Persistent operation is the systemd --user unit, not this script.
#
#   ./run-local-agent.sh report   # report ONCE, report-only (CAN_EXECUTE=0) - proves takeover
#   ./run-local-agent.sh dry      # loop, execute+DRYRUN - buttons appear, commands only logged
#   ./run-local-agent.sh live     # loop, execute for real (same as the systemd unit)
set -euo pipefail
cd "$(dirname "$0")"

MODE="${1:-report}"
export BACKUP_MONITOR_ENV="$PWD/config/backup-monitor.env"   # agent.py load_env() reads BM_API_TOKEN from here
export BM_API_URL="${BM_API_URL:-http://localhost:8929}"
export BM_AGENT_NAME="${BM_AGENT_NAME:-local}"               # same name as the container agent = clean ownership handoff
export BM_TARGETS="${BM_TARGETS:-$PWD/config/targets.yaml}"
export BM_INTERVAL="${BM_INTERVAL:-900}"

case "$MODE" in
  report) export BM_CAN_EXECUTE=0 BM_DRYRUN=0; set -- --once ;;
  dry)    export BM_CAN_EXECUTE=1 BM_DRYRUN=1; set -- ;;
  live)   export BM_CAN_EXECUTE=1 BM_DRYRUN=0; set -- ;;
  *) echo "usage: $0 {report|dry|live}" >&2; exit 2 ;;
esac

echo "mode=$MODE  execute=$BM_CAN_EXECUTE  dryrun=$BM_DRYRUN  api=$BM_API_URL  name=$BM_AGENT_NAME"
[ "$MODE" = live ] && echo "WARNING: live mode EXECUTES queued actions (snapshot/replicate/scrub)."
exec /usr/bin/python3 agent.py "$@"
