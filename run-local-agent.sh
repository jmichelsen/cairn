#!/usr/bin/env bash
# run-local-agent.sh - run the host agent by hand for the RO->host upgrade walkthrough.
# It loads the token from config/cairn.env (via CAIRN_ENV) and points the
# agent at the local API. Persistent operation is the systemd --user unit, not this script.
#
#   ./run-local-agent.sh report   # report ONCE, report-only (CAN_EXECUTE=0) - proves takeover
#   ./run-local-agent.sh dry      # loop, execute+DRYRUN - buttons appear, commands only logged
#   ./run-local-agent.sh live     # loop, execute for real (same as the systemd unit)
set -euo pipefail
cd "$(dirname "$0")"

MODE="${1:-report}"
export CAIRN_ENV="$PWD/config/cairn.env"   # agent.py load_env() reads CAIRN_API_TOKEN from here
export CAIRN_API_URL="${CAIRN_API_URL:-http://localhost:8929}"
export CAIRN_AGENT_NAME="${CAIRN_AGENT_NAME:-local}"               # same name as the container agent = clean ownership handoff
export CAIRN_TARGETS="${CAIRN_TARGETS:-$PWD/config/targets.yaml}"
export CAIRN_INTERVAL="${CAIRN_INTERVAL:-900}"

case "$MODE" in
  report) export CAIRN_CAN_EXECUTE=0 CAIRN_DRYRUN=0; set -- --once ;;
  dry)    export CAIRN_CAN_EXECUTE=1 CAIRN_DRYRUN=1; set -- ;;
  live)   export CAIRN_CAN_EXECUTE=1 CAIRN_DRYRUN=0; set -- ;;
  *) echo "usage: $0 {report|dry|live}" >&2; exit 2 ;;
esac

echo "mode=$MODE  execute=$CAIRN_CAN_EXECUTE  dryrun=$CAIRN_DRYRUN  api=$CAIRN_API_URL  name=$CAIRN_AGENT_NAME"
[ "$MODE" = live ] && echo "WARNING: live mode EXECUTES queued actions (snapshot/replicate/scrub)."
exec /usr/bin/python3 agent.py "$@"
