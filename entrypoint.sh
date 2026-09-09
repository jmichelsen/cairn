#!/usr/bin/env bash
# Container entrypoint. Dispatches by first arg:
#   api        - serve the dashboard + API (default)
#   collect    - run the collector on a loop every $BM_INTERVAL seconds
#   collect-1  - run the collector once and exit (for cron/testing)
#   runner     - process queued action intents once (usually the HOST runs this, not the container)
#   <other>    - exec it verbatim
set -euo pipefail

case "${1:-api}" in
  api)
    exec uvicorn api:app --app-dir /app/phase1 --host 0.0.0.0 --port "${BM_PORT:-8929}"
    ;;
  collect)
    echo "collector loop: interval=${BM_INTERVAL:-900}s alert=${BM_ALERT:-0}"
    while true; do
      if [ "${BM_ALERT:-0}" = "1" ]; then
        python3 /app/phase1/collector.py --alert || echo "collector run failed (continuing)"
      else
        python3 /app/phase1/collector.py || echo "collector run failed (continuing)"
      fi
      sleep "${BM_INTERVAL:-900}"
    done
    ;;
  collect-1)
    shift; exec python3 /app/phase1/collector.py "$@"
    ;;
  runner)
    exec python3 /app/phase3/backup-action-runner.py --once
    ;;
  *)
    exec "$@"
    ;;
esac
