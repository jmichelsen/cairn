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
    # pure control plane - no ZFS/host access; ingests agent reports, serves the dashboard.
    exec uvicorn api:app --app-dir /app/phase1 --host 0.0.0.0 --port "${BM_PORT:-8929}"
    ;;
  agent)
    # the uniform agent: report status (+ execute intents if BM_CAN_EXECUTE=1), talking HTTP
    # to BM_API_URL. Same command whether this is the local host or a remote vault.
    exec python3 /app/agent.py
    ;;
  agent-1)
    exec python3 /app/agent.py --once
    ;;
  collect-1)
    # legacy: run the collector once writing SQLite directly (no API). For debugging.
    shift; exec python3 /app/phase1/collector.py "$@"
    ;;
  *)
    exec "$@"
    ;;
esac
