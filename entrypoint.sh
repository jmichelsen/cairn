#!/usr/bin/env bash
# Container entrypoint. Dispatches by first arg:
#   api        - serve the dashboard + API (default)
#   collect    - run the collector on a loop every $BM_INTERVAL seconds
#   collect-1  - run the collector once and exit (for cron/testing)
#   runner     - process queued action intents once (usually the HOST runs this, not the container)
#   <other>    - exec it verbatim
set -euo pipefail

# Fail loudly + early on missing/placeholder config (compose can't validate env_file contents,
# so we do it here - `docker compose up` then shows a clear message instead of a runtime 503).
_require() {  # _require VARNAME "hint"
  local v="${!1:-}"
  case "$v" in
    "" ) echo "FATAL: $1 is not set. $2" >&2; exit 1 ;;
    CHANGEME* ) echo "FATAL: $1 is still the placeholder ('$v'). $2" >&2; exit 1 ;;
  esac
}

case "${1:-api}" in
  api)
    _require BM_ADMIN_TOKEN "Set the 3 tokens in config/backup-monitor.env (generate: openssl rand -hex 32)."
    _require BM_AGENT_TOKENS "Set BM_AGENT_TOKENS in config/backup-monitor.env."
    # pure control plane - no ZFS/host access; ingests agent reports, serves the dashboard.
    exec uvicorn api:app --app-dir /app/phase1 --host 0.0.0.0 --port "${BM_PORT:-8929}"
    ;;
  agent)
    _require BM_API_URL "Set BM_API_URL (e.g. http://api:8929)."
    if [ -z "${BM_ENROLL_SECRET:-}" ]; then
      _require BM_API_TOKEN "Set BM_API_TOKEN (this agent's token) in config/backup-monitor.env, or use BM_ENROLL_SECRET."
    fi
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
