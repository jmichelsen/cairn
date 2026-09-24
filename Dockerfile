# cairn - aggregate ZFS/borg/backupninja backup status, alert, and trigger actions.
#
# Multi-stage: the `deps` base pins the Python app dependencies ONCE, and both the production `runtime`
# image and the `ci` test image build from it - so CI provably runs the tests against the exact dependency
# versions production ships (no drift). Build the runtime with `--target runtime` (it's last, so also the
# default) and the CI checks with `--target ci`. The CI stages cache the deps across runs (see the
# .gitlab-ci.yml files); the two targets share the `deps` layer in the daemon, so pip runs once.

# ---- shared base: python + the app's pip deps (single source of truth for versions) ----
FROM python:3.12-slim AS deps
ENV DEBIAN_FRONTEND=noninteractive PIP_DISABLE_PIP_VERSION_CHECK=1
RUN pip install --no-cache-dir pyyaml "fastapi>=0.110" "uvicorn[standard]>=0.29" "segno>=1.6"

# ---- ci: adds nodejs (for check_js's `node --check`) + pytest, then RUNS the checks as the final layer.
# A failed `docker build --target ci` IS a failed test stage. Only the source COPY + this RUN re-run when
# code changes; the deps/apt/pip layers above stay cached. ----
FROM deps AS ci
ENV PYTHONDONTWRITEBYTECODE=1
RUN apt-get update -qq && apt-get install -y --no-install-recommends nodejs && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir pytest
WORKDIR /src
COPY phase1 /src/phase1
COPY tools  /src/tools
COPY tests  /src/tests
COPY agent.py VERSION /src/
RUN python3 -m py_compile phase1/*.py agent.py \
 && python3 tools/check_js.py \
 && python3 -m pytest -q

# ---- runtime: the production image (default target - keep it LAST) ----
FROM deps AS runtime
LABEL org.opencontainers.image.title="cairn" \
      org.opencontainers.image.description="Aggregate ZFS/borg/backupninja backup status, alert (email + Gotify), and trigger on-demand snapshot/replicate/scrub." \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/jmichelsen/cairn"
# Userland tools the adapters shell out to. zfsutils-linux lives in Debian 'contrib' (ZFS licensing), so
# enable it first. It is the ONLY version-sensitive tool: for ZFS reads the container's zfs userland should
# match the host's MAJOR version (2.x today); if yours differs, mount the host binaries over these.
RUN set -eux; \
    if [ -f /etc/apt/sources.list.d/debian.sources ]; then \
        sed -i 's/^Components: main$/Components: main contrib/' /etc/apt/sources.list.d/debian.sources; \
    else \
        sed -i 's/ main$/ main contrib/' /etc/apt/sources.list; \
    fi; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        zfsutils-linux borgbackup msmtp smartmontools sqlite3 curl ca-certificates bash; \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY phase0 /app/phase0
COPY phase1 /app/phase1
COPY agent.py /app/agent.py
COPY VERSION /app/VERSION
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh /app/agent.py /app/phase0/*.sh 2>/dev/null || true

ENV PYTHONUNBUFFERED=1 \
    CAIRN_DB=/data/cairn.db \
    CAIRN_TARGETS=/config/targets.yaml \
    CAIRN_ENV=/config/cairn.env \
    NOTIFY_SH=/app/phase0/notify.sh \
    INTENT_DIR=/run/backup-intents \
    CAIRN_PORT=8929 \
    CAIRN_INTERVAL=900

EXPOSE 8929
VOLUME ["/data"]
ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["api"]
