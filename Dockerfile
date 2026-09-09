# backup-monitor - aggregate ZFS/borg/backupninja backup status, alert, and trigger actions.
FROM python:3.12-slim

LABEL org.opencontainers.image.title="backup-monitor" \
      org.opencontainers.image.description="Aggregate ZFS/borg/backupninja backup status, alert (email + Gotify), and trigger on-demand snapshot/replicate/scrub." \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/jmichelsen/backup-monitor"

# Userland tools the adapters shell out to. zfsutils-linux lives in Debian 'contrib' (ZFS
# licensing), so enable it first. It is the ONLY version-sensitive tool: for ZFS reads the
# container's zfs userland should match the host's MAJOR version (2.x today); if yours differs,
# mount the host binaries over these (see docker-compose.yml).
ENV DEBIAN_FRONTEND=noninteractive
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

RUN pip install --no-cache-dir pyyaml "fastapi>=0.110" "uvicorn[standard]>=0.29"

WORKDIR /app
COPY phase0 /app/phase0
COPY phase1 /app/phase1
COPY agent.py /app/agent.py
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh /app/agent.py /app/phase0/*.sh 2>/dev/null || true

ENV BM_DB=/data/backup-monitor.db \
    BM_TARGETS=/config/targets.yaml \
    BACKUP_MONITOR_ENV=/config/backup-monitor.env \
    NOTIFY_SH=/app/phase0/notify.sh \
    INTENT_DIR=/run/backup-intents \
    BM_PORT=8929 \
    BM_INTERVAL=900

EXPOSE 8929
VOLUME ["/data"]
ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["api"]
