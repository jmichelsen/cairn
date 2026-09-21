#!/usr/bin/env bash
# notify.sh SEVERITY "TITLE" "BODY" [DEDUP_KEY]
#   SEVERITY : INFO | WARN | CRIT
#   Sends email for WARN/CRIT (and INFO if NOTIFY_INFO_EMAIL=1) via /usr/sbin/sendmail (msmtp).
#   Pushes Gotify for CRIT (and WARN if NOTIFY_GOTIFY_WARN=1).
#   DEDUP_KEY (optional): enables per-key cooldown so repeated findings don't spam.
#
# Shared primitive - phase0/check_backups.sh and phase1/collector.py both call this.
set -uo pipefail

ENV_FILE="${CAIRN_ENV:-/etc/cairn/cairn.env}"
[ -r "$ENV_FILE" ] && . "$ENV_FILE"

SEV="${1:?usage: notify.sh SEVERITY TITLE BODY [DEDUP_KEY]}"
TITLE="${2:?missing title}"
BODY="${3:-}"
KEY="${4:-}"

MAIL_TO="${NOTIFY_EMAIL:-root}"
HOSTN="$(hostname -s 2>/dev/null || echo host)"
LOG="${NOTIFY_LOG:-/var/log/cairn.log}"
STATE_DIR="${STATE_DIR:-/var/lib/cairn}"
NOW="$(date +%s)"

log() { printf '%s [notify:%s] %s\n' "$(date '+%F %T')" "$SEV" "$*" >>"$LOG" 2>/dev/null; }

# --- cooldown: skip if this key was alerted at >= severity within its window ---
if [ -n "$KEY" ]; then
  mkdir -p "$STATE_DIR" 2>/dev/null
  SF="$STATE_DIR/alert-state"
  touch "$SF" 2>/dev/null
  case "$SEV" in CRIT) CD="${COOLDOWN_CRIT:-21600}";; WARN) CD="${COOLDOWN_WARN:-86400}";; *) CD=0;; esac
  last="$(awk -F'\t' -v k="$KEY" '$1==k{print $2"\t"$3}' "$SF" 2>/dev/null | tail -1)"
  lsev="${last%%$'\t'*}"; lts="${last##*$'\t'}"
  if [ -n "$lts" ] && [ "$lsev" = "$SEV" ] && [ $((NOW - lts)) -lt "$CD" ]; then
    log "cooldown skip key=$KEY ($((NOW-lts))s < ${CD}s)"; exit 0
  fi
  # record (rewrite line for this key)
  tmp="$(mktemp)"; awk -F'\t' -v k="$KEY" '$1!=k' "$SF" 2>/dev/null >"$tmp"
  printf '%s\t%s\t%s\n' "$KEY" "$SEV" "$NOW" >>"$tmp"; mv "$tmp" "$SF" 2>/dev/null
fi

send_email() {
  local subj="[cairn:$SEV] $TITLE"
  local from="${MAIL_FROM:-cairn@$(hostname -f 2>/dev/null || hostname 2>/dev/null || echo localhost)}"
  local msg
  msg="$(printf 'From: %s\nTo: %s\nSubject: %s\nContent-Type: text/plain; charset=UTF-8\n\n%s - %s\n\n%s\n\n-- cairn @ %s  %s\n' \
      "$from" "$MAIL_TO" "$subj" "$SEV" "$TITLE" "$BODY" "$HOSTN" "$(date '+%F %T %Z')")"
  case "${MAIL_MODE:-smtp}" in
    smtp|relay)
      # Generic SMTP via msmtp (portable - works for a local unauth relay OR an authed provider).
      # Config from env: SMTP_HOST/PORT, SMTP_TLS(on/off), SMTP_STARTTLS(on/off), SMTP_USER/PASS.
      # No SMTP_USER => no auth (relay). No SMTP_TLS=on => plaintext (local relay). MSMTPD_* are
      # honored as fallbacks for back-compat.
      local args=( --from="$from" -t
                   --host="${SMTP_HOST:-${MSMTPD_HOST:-127.0.0.1}}"
                   --port="${SMTP_PORT:-${MSMTPD_PORT:-2500}}" )
      if [ "${SMTP_TLS:-off}" = on ]; then
        args+=( --tls=on --tls-starttls="${SMTP_STARTTLS:-on}" )
      else
        args+=( --tls=off )
      fi
      if [ -n "${SMTP_USER:-}" ]; then
        export SMTP_PASS                                   # so --passwordeval's shell can read it
        args+=( --auth="${SMTP_AUTH:-on}" --user="$SMTP_USER" --passwordeval='printf "%s" "$SMTP_PASS"' )
      else
        args+=( --auth=off )
      fi
      printf '%s' "$msg" | msmtp "${args[@]}" >>"$LOG" 2>&1 \
        && log "email sent to $MAIL_TO: $TITLE" || log "SMTP EMAIL FAILED: $TITLE" ;;
    sendmail)
      # host root path: /usr/sbin/sendmail (msmtp); 'root' resolves via /etc/aliases.
      printf '%s' "$msg" | /usr/sbin/sendmail -t >>"$LOG" 2>&1 \
        && log "email sent (sendmail) to $MAIL_TO: $TITLE" || log "SENDMAIL FAILED: $TITLE" ;;
    *) log "unknown MAIL_MODE '${MAIL_MODE}'" ;;
  esac
}

push_gotify() {
  [ -n "${GOTIFY_URL:-}" ] && [ -n "${GOTIFY_TOKEN:-}" ] && [ "${GOTIFY_TOKEN:-}" != "CHANGEME_app_token" ] || { log "gotify not configured, skip push"; return 0; }
  local prio="${GOTIFY_PRIORITY:-8}" code
  # curl exits 0 for ANY completed request incl 4xx/5xx (no --fail), so we MUST inspect the HTTP
  # status - otherwise a bad/expired token (401) or wrong app (404) gets logged as "pushed" and the
  # push silently never arrives. Capture the code and only treat 2xx as success.
  code=$(curl -s -m 8 -o /dev/null -w '%{http_code}' \
    -H "X-Gotify-Key: ${GOTIFY_TOKEN}" \
    -F "title=[$SEV] $TITLE" \
    -F "message=$BODY" \
    -F "priority=$prio" \
    "${GOTIFY_URL%/}/message" 2>>"$LOG")
  case "$code" in
    2??) log "gotify pushed: $TITLE" ;;
    401|403) log "GOTIFY PUSH FAILED (HTTP $code - bad/expired app token): $TITLE" ;;
    *)   log "GOTIFY PUSH FAILED (HTTP ${code:-000}): $TITLE" ;;
  esac
}

case "$SEV" in
  CRIT) send_email; push_gotify ;;
  WARN) send_email; [ "${NOTIFY_GOTIFY_WARN:-0}" = "1" ] && push_gotify ;;
  INFO) [ "${NOTIFY_INFO_EMAIL:-0}" = "1" ] && send_email ;;
  *)    log "unknown severity '$SEV'"; exit 2 ;;
esac
exit 0
