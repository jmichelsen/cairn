#!/usr/bin/env bash
# notify.sh SEVERITY "TITLE" "BODY" [DEDUP_KEY]
#   SEVERITY : INFO | WARN | CRIT
#   Routes EMAIL per severity (see "email routing" below); pushes Gotify for CRIT (and WARN if
#   NOTIFY_GOTIFY_WARN=1). DEDUP_KEY (optional) enables per-key cooldown so repeated findings
#   don't spam - this runs BEFORE routing, so a cooled-down finding is neither emailed nor spooled.
#
# notify.sh --flush-digest
#   Send ONE summary email of everything spooled for the daily digest, then clear the spool.
#   (Scheduled by the API's once-daily flush loop; safe to run by hand or from a host timer.)
#
# --- email routing (per severity) -------------------------------------------------------------
#   EMAIL_CRIT / EMAIL_WARN / EMAIL_INFO = immediate | digest | off
#     immediate : email the moment it fires   (defaults: CRIT + WARN)
#     digest    : hold it for the once-daily summary email
#     off       : never email this severity   (default for INFO, unless NOTIFY_INFO_EMAIL=1)
#   Gotify/push is NOT affected by routing - urgent pushes always go out immediately.
#   Back-compat: with none of EMAIL_* set, behavior is identical to before (CRIT+WARN email
#   immediately, INFO emails only when NOTIFY_INFO_EMAIL=1).
#
# Shared primitive - phase0/check_backups.sh and phase1/collector.py/api.py all call this.
set -uo pipefail

ENV_FILE="${CAIRN_ENV:-/etc/cairn/cairn.env}"
[ -r "$ENV_FILE" ] && . "$ENV_FILE"

MAIL_TO="${NOTIFY_EMAIL:-root}"
HOSTN="$(hostname -s 2>/dev/null || echo host)"
LOG="${NOTIFY_LOG:-/var/log/cairn.log}"
STATE_DIR="${STATE_DIR:-/var/lib/cairn}"
SPOOL="$STATE_DIR/digest-spool"
NOW="$(date +%s)"
SEV="${1:-}"   # provisional - real severity (or --flush-digest) resolved below

log() { printf '%s [notify:%s] %s\n' "$(date '+%F %T')" "$SEV" "$*" >>"$LOG" 2>/dev/null; }

# --- shared email transport: _transport SUBJECT BODY  -> emails, returns transport exit status ---
_transport() {
  local subj="$1" body="$2"
  local from="${MAIL_FROM:-cairn@$(hostname -f 2>/dev/null || hostname 2>/dev/null || echo localhost)}"
  local msg
  msg="$(printf 'From: %s\nTo: %s\nSubject: %s\nContent-Type: text/plain; charset=UTF-8\n\n%s\n' \
      "$from" "$MAIL_TO" "$subj" "$body")"
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
      printf '%s' "$msg" | msmtp "${args[@]}" >>"$LOG" 2>&1 ;;
    sendmail)
      # host root path: /usr/sbin/sendmail (msmtp); 'root' resolves via /etc/aliases.
      printf '%s' "$msg" | /usr/sbin/sendmail -t >>"$LOG" 2>&1 ;;
    *) log "unknown MAIL_MODE '${MAIL_MODE}'"; return 2 ;;
  esac
}

send_email() {
  local subj="[cairn:$SEV] $TITLE" body
  body="$(printf '%s - %s\n\n%s\n\n-- cairn @ %s  %s' "$SEV" "$TITLE" "$BODY" "$HOSTN" "$(date '+%F %T %Z')")"
  if _transport "$subj" "$body"; then log "email sent to $MAIL_TO: $TITLE"; else log "EMAIL FAILED: $TITLE"; fi
}

# --- digest spool: hold a notice for the once-daily summary email ---
spool_digest() {
  mkdir -p "$STATE_DIR" 2>/dev/null
  local flatbody="${BODY//$'\n'/ / }"          # keep each notice on ONE tab-delimited line
  printf '%s\t%s\t%s\t%s\n' "$NOW" "$SEV" "$TITLE" "$flatbody" >>"$SPOOL" 2>/dev/null \
    && log "digest-spooled: $TITLE" || log "DIGEST SPOOL FAILED: $TITLE"
}

# --- render the spool into a grouped plaintext body ---
_format_digest() {   # $1 = spool file
  local ts sev title body hhmm line crit="" warn="" info=""
  while IFS=$'\t' read -r ts sev title body; do
    hhmm="$(date -d "@$ts" '+%H:%M' 2>/dev/null || echo '--:--')"
    line="  $hhmm  $title"; [ -n "$body" ] && line="$line - $body"
    case "$sev" in
      CRIT) crit="$crit$line"$'\n' ;;
      WARN) warn="$warn$line"$'\n' ;;
      *)    info="$info$line"$'\n' ;;
    esac
  done <"$1"
  [ -n "$crit" ] && printf 'CRITICAL\n%s\n' "$crit"
  [ -n "$warn" ] && printf 'WARNING\n%s\n' "$warn"
  [ -n "$info" ] && printf 'INFO\n%s\n' "$info"
  printf -- '-- cairn digest @ %s  %s\n' "$HOSTN" "$(date '+%F %T %Z')"
}

# --- flush: compose ONE email from the spool, send, clear (restore on failure) ---
flush_digest() {
  [ -s "$SPOOL" ] || { log "digest flush: spool empty, nothing to send"; return 0; }
  # Atomically claim the spool so notices appended DURING the send land in a fresh spool, not lost.
  local work
  work="$(mktemp "${SPOOL}.XXXXXX" 2>/dev/null)" || { log "digest flush: mktemp failed"; return 1; }
  mv "$SPOOL" "$work" 2>/dev/null || { log "digest flush: could not claim spool"; rm -f "$work"; return 1; }
  local n; n="$(wc -l <"$work" 2>/dev/null | tr -d ' ')"; n="${n:-0}"
  local plural=""; [ "$n" = "1" ] || plural="s"
  local subj="[cairn:digest] $n notice$plural - $HOSTN $(date '+%F')"
  if _transport "$subj" "$(_format_digest "$work")"; then
    log "digest sent: $n notice(s) to $MAIL_TO"; rm -f "$work"; return 0
  fi
  # Send failed - prepend the claimed notices back so nothing is dropped (keep any that arrived since).
  log "DIGEST SEND FAILED - restoring $n spooled notice(s)"
  [ -f "$SPOOL" ] && cat "$SPOOL" >>"$work" 2>/dev/null
  mv "$work" "$SPOOL" 2>/dev/null
  return 1
}

# --- --flush-digest mode (before severity parsing) ---
if [ "$SEV" = "--flush-digest" ] || [ "$SEV" = "--flush" ]; then
  SEV="digest"; flush_digest; exit $?
fi

SEV="${1:?usage: notify.sh SEVERITY TITLE BODY [DEDUP_KEY]  (or --flush-digest)}"
TITLE="${2:?missing title}"
BODY="${3:-}"
KEY="${4:-}"

# --- cooldown: skip if this key was alerted at >= severity within its window ---
if [ -n "$KEY" ]; then
  mkdir -p "$STATE_DIR" 2>/dev/null
  SF="$STATE_DIR/alert-state"
  touch "$SF" 2>/dev/null
  case "$SEV" in CRIT) CD="${COOLDOWN_CRIT:-21600}";; WARN) CD="${COOLDOWN_WARN:-86400}";; *) CD=0;; esac
  # per-call override (e.g. the removable reminder's weekly re-nudge, or 0 for a one-shot confirmation)
  case "${NOTIFY_COOLDOWN:-}" in ''|*[!0-9]*) : ;; *) CD="$NOTIFY_COOLDOWN" ;; esac
  last="$(awk -F'\t' -v k="$KEY" '$1==k{print $2"\t"$3}' "$SF" 2>/dev/null | tail -1)"
  lsev="${last%%$'\t'*}"; lts="${last##*$'\t'}"
  if [ -n "$lts" ] && [ "$lsev" = "$SEV" ] && [ $((NOW - lts)) -lt "$CD" ]; then
    log "cooldown skip key=$KEY ($((NOW-lts))s < ${CD}s)"; exit 0
  fi
  # record (rewrite line for this key)
  tmp="$(mktemp)"; awk -F'\t' -v k="$KEY" '$1!=k' "$SF" 2>/dev/null >"$tmp"
  printf '%s\t%s\t%s\n' "$KEY" "$SEV" "$NOW" >>"$tmp"; mv "$tmp" "$SF" 2>/dev/null
fi

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

# --- resolve the per-severity EMAIL routing policy (immediate | digest | off) ---
# Back-compat default for INFO: immediate when NOTIFY_INFO_EMAIL=1 (the old force-email flag), else off.
_info_default="off"; [ "${NOTIFY_INFO_EMAIL:-0}" = "1" ] && _info_default="immediate"
case "$SEV" in
  CRIT) EMAIL_POLICY="${EMAIL_CRIT:-immediate}" ;;
  WARN) EMAIL_POLICY="${EMAIL_WARN:-immediate}" ;;
  INFO) EMAIL_POLICY="${EMAIL_INFO:-$_info_default}" ;;
esac

route_email() {
  case "$EMAIL_POLICY" in
    immediate) send_email ;;
    digest)    spool_digest ;;
    off|*)     log "email off for $SEV: $TITLE" ;;
  esac
}

case "$SEV" in
  CRIT) route_email; push_gotify ;;
  WARN) route_email; { [ "${NOTIFY_GOTIFY_WARN:-0}" = "1" ] || [ "${NOTIFY_FORCE_GOTIFY:-0}" = "1" ]; } && push_gotify ;;
  INFO) route_email; [ "${NOTIFY_FORCE_GOTIFY:-0}" = "1" ] && push_gotify ;;
  *)    log "unknown severity '$SEV'"; exit 2 ;;
esac
exit 0
