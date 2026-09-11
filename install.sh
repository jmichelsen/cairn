#!/usr/bin/env bash
# install.sh - single-entry setup for backup-monitor.
#
#   ./install.sh                 # interactive; asks role (home | vault) + a few questions
#   ./install.sh home            # this box = control plane + dashboard + local agent
#   ./install.sh vault [--config vault-install.conf]   # this box = remote reporting agent
#   ./install.sh --check         # preflight only, change nothing
#
# Design: you run ONE command, answer a few questions, and elevate ONCE (a single sudo for the
# borg/backupninja read-access + linger). Everything else - build, config, start - runs as your
# normal user. Re-running is idempotent (existing tokens/config are kept).
#
# HOME can optionally provision a remote VAULT during setup: either it writes a
# vault-install.conf bundle for you to copy, or - if the vault is reachable over SSH - it can
# ssh-copy-id (so home always connects by key) and push+run the vault install for you.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; cd "$HERE"

# prompt source: the controlling terminal if we truly have one, else stdin (so pipes/CI don't error)
if ( : </dev/tty ) 2>/dev/null; then TTY=/dev/tty; else TTY=/dev/stdin; fi

# ---------------- ui ----------------
say()  { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }
info() { printf '   %s\n' "$*"; }
ok()   { printf '   \033[32m✓\033[0m %s\n' "$*"; }
warn() { printf '   \033[33m! %s\033[0m\n' "$*"; }
die()  { printf '\033[31mFATAL: %s\033[0m\n' "$*" >&2; exit 1; }
ask()  { local __v="$1" __p="$2" __d="${3:-}" __a; if [ "$YES" = 1 ]; then printf -v "$__v" '%s' "$__d"; return; fi
         read -r -p "   $__p${__d:+ [$__d]}: " __a <"$TTY" || true; printf -v "$__v" '%s' "${__a:-$__d}"; }
askyn(){ local __p="$1" __d="${2:-y}" __a; if [ "$YES" = 1 ]; then [ "$__d" = y ]; return; fi
         read -r -p "   $__p [$([ "$__d" = y ] && echo Y/n || echo y/N)]: " __a <"$TTY" || true
         __a="${__a:-$__d}"; [[ "$__a" =~ ^[Yy] ]]; }
gen()  { openssl rand -hex 32 2>/dev/null || { head -c32 /dev/urandom | od -An -tx1 | tr -d ' \n'; }; }

# ---------------- packages / prerequisites ----------------
PKG=""  # detected package manager
detect_pkg() { for m in apt-get dnf yum pacman zypper; do command -v "$m" >/dev/null && { PKG="$m"; return; }; done; }
_sudo_primed=0
prime_sudo() { [ "$_sudo_primed" = 1 ] && return; sudo -v || die "sudo required to install packages / grant access"; _sudo_primed=1; }
pkg_install() {  # pkg_install pkg...
  [ $# -gt 0 ] || return 0
  [ -n "$PKG" ] || die "no supported package manager found - install manually: $*"
  prime_sudo
  say "Installing missing packages: $*"
  case "$PKG" in
    apt-get) sudo apt-get update -qq && sudo DEBIAN_FRONTEND=noninteractive apt-get install -y "$@" ;;
    dnf|yum) sudo "$PKG" install -y "$@" ;;
    pacman)  sudo pacman -Sy --noconfirm "$@" ;;
    zypper)  sudo zypper -n install "$@" ;;
  esac || die "package install failed ($PKG install $*)"
}
# cmd->package name differs per distro; we target apt/Debian primarily (as requested) with fallbacks.
pkgname() { case "$1:$PKG" in
    yaml:apt-get) echo python3-yaml;;  yaml:*) echo python3-pyyaml;;
    docker:apt-get) echo docker.io;;   docker:*) echo docker;;
    compose:apt-get) echo docker-compose-v2;; compose:*) echo docker-compose;;
    *) echo "$1";; esac; }
ensure() {  # ensure "check-cmd" pkgkey "human hint" -> installs pkg if the check fails
  local chk="$1" key="$2"; eval "$chk" 2>/dev/null && return 0
  local p; p="$(pkgname "$key")"
  if [ "$YES" = 1 ] || askyn "install missing prerequisite '$p'?" y; then pkg_install "$p"; eval "$chk" 2>/dev/null || die "'$key' still unavailable after installing $p"; else die "prerequisite '$key' missing"; fi
}
# docker CLI access: daemon is root; if this user isn't in the docker group, install-time docker runs
# via sudo (and we add the user to the group for future sudoless use - takes effect next login).
DOCKER_SUDO=0
dc() { if [ "$DOCKER_SUDO" = 1 ]; then sudo docker compose "$@"; else docker compose "$@"; fi; }
ensure_docker_access() {
  docker info >/dev/null 2>&1 && return 0
  sudo -n true 2>/dev/null || prime_sudo
  sudo systemctl enable --now docker 2>/dev/null || true
  if sudo docker info >/dev/null 2>&1; then
    DOCKER_SUDO=1
    getent group docker >/dev/null && ! id -nG "$USER" | tr ' ' '\n' | grep -qx docker \
      && { sudo usermod -aG docker "$USER"; warn "added $USER to the 'docker' group - log out/in for sudoless docker later"; }
  else die "docker installed but the daemon isn't reachable even via sudo - check 'systemctl status docker'"; fi
}

# ---------------- args ----------------
ROLE=""; CONFIG_IN=""; YES=0; SMART_DETAIL=0; CHECK=0; API_URL=""; VAULT_SSH=""
while [ $# -gt 0 ]; do case "$1" in
  home|vault) ROLE="$1";;
  --role) ROLE="$2"; shift;;
  --config) CONFIG_IN="$2"; shift;;
  --api-url) API_URL="$2"; shift;;
  --vault-ssh) VAULT_SSH="$2"; shift;;
  --smart-detail) SMART_DETAIL=1;;
  --yes|-y) YES=1;;
  --check) CHECK=1;;
  -h|--help) sed -n '2,17p' "$0"; exit 0;;
  *) die "unknown arg: $1 (try --help)";;
esac; shift; done
[ -n "$CONFIG_IN" ] && [ -z "$ROLE" ] && ROLE=vault
detect_pkg

# ---------------- self-bootstrap (so `curl … | bash` works without a manual clone) ----------------
# When piped from curl, the repo files aren't beside us - fetch them, then re-exec from the clone.
BM_REPO="${BM_REPO:-https://github.com/jmichelsen/backup-monitor.git}"   # public mirror; GitLab origin is private
BM_DIR="${BM_DIR:-$HOME/backup-monitor}"
if [ ! -f "$HERE/agent.py" ] || [ ! -f "$HERE/docker-compose.yml" ]; then
  say "Bootstrap - fetching backup-monitor ($BM_REPO)"
  ensure "command -v git >/dev/null" git "git"
  if [ -d "$BM_DIR/.git" ]; then info "updating existing $BM_DIR"; git -C "$BM_DIR" pull --ff-only || warn "git pull failed - using what's there";
  else git clone --depth 1 "$BM_REPO" "$BM_DIR" || die "clone failed - is the repo public? for a private repo set BM_REPO to an SSH/token URL"; fi
  ok "fetched to $BM_DIR - continuing there"
  exec bash "$BM_DIR/install.sh" "$@"
fi

# ---------------- preflight (auto-installs missing prerequisites) ----------------
say "Preflight"
[ -n "$PKG" ] && info "package manager: $PKG" || warn "no known package manager - prerequisites must be present already"
if [ -z "$ROLE" ]; then
  info "Which role is THIS machine?"
  info "  home  - control plane + dashboard + local agent (the main server)"
  info "  vault - a remote agent reporting to an existing home (off-site box)"
  ask ROLE "role (home/vault)" home
fi
[ "$ROLE" = home ] || [ "$ROLE" = vault ] || die "role must be 'home' or 'vault'"

ensure "command -v curl >/dev/null"    curl   "curl"
command -v openssl >/dev/null || warn "openssl missing - tokens will use /dev/urandom"
ensure "command -v python3 >/dev/null" python3 "python3"
ensure "python3 -c 'import yaml'"      yaml    "python3 yaml"
if [ "$ROLE" = home ]; then
  ensure "command -v docker >/dev/null"          docker  "docker"
  ensure "docker compose version >/dev/null 2>&1" compose "docker compose plugin"
  command -v rsync >/dev/null || ensure "command -v rsync >/dev/null" rsync "rsync"   # for SSH vault push
  ensure_docker_access
  ok "docker + compose + python/yaml ready"
else
  command -v systemctl >/dev/null || die "systemd needed for the vault agent"
  ok "python/yaml + systemd ready"
fi
[ "$CHECK" = 1 ] && { ok "preflight passed - nothing changed (--check)"; exit 0; }

# ============================================================ HOME ============================================================
install_home() {
  local ENVF="$HERE/config/backup-monitor.env" TGT="$HERE/config/targets.yaml"
  mkdir -p "$HERE/config"

  # ---- config + tokens (idempotent: keep existing, non-placeholder tokens) ----
  if [ -f "$ENVF" ] && grep -q '^BM_ADMIN_TOKEN=' "$ENVF" && ! grep -q 'CHANGEME' "$ENVF"; then
    say "Config exists - keeping the tokens already in config/backup-monitor.env"
  else
    say "Generating config + zero-trust tokens"
    local ADMIN AGENT EMAIL GURL GTOK
    ADMIN="$(gen)"; AGENT="$(gen)"
    ask EMAIL "alert email for WARN/CRIT" "root@localhost"
    GURL=""; GTOK=""
    if askyn "configure a Gotify push for CRIT alerts?" n; then ask GURL "Gotify base URL" ""; ask GTOK "Gotify app token" ""; fi
    cat > "$ENVF" <<EOF
# backup-monitor - generated by install.sh $(date -u +%Y-%m-%dT%H:%M:%SZ)
# Zero-trust tokens (keep secret). Regenerate: openssl rand -hex 32
BM_ADMIN_TOKEN=$ADMIN
BM_AGENT_TOKENS=$AGENT
BM_API_TOKEN=$AGENT

# Alerting
MAIL_MODE=smtp
NOTIFY_EMAIL=$EMAIL
MAIL_FROM=backup-monitor@$(hostname -f 2>/dev/null || hostname)
SMTP_HOST=${SMTP_HOST:-127.0.0.1}
SMTP_PORT=${SMTP_PORT:-25}
SMTP_TLS=off
GOTIFY_URL=$GURL
GOTIFY_TOKEN=$GTOK
GOTIFY_PRIORITY=8

# Behavior
NOTIFY_LOG=/data/backup-monitor.log
STATE_DIR=/data/state
BM_INTERVAL=900
EOF
    chmod 600 "$ENVF"
    ok "wrote $ENVF (admin + agent tokens generated)"
    info "admin token (dashboard login) - save it now:"; printf '     \033[1m%s\033[0m\n' "$ADMIN"
  fi

  # ---- targets ----
  if [ ! -f "$TGT" ]; then
    cp "$HERE/config/targets.example.yaml" "$TGT" 2>/dev/null || die "missing config/targets.example.yaml"
    warn "wrote a STARTER config/targets.yaml from the example - edit it to list YOUR pools/repos"
    askyn "open it in \$EDITOR now?" y && { "${EDITOR:-vi}" "$TGT" <"$TTY" >/dev/tty 2>&1 || true; }
  else ok "targets.yaml present"; fi

  # ---- public URL (for a future vault to reach this home) ----
  [ -z "$API_URL" ] && ask API_URL "public/Tailscale URL a remote vault would use to reach this home (blank = LAN only)" ""

  # ---- control plane ----
  say "Building + starting the control plane (docker compose up -d api)"
  dc up -d --build api
  info "waiting for the API to become healthy…"
  for i in $(seq 1 30); do curl -fs -o /dev/null "http://localhost:8929/login" && { ok "API up at http://localhost:8929"; break; }; sleep 2; done

  # ---- host agent (systemd --user, execute-capable) ----
  say "Installing the local host agent (systemd --user, execute-capable)"
  mkdir -p "$HOME/.config/systemd/user"
  sed "s#%h/backup-monitor#$HERE#g" "$HERE/backup-monitor-agent.service" > "$HOME/.config/systemd/user/backup-monitor-agent.service"
  systemctl --user daemon-reload
  systemctl --user enable backup-monitor-agent.service >/dev/null 2>&1 || true
  ok "unit installed (started after the privileged step below, once group access is granted)"

  # ---- the ONE privileged step ----
  say "One-time privileged setup - a single sudo (borg/backupninja read access + linger)"
  info "grant-access.sh: adds you to the 'backup' group, makes borg segments group-readable"
  info "(borg --umask, no runtime sudo), opens backupninja logs; linger runs the --user agent at boot."
  local sd=""; [ "$SMART_DETAIL" = 1 ] && sd="--smart-detail"
  askyn "also enable the SMART attribute-table detail (installs a scoped smartctl sudo wrapper)?" n && sd="--smart-detail"
  sudo env BM_USER="$USER" bash -c "'$HERE/phase1/grant-access.sh' $sd && loginctl enable-linger '$USER'"
  ok "privileged setup done"

  # ---- start the agent (sg re-reads the new group at exec) ----
  systemctl --user restart backup-monitor-agent.service || warn "agent start failed - check: systemctl --user status backup-monitor-agent"
  sleep 3
  systemctl --user is-active --quiet backup-monitor-agent.service && ok "host agent running" || warn "agent not active yet (a fresh 'backup' group sometimes needs a re-login; the unit's sg wrapper handles it on next start)"

  # ---- optional: provision a remote vault ----
  if askyn "add a remote off-site VAULT now?" n; then provision_vault; fi

  say "HOME setup complete"
  info "Dashboard: http://localhost:8929${API_URL:+  (public: $API_URL)}"
  info "Log in with the admin token shown above (or in config/backup-monitor.env)."
}

provision_vault() {
  local NAME SECRET BUNDLE="$HERE/vault-install.conf"
  ask NAME "a name for the vault agent" "vault"
  [ -z "$API_URL" ] && ask API_URL "URL the vault will use to reach THIS home (e.g. https://backups.example.com or the Tailscale addr)" ""
  [ -z "$API_URL" ] && { warn "no reachable URL for home - skipping vault provisioning (set one and re-run)"; return; }
  say "Minting a per-vault enrollment secret (hash-at-rest; shown once)"
  SECRET="$(dc exec -T api python3 /app/phase1/bmtoken.py mint --role agent --label "$NAME" 2>/dev/null | awk '/^SECRET:/{print $2}')"
  [ -n "$SECRET" ] || { warn "could not mint a token (is a label '$NAME' already used? try another name)"; return; }
  cat > "$BUNDLE" <<EOF
# backup-monitor vault bundle - generated on $(hostname) $(date -u +%Y-%m-%dT%H:%M:%SZ).
# Everything the vault needs to enroll with home. Treat the enrollment secret as a credential.
#   ./install.sh vault --config vault-install.conf
BM_API_URL=$API_URL
BM_AGENT_NAME=$NAME
BM_ENROLL_SECRET=$SECRET
EOF
  chmod 600 "$BUNDLE"; ok "wrote $BUNDLE"

  if askyn "configure the vault now over SSH from here?" n; then
    ask VAULT_SSH "vault ssh target (user@host)" "$VAULT_SSH"
    [ -n "$VAULT_SSH" ] || { warn "no ssh target - bundle is ready to copy manually instead"; return; }
    if askyn "run ssh-copy-id to $VAULT_SSH (so home always connects by key, not password)?" y; then
      ssh-copy-id "$VAULT_SSH" <"$TTY" || warn "ssh-copy-id failed - continuing (key may already be present)"
    fi
    say "Pushing backup-monitor to $VAULT_SSH and running the vault install remotely"
    command -v rsync >/dev/null || die "rsync needed to push to the vault"
    rsync -a --delete --exclude '.git' --exclude 'config/backup-monitor.env' --exclude '*.db*' --exclude 'vault-install.conf' \
      "$HERE/" "$VAULT_SSH:backup-monitor/" || die "rsync to $VAULT_SSH failed"
    scp "$BUNDLE" "$VAULT_SSH:backup-monitor/vault-install.conf" >/dev/null || die "copying the bundle failed"
    ssh -t "$VAULT_SSH" "cd backup-monitor && ./install.sh vault --config vault-install.conf --yes" <"$TTY" \
      && ok "vault provisioned over SSH - it should appear in the Agents card shortly" \
      || warn "remote vault install returned non-zero - check on the vault"
  else
    info "Copy $BUNDLE to the vault, then run there:  ./install.sh vault --config vault-install.conf"
  fi
}

# ============================================================ VAULT ============================================================
install_vault() {
  local ENVF="$HERE/config/backup-monitor.env" TGT="$HERE/config/targets.yaml"
  mkdir -p "$HERE/config"
  [ -n "$CONFIG_IN" ] || ask CONFIG_IN "path to the vault bundle from home (vault-install.conf)" "$HERE/vault-install.conf"
  [ -f "$CONFIG_IN" ] || die "bundle not found: $CONFIG_IN (generate it on home: install.sh home)"
  # shellcheck disable=SC1090
  . "$CONFIG_IN"
  [ -n "${BM_API_URL:-}" ] && [ -n "${BM_ENROLL_SECRET:-}" ] || die "bundle missing BM_API_URL / BM_ENROLL_SECRET"
  local NAME="${BM_AGENT_NAME:-vault}"

  say "Reachability check: $BM_API_URL"
  curl -fs -o /dev/null "${BM_API_URL%/}/login" && ok "home API reachable" || warn "could not reach $BM_API_URL/login yet - will keep retrying once the agent runs"

  if [ ! -f "$ENVF" ] || grep -q 'CHANGEME\|BM_ENROLL_SECRET=$' "$ENVF" 2>/dev/null; then
    say "Writing vault agent config"
    cat > "$ENVF" <<EOF
# backup-monitor vault agent - generated by install.sh $(date -u +%Y-%m-%dT%H:%M:%SZ)
BM_API_URL=$BM_API_URL
BM_AGENT_NAME=$NAME
BM_ENROLL_SECRET=$BM_ENROLL_SECRET
BM_INTERVAL=300
EOF
    chmod 600 "$ENVF"; ok "wrote $ENVF"
  else ok "vault config present"; fi

  if [ ! -f "$TGT" ]; then
    cp "$HERE/config/targets.example.yaml" "$TGT" 2>/dev/null || die "missing config/targets.example.yaml"
    warn "wrote a starter targets.yaml - edit it to list the VAULT's own pool(s)/replica datasets"
    askyn "open it in \$EDITOR now?" y && { "${EDITOR:-vi}" "$TGT" <"$TTY" >/dev/tty 2>&1 || true; }
  fi

  local CAN=0; askyn "should the vault EXECUTE actions (e.g. run its own scrubs)? (default: report-only)" n && CAN=1

  say "Installing the vault agent (systemd --user)"
  mkdir -p "$HOME/.config/systemd/user"
  cat > "$HOME/.config/systemd/user/backup-monitor-agent.service" <<EOF
[Unit]
Description=backup-monitor vault agent (remote, reports to home)
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
Environment=PYTHONUNBUFFERED=1
Environment=BACKUP_MONITOR_ENV=$HERE/config/backup-monitor.env
Environment=BM_TARGETS=$HERE/config/targets.yaml
Environment=BM_CAN_EXECUTE=$CAN
WorkingDirectory=$HERE
ExecStart=/usr/bin/python3 $HERE/agent.py
Restart=on-failure
RestartSec=15
[Install]
WantedBy=default.target
EOF
  systemctl --user daemon-reload
  systemctl --user enable --now backup-monitor-agent.service
  sudo loginctl enable-linger "$USER" 2>/dev/null || warn "couldn't enable linger (run: sudo loginctl enable-linger $USER) - agent won't survive logout without it"
  sleep 3
  systemctl --user is-active --quiet backup-monitor-agent.service && ok "vault agent running → $BM_API_URL" \
    || warn "agent not active - check: systemctl --user status backup-monitor-agent"
  say "VAULT setup complete - it should appear in home's Agents card within a poll interval"
}

case "$ROLE" in
  home)  install_home ;;
  vault) install_vault ;;
esac
