#!/usr/bin/env bash
# install.sh - single-entry setup for Cairn (backup monitor).
#
#   ./install.sh                 # interactive; asks role (home | vault) + a few questions
#   ./install.sh home            # this box = control plane + dashboard + local agent
#   ./install.sh vault [--config vault-install.conf]   # this box = remote reporting agent
#   ./install.sh home --add-vault  # add a remote vault to an ALREADY-set-up home (skips home setup)
#   ./install.sh home --replication [--vault-ssh user@host]  # set up the nightly vault-pull replication
#   ./install.sh home --configure  # re-run config on an existing install (DESTRUCTIVE: regenerates tokens)
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
# normalize a URL the user typed: add https:// if no scheme, strip a trailing slash. Blank stays blank.
# (urllib in the agent REQUIRES a scheme, so a bare `host.example.com` would otherwise break it.)
normurl(){ local u="${1:-}"; [ -z "$u" ] && { printf ''; return; }
           case "$u" in http://*|https://*) ;; *) u="https://$u";; esac; printf '%s' "${u%/}"; }

# ---------------- packages / prerequisites ----------------
PKG=""  # detected package manager
detect_pkg() { for m in apt-get dnf yum pacman zypper; do command -v "$m" >/dev/null && { PKG="$m"; return; }; done; }
_sudo_primed=0
prime_sudo() { [ "$_sudo_primed" = 1 ] && return; sudo -v || die "sudo required to install packages / grant access"; _sudo_primed=1; }
_pkg_do() {  # run the package manager for "$@"; return its exit status (never dies)
  case "$PKG" in
    apt-get) sudo apt-get update -qq && sudo DEBIAN_FRONTEND=noninteractive apt-get install -y "$@" ;;
    dnf|yum) sudo "$PKG" install -y "$@" ;;
    pacman)  sudo pacman -Sy --noconfirm "$@" ;;
    zypper)  sudo zypper -n install "$@" ;;
    *) return 127 ;;
  esac
}
pkg_install() {  # required package(s): die on failure
  [ $# -gt 0 ] || return 0
  [ -n "$PKG" ] || die "no supported package manager found - install manually: $*"
  prime_sudo
  say "Installing missing packages: $*"
  _pkg_do "$@" || die "package install failed ($PKG install $*)"
}
# cmd->package name differs per distro; we target apt/Debian primarily (as requested) with fallbacks.
pkgname() { case "$1:$PKG" in
    yaml:apt-get) echo python3-yaml;;  yaml:*) echo python3-pyyaml;;
    docker:apt-get) echo docker.io;;   docker:*) echo docker;;
    compose:apt-get) echo docker-compose-v2;; compose:*) echo docker-compose;;
    syncoid:*) echo sanoid;;            # the sanoid package ships both sanoid + syncoid
    borg:*) echo borgbackup;;           # command is `borg`, package is borgbackup
    *) echo "$1";; esac; }
ensure() {  # ensure "check-cmd" pkgkey "human hint" -> installs pkg if the check fails
  local chk="$1" key="$2"; eval "$chk" 2>/dev/null && return 0
  local p; p="$(pkgname "$key")"
  if [ "$YES" = 1 ] || askyn "install missing prerequisite '$p'?" y; then pkg_install "$p"; eval "$chk" 2>/dev/null || die "'$key' still unavailable after installing $p"; else die "prerequisite '$key' missing"; fi
}
ensure_opt() {  # optional tool: offer to install, but WARN (never die) if missing/declined/failed -
  # cairn just reports nothing for a backup tool this host doesn't have.
  local chk="$1" key="$2" why="$3"; eval "$chk" 2>/dev/null && { ok "$key ready"; return 0; }
  local p; p="$(pkgname "$key")"
  if [ -z "$PKG" ]; then warn "no package manager - install '$key' manually ($why)"; return 0; fi
  # "optional" means install what THIS host actually uses. A non-interactive run (--yes, e.g. an
  # update) must NOT pull every backup tool onto a host that doesn't use it, so default a MISSING
  # optional tool to NO there. Tools already present are handled above and are unaffected. To add one
  # non-interactively, install it first (then it shows "ready") or run the installer interactively.
  if [ "$YES" = 1 ]; then warn "skipped '$key' (not installed; --yes adds no optional tools) - $why"; return 0; fi
  if askyn "install '$p'? (enables: $why)" y; then
    if prime_sudo && _pkg_do "$p" && eval "$chk" 2>/dev/null; then ok "$key ready"; else
      warn "'$key' not installed - $why unavailable until it is present"; fi
  else warn "skipped '$key' - $why unavailable until installed"; fi
}
ensure_httm() {  # httm is NOT in a distro repo (Rust tool), but its GitHub releases ship a .deb/.rpm.
  command -v httm >/dev/null 2>&1 && { ok "httm ready"; return 0; }
  # Pick the package type this distro+arch can install directly (releases are x86_64/amd64 only).
  local ext="" arch; arch="$(uname -m)"
  if [ "$arch" = x86_64 ] || [ "$arch" = amd64 ]; then
    case "$PKG" in apt-get) ext=.deb;; dnf|yum|zypper) ext=.rpm;; esac
  fi
  # httm is optional: a non-interactive run (--yes) does not add it (see ensure_opt rationale).
  if [ -n "$ext" ] && [ "$YES" != 1 ] && command -v curl >/dev/null 2>&1 \
     && askyn "install httm (recovery-point catalog) from its GitHub releases?" y; then
    local api url tmpd rc=1
    api="$(curl -fsSL -H 'Accept: application/vnd.github+json' -A cairn-install \
           https://api.github.com/repos/kimono-koans/httm/releases/latest 2>/dev/null)"
    url="$(printf '%s' "$api" | python3 -c "import sys,json
ext=sys.argv[1]; d=json.load(sys.stdin)
c=[a['browser_download_url'] for a in d.get('assets',[])
   if a['name'].endswith(ext) and ('amd64' in a['name'] or 'x86_64' in a['name'])]
print(c[0] if c else '')" "$ext" 2>/dev/null)"
    if [ -n "$url" ]; then
      tmpd="$(mktemp -d)"; local f="$tmpd/httm$ext"
      if curl -fsSL -o "$f" "$url"; then
        say "installing httm from $(basename "$url")"
        case "$ext" in
          .deb) sudo dpkg -i "$f" >/dev/null 2>&1 || sudo apt-get -f install -y >/dev/null 2>&1 || true ;;
          .rpm) sudo "$PKG" install -y "$f" >/dev/null 2>&1 || sudo rpm -i "$f" >/dev/null 2>&1 || true ;;
        esac
      fi
      rm -rf "$tmpd"
    fi
    command -v httm >/dev/null 2>&1 && { ok "httm installed ($(httm --version 2>/dev/null | head -1))"; return 0; }
    warn "httm auto-install did not complete (network/permissions?) - falling back to manual"
  fi
  warn "httm not found - the recovery-point catalog (points / deleted-file / version search) needs it"
  info "install a .deb/.rpm from https://github.com/kimono-koans/httm/releases, or 'cargo install httm'"
}
# docker CLI access: daemon is root; if this user isn't in the docker group, install-time docker runs
# via sudo (and we add the user to the group for future sudoless use - takes effect next login).
DOCKER_SUDO=0
dc()  { if [ "$DOCKER_SUDO" = 1 ]; then sudo docker compose "$@"; else docker compose "$@"; fi; }
dps() { if [ "$DOCKER_SUDO" = 1 ]; then sudo docker ps "$@"; else docker ps "$@"; fi; }
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
ROLE=""; CONFIG_IN=""; YES=0; SMART_DETAIL=0; CHECK=0; API_URL=""; VAULT_SSH=""; ADD_VAULT=0; RECONFIGURE=0; REPLICATION=0; UPDATE=0
while [ $# -gt 0 ]; do case "$1" in
  home|vault) ROLE="$1";;
  --role) ROLE="$2"; shift;;
  --config) CONFIG_IN="$2"; shift;;
  --api-url) API_URL="$2"; shift;;
  --vault-ssh) VAULT_SSH="$2"; shift;;
  --add-vault) ADD_VAULT=1;;
  --replication) REPLICATION=1;;
  --configure|--reconfigure) RECONFIGURE=1;;
  --smart-detail) SMART_DETAIL=1;;
  --update) UPDATE=1; YES=1;;   # non-interactive code refresh: keep every existing setting, restart
  --yes|-y) YES=1;;
  --check) CHECK=1;;
  -h|--help) sed -n '2,20p' "$0"; exit 0;;
  *) die "unknown arg: $1 (try --help)";;
esac; shift; done
[ -n "$CONFIG_IN" ] && [ -z "$ROLE" ] && ROLE=vault
{ [ "$ADD_VAULT" = 1 ] || [ "$RECONFIGURE" = 1 ] || [ "$REPLICATION" = 1 ]; } && [ -z "$ROLE" ] && ROLE=home
detect_pkg

# ---------------- update: a fast, role-agnostic path that skips preflight entirely ----------------
self_update_code() {
  # Refresh the code in $HERE, NEVER touching config/ (user settings). git pull for a checkout, else a
  # GitHub tarball for an rsync-provisioned copy (e.g. a vault). Best-effort: warn, never die.
  local url="${CAIRN_REPO_URL:-https://github.com/jmichelsen/cairn}"
  if [ -d "$HERE/.git" ]; then
    say "Updating code (git) in $HERE"
    if git -C "$HERE" pull --ff-only >/dev/null 2>&1; then
      ok "code updated to $(git -C "$HERE" rev-parse --short HEAD 2>/dev/null)"
    else warn "git pull --ff-only failed (local changes or diverged) - code NOT updated; resolve by hand"; fi
  else
    say "Updating code (tarball) from $url"
    command -v curl >/dev/null 2>&1 || { warn "curl missing - cannot fetch update"; return 0; }
    local tb; tb="$(mktemp -d)"
    if curl -fsSL "$url/archive/refs/heads/main.tar.gz" -o "$tb/c.tgz" \
       && tar -xzf "$tb/c.tgz" -C "$HERE" --strip-components=1 --exclude='*/config'; then
      ok "code updated from tarball (config preserved)"
    else warn "couldn't fetch/apply $url tarball - code NOT updated"; fi
    rm -rf "$tb"
  fi
  # Ensure the executable bit on scripts systemd/ssh invoke DIRECTLY (a tarball carries git's mode, so
  # a script committed 0644 would land non-runnable and e.g. cairn-pull.service would fail to exec it).
  chmod +x "$HERE"/install.sh "$HERE"/agent.py "$HERE"/entrypoint.sh 2>/dev/null || true
  chmod +x "$HERE"/replication/*.sh "$HERE"/phase1/*.sh "$HERE"/phase1/*.py "$HERE"/phase0/*.sh 2>/dev/null || true
}
update_agent() {
  # Fetch new code, keep the EXISTING unit + config exactly as-is (every setting preserved), restart.
  local unit="$HOME/.config/systemd/user/cairn-agent.service"
  [ -f "$unit" ] || die "no agent unit at $unit - run a full install first (this flag only updates an existing agent)"
  local was; was="$(cat "$HERE/VERSION" 2>/dev/null || echo '?')"
  self_update_code
  systemctl --user daemon-reload
  systemctl --user restart cairn-agent.service
  sleep 3
  if systemctl --user is-active --quiet cairn-agent.service; then
    ok "agent updated ${was} -> $(cat "$HERE/VERSION" 2>/dev/null || echo '?') and restarted"
  else warn "agent not active after update - check: systemctl --user status cairn-agent"; fi
}
[ "$UPDATE" = 1 ] && { update_agent; exit 0; }

# ---------------- self-bootstrap (so `curl … | bash` works without a manual clone) ----------------
# When piped from curl, the repo files aren't beside us - fetch them, then re-exec from the clone.
CAIRN_REPO="${CAIRN_REPO:-https://github.com/jmichelsen/cairn.git}"   # public mirror; GitLab origin is private
CAIRN_DIR="${CAIRN_DIR:-$HOME/cairn}"
if [ ! -f "$HERE/agent.py" ] || [ ! -f "$HERE/docker-compose.yml" ]; then
  say "Bootstrap - fetching Cairn ($CAIRN_REPO)"
  ensure "command -v git >/dev/null" git "git"
  if [ -d "$CAIRN_DIR/.git" ]; then info "updating existing $CAIRN_DIR"; git -C "$CAIRN_DIR" pull --ff-only || warn "git pull failed - using what's there";
  else git clone --depth 1 "$CAIRN_REPO" "$CAIRN_DIR" || die "clone failed - is the repo public? for a private repo set CAIRN_REPO to an SSH/token URL"; fi
  ok "fetched to $CAIRN_DIR - continuing there"
  exec bash "$CAIRN_DIR/install.sh" "$@"
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
  ensure_docker_access
  ok "docker + compose ready"
else
  command -v systemctl >/dev/null || die "systemd needed for the vault agent"
  ok "python/yaml + systemd ready"
fi

# Backup toolchain (optional): cairn monitors and drives these; a host missing one just reports nothing
# for it, so these are best-effort (offer to install, never block). rsync/syncoid/httm apply to any
# host; borg + backupninja are for the main backup host.
say "Backup toolchain (optional - install what THIS host uses)"
ensure_opt "command -v rsync >/dev/null"   rsync   "file transfers, restores, and vault seeding"
ensure_opt "command -v syncoid >/dev/null" syncoid "ZFS snapshot replication (sanoid + syncoid)"
ensure_opt "command -v restic >/dev/null"  restic  "restic repository monitoring"
ensure_opt "command -v rclone >/dev/null"  rclone  "rclone remote (off-site sync) monitoring"
if [ "$ROLE" = home ]; then
  ensure_opt "command -v borg >/dev/null"        borg        "borg repository monitoring"
  ensure_opt "command -v backupninja >/dev/null" backupninja "backupninja handler monitoring"
  ensure_opt "command -v snapper >/dev/null"     snapper     "snapper (btrfs) snapshot monitoring"
fi
ensure_httm
[ "$CHECK" = 1 ] && { ok "preflight passed - nothing changed (--check)"; exit 0; }

# ---------------- existing-install summary (shown on idempotent + --configure runs) ----------------
show_existing_config() {
  local f="$HERE/config/cairn.env" u="$HOME/.config/systemd/user/cairn-agent.service"
  info "current settings (kept as-is):"
  if [ -f "$f" ]; then
    info "  alert email  : $(grep -m1 '^NOTIFY_EMAIL=' "$f" | cut -d= -f2-)"
    info "  SMTP         : $(grep -m1 '^SMTP_HOST=' "$f" | cut -d= -f2-):$(grep -m1 '^SMTP_PORT=' "$f" | cut -d= -f2-)"
    local g; g="$(grep -m1 '^GOTIFY_URL=' "$f" | cut -d= -f2-)"; info "  Gotify       : ${g:-(none)}"
    info "  poll interval: $(grep -m1 '^CAIRN_INTERVAL=' "$f" | cut -d= -f2-)s"
    grep -q '^CAIRN_ADMIN_TOKEN=' "$f" && info "  admin token  : (set - see config/cairn.env)"
  fi
  [ -f "$HERE/config/targets.yaml" ] && info "  targets      : config/targets.yaml"
  [ -f "$u" ] && info "  local agent  : $(grep -m1 '^Environment=CAIRN_API_URL=' "$u" | cut -d= -f3-)"
  local c; c="$(dps --format '{{.Names}} {{.Status}}' 2>/dev/null | grep -iE '^cairn' | head -1)"
  [ -n "$c" ] && info "  api container: $c"
}

# ============================================================ HOME ============================================================
install_home() {
  local ENVF="$HERE/config/cairn.env" TGT="$HERE/config/targets.yaml"
  mkdir -p "$HERE/config"

  # ---- config + tokens (idempotent by default; --configure regenerates, destructively) ----
  local NEED_CONFIG=0
  if [ ! -f "$ENVF" ] || ! grep -q '^CAIRN_ADMIN_TOKEN=' "$ENVF" || grep -q 'CHANGEME' "$ENVF"; then
    NEED_CONFIG=1
  elif [ "$RECONFIGURE" = 1 ]; then
    say "Detected an existing install"; show_existing_config
    warn "--configure REGENERATES config + tokens. This is DESTRUCTIVE:"
    warn "  - a NEW admin login token (the current dashboard login stops working)"
    warn "  - NEW agent tokens (every existing agent must be re-tokened / re-enrolled)"
    askyn "overwrite config/cairn.env with fresh settings + tokens?" n && NEED_CONFIG=1 || info "keeping existing config"
  else
    say "Detected an existing install - keeping it (idempotent)"; show_existing_config
    info "to CHANGE settings (regenerates tokens - destructive): ./install.sh home --configure"
  fi
  if [ "$NEED_CONFIG" = 1 ]; then
    say "Generating config + zero-trust tokens"
    local ADMIN AGENT EMAIL GURL GTOK
    ADMIN="$(gen)"; AGENT="$(gen)"
    ask EMAIL "alert email for WARN/CRIT" "root@localhost"
    GURL=""; GTOK=""
    if askyn "configure a Gotify push for CRIT alerts?" n; then ask GURL "Gotify base URL" ""; ask GTOK "Gotify app token" ""; fi
    cat > "$ENVF" <<EOF
# cairn - generated by install.sh $(date -u +%Y-%m-%dT%H:%M:%SZ)
# Zero-trust tokens (keep secret). Regenerate: openssl rand -hex 32
CAIRN_ADMIN_TOKEN=$ADMIN
CAIRN_AGENT_TOKENS=$AGENT
CAIRN_API_TOKEN=$AGENT

# Alerting
MAIL_MODE=smtp
NOTIFY_EMAIL=$EMAIL
MAIL_FROM=cairn@$(hostname -f 2>/dev/null || hostname)
SMTP_HOST=${SMTP_HOST:-127.0.0.1}
SMTP_PORT=${SMTP_PORT:-25}
SMTP_TLS=off
GOTIFY_URL=$GURL
GOTIFY_TOKEN=$GTOK
GOTIFY_PRIORITY=8

# Behavior
NOTIFY_LOG=/data/cairn.log
STATE_DIR=/data/state
CAIRN_INTERVAL=900
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
  elif [ "$RECONFIGURE" = 1 ] && askyn "re-edit config/targets.yaml?" n; then
    "${EDITOR:-vi}" "$TGT" <"$TTY" >/dev/tty 2>&1 || true
  else ok "targets.yaml present"; fi

  # ---- public URL (for a future vault to reach this home) ----
  if [ -z "$API_URL" ]; then
    info "A remote vault reaches this home over the network. What URL should it use?"
    info "  example:  https://cairn.example.com    (scheme optional - https is assumed if you omit it)"
    info "  blank  =  LAN only: the vault must share this LAN and will use  http://<this-host-ip>:8929"
    ask API_URL "URL a vault uses to reach this home (blank = LAN only)" ""
  fi
  API_URL="$(normurl "$API_URL")"

  # ---- control plane (idempotent: never clobber an api container managed elsewhere, e.g. CI/proxy) ----
  local API_LOCAL_OK=0
  if dps --format '{{.Names}}' | grep -qxE 'cairn|cairn-api-1'; then
    ok "an api container is already running - leaving it as-is (not rebuilding)"
    info "if you deploy the api another way (CI / a custom compose behind a proxy), this respects it."
    info "to force a rebuild from THIS compose: docker compose up -d --build api"
  else
    say "Building + starting the control plane (docker compose up -d api)"
    dc up -d --build api
  fi
  info "checking the API on http://localhost:8929 …"
  for i in $(seq 1 20); do curl -fs -o /dev/null "http://localhost:8929/login" && { API_LOCAL_OK=1; break; }; sleep 2; done
  [ "$API_LOCAL_OK" = 1 ] && ok "API reachable at http://localhost:8929" \
    || info "nothing on http://localhost:8929 (normal if the api has no host port / is fronted by a proxy)"

  # ---- host agent (systemd --user, execute-capable); idempotent - keep an existing unit's settings ----
  say "Installing the local host agent (systemd --user, execute-capable)"
  mkdir -p "$HOME/.config/systemd/user"
  if [ -f "$HOME/.config/systemd/user/cairn-agent.service" ]; then
    ok "agent unit already present - keeping it (edit it to change CAIRN_API_URL / interval)"
  else
    sed "s#%h/cairn#$HERE#g" "$HERE/cairn-agent.service" > "$HOME/.config/systemd/user/cairn-agent.service"
    ok "agent unit installed"
  fi
  systemctl --user daemon-reload
  systemctl --user enable cairn-agent.service >/dev/null 2>&1 || true

  # ---- the ONE privileged step ----
  say "One-time privileged setup - a single sudo (borg/backupninja read access + linger)"
  info "grant-access.sh: adds you to the 'backup' group, makes borg segments group-readable"
  info "(borg --umask, no runtime sudo), opens backupninja logs; linger runs the --user agent at boot."
  local sd=""; [ "$SMART_DETAIL" = 1 ] && sd="--smart-detail"
  askyn "also enable the SMART attribute-table detail (installs a scoped smartctl sudo wrapper)?" n && sd="--smart-detail"
  sudo env CAIRN_USER="$USER" bash -c "'$HERE/phase1/grant-access.sh' $sd && loginctl enable-linger '$USER'"
  ok "privileged setup done"

  # ---- SMART attribute-table detail: grant-access installs the scoped wrapper but only the agent's
  #      CAIRN_SMART_DETAIL flag turns detail ON. Set it in the unit whenever the wrapper is present, so
  #      the attribute table survives a unit regeneration (e.g. a rename) instead of silently reverting
  #      to sudoless scan-only. ----
  local unit="$HOME/.config/systemd/user/cairn-agent.service"
  if { [ -n "$sd" ] || [ -x /opt/cairn/phase1/smart-probe.sh ]; } \
     && ! grep -q '^Environment=CAIRN_SMART_DETAIL=' "$unit" 2>/dev/null; then
    sed -i '/^Environment=CAIRN_DRYRUN=/a Environment=CAIRN_SMART_DETAIL=1' "$unit"
    systemctl --user daemon-reload
    ok "SMART attribute-table detail enabled on the agent (CAIRN_SMART_DETAIL=1)"
  fi

  # ---- start the agent (sg re-reads the new group at exec) ----
  systemctl --user restart cairn-agent.service || warn "agent start failed - check: systemctl --user status cairn-agent"
  sleep 3
  systemctl --user is-active --quiet cairn-agent.service && ok "host agent running" || warn "agent not active yet (a fresh 'backup' group sometimes needs a re-login; the unit's sg wrapper handles it on next start)"

  # ---- optional: provision a remote vault ----
  if askyn "add a remote off-site VAULT now?" n; then provision_vault; fi

  say "HOME setup complete"
  if [ "$API_LOCAL_OK" = 1 ]; then
    info "Dashboard: http://localhost:8929${API_URL:+  (off-box: $API_URL)}"
  elif [ -n "$API_URL" ]; then
    info "Dashboard: $API_URL  (this host publishes no local :8929 port; served via your proxy)"
  else
    warn "the API isn't on http://localhost:8929 and no public URL was set - if a proxy fronts it, browse that URL"
  fi
  local admin_tok; admin_tok="$(grep -m1 '^CAIRN_ADMIN_TOKEN=' "$ENVF" | cut -d= -f2-)"
  if [ -n "$admin_tok" ]; then
    info "Log in with this admin token:"; printf '     \033[1m%s\033[0m\n' "$admin_tok"
  else
    warn "couldn't read CAIRN_ADMIN_TOKEN from $ENVF - check that file for your login token"
  fi
}

provision_vault() {
  local NAME SECRET BUNDLE="$HERE/vault-install.conf"
  ask NAME "a name for the vault agent" "vault"
  [ -z "$API_URL" ] && ask API_URL "URL the vault uses to reach THIS home (e.g. https://cairn.example.com; https assumed if no scheme)" ""
  API_URL="$(normurl "$API_URL")"
  [ -z "$API_URL" ] && { warn "no reachable URL for home - skipping vault provisioning (set one and re-run)"; return; }
  say "Minting a per-vault enrollment secret (hash-at-rest; shown once)"
  SECRET="$(dc exec -T api python3 /app/phase1/cairn-token.py mint --role agent --label "$NAME" 2>/dev/null | awk '/^SECRET:/{print $2}')"
  [ -n "$SECRET" ] || { warn "could not mint a token (is a label '$NAME' already used? try another name)"; return; }
  cat > "$BUNDLE" <<EOF
# cairn vault bundle - generated on $(hostname) $(date -u +%Y-%m-%dT%H:%M:%SZ).
# Everything the vault needs to enroll with home. Treat the enrollment secret as a credential.
#   ./install.sh vault --config vault-install.conf
CAIRN_API_URL=$API_URL
CAIRN_AGENT_NAME=$NAME
CAIRN_ENROLL_SECRET=$SECRET
EOF
  chmod 600 "$BUNDLE"; ok "wrote $BUNDLE"

  if askyn "configure the vault now over SSH from here?" n; then
    ask VAULT_SSH "vault ssh target (user@host)" "$VAULT_SSH"
    [ -n "$VAULT_SSH" ] || { warn "no ssh target - bundle is ready to copy manually instead"; return; }
    # Test key auth FIRST; only offer ssh-copy-id if we actually need it (don't ship a key blindly).
    if ssh -o BatchMode=yes -o ConnectTimeout=6 -o StrictHostKeyChecking=accept-new "$VAULT_SSH" true 2>/dev/null; then
      ok "SSH key auth to $VAULT_SSH already works"
    else
      warn "SSH key auth to $VAULT_SSH isn't working yet"
      if askyn "run ssh-copy-id (enter the vault password once, then home connects by key)?" y; then
        ssh-copy-id "$VAULT_SSH" <"$TTY" || warn "ssh-copy-id failed"
      fi
      # Confirm the vault is actually reachable before pushing anything.
      if ssh -o BatchMode=yes -o ConnectTimeout=6 "$VAULT_SSH" true 2>/dev/null; then
        ok "reachable at $VAULT_SSH (key auth)"
      elif ssh -o ConnectTimeout=6 "$VAULT_SSH" true <"$TTY" 2>/dev/null; then
        warn "reachable at $VAULT_SSH, but only with a password - each SSH step below will prompt you"
      else
        warn "cannot reach $VAULT_SSH over SSH - fix access, or copy $BUNDLE to the vault manually"; return
      fi
    fi
    say "Pushing cairn to $VAULT_SSH"
    command -v rsync >/dev/null || die "rsync needed to push to the vault"
    # Exclude HOST-SPECIFIC config so the vault gets its OWN: cairn.env (tokens) AND targets.yaml
    # (the vault must monitor ITS pools/replicas, not home's - a copied home targets.yaml makes the
    # vault report home's fleet as UNKNOWN). The *.example.yaml files are still copied so the vault
    # can seed a starter targets.yaml.
    rsync -a --delete --exclude '.git' --exclude 'config/cairn.env' --exclude 'config/targets.yaml' \
      --exclude '*.db*' --exclude 'vault-install.conf' --exclude '.cairn-pull.log' \
      "$HERE/" "$VAULT_SSH:cairn/" || die "rsync to $VAULT_SSH failed"
    scp "$BUNDLE" "$VAULT_SSH:cairn/vault-install.conf" >/dev/null || die "copying the bundle failed"
    printf '\n   \033[1;35m>>> now running ON THE VAULT (%s) - a sudo prompt below is the VAULT asking for its password <<<\033[0m\n' "$VAULT_SSH"
    if ssh -t "$VAULT_SSH" "cd cairn && ./install.sh vault --config vault-install.conf --yes" <"$TTY"; then
      printf '   \033[1;35m>>> back on home (local) <<<\033[0m\n'
      ok "vault provisioned - it should appear in the Agents card shortly"
    else
      printf '   \033[1;35m>>> back on home (local) <<<\033[0m\n'
      warn "remote vault install returned non-zero - check on the vault"
    fi
  else
    info "Copy $BUNDLE to the vault, then run there:  ./install.sh vault --config vault-install.conf"
  fi
  [ -n "$VAULT_SSH" ] && askyn "set up replication now (vault pulls home's ZFS datasets nightly)?" y \
    && provision_replication "$VAULT_SSH"
}

# detect home's replication sets from targets.yaml -> "name source dest raw" per line
_repl_sets() {
  [ -f "$HERE/config/targets.yaml" ] || return 0
  python3 - "$HERE/config/targets.yaml" <<'PY' 2>/dev/null
import sys, yaml
try: d = yaml.safe_load(open(sys.argv[1])) or {}
except Exception: sys.exit(0)
for t in (d.get("targets") or []):
    if isinstance(t, dict) and t.get("type") == "zfs-repl" and t.get("source") and t.get("dest"):
        print(t.get("name",""), t["source"], t["dest"], "raw" if t.get("encrypted") else "")
PY
}

# Configure the vault to PULL home's ZFS datasets nightly, over a dedicated restricted key.
# Idempotent: it checks what's already delegated / authorized and only fills gaps. Delegation-only
# (no run-time sudo); the one-time zfs allow on each side may prompt for a password.
provision_replication() {
  local ssh_t="${1:-$VAULT_SSH}"
  say "Replication (vault pulls home's ZFS datasets, nightly)"
  local sets; sets="$(_repl_sets)"
  [ -n "$sets" ] || { warn "no zfs-repl targets in config/targets.yaml - nothing to replicate"; return; }
  info "replication sets:"; while read -r n s d r; do [ -n "$n" ] && info "  $n: $s -> $d ${r:+(raw)}"; done <<<"$sets"
  [ -n "$ssh_t" ] || ask ssh_t "vault ssh target (user@host)" "$VAULT_SSH"
  [ -n "$ssh_t" ] || { warn "no vault ssh target - skipping replication"; return; }
  ssh -o BatchMode=yes -o ConnectTimeout=6 -o StrictHostKeyChecking=accept-new "$ssh_t" true 2>/dev/null \
    || { warn "cannot ssh to $ssh_t by key - run --add-vault first, or fix access"; return; }
  ensure_opt "command -v rsync >/dev/null" rsync "copying the runner to the vault"

  local vuser="${ssh_t%@*}"; [ "$vuser" = "$ssh_t" ] && vuser="$USER"
  local huser="$USER" wrapper="$HERE/replication/pull-command.sh"
  local home_addr; ask home_addr "address the VAULT uses to reach THIS home (LAN ip / VPN / host)" \
    "$(hostname -I 2>/dev/null | tr ' ' '\n' | grep -E '^(10\.|192\.168\.|172\.)' | head -1)"
  [ -n "$home_addr" ] || { warn "no home address - skipping replication"; return; }
  local HOME_SSH="$huser@$home_addr"
  local src_pools dst_pools p
  src_pools="$(echo "$sets" | awk 'NF{print $2}' | cut -d/ -f1 | sort -u)"
  dst_pools="$(echo "$sets" | awk 'NF{print $3}' | cut -d/ -f1 | sort -u)"

  # 1. HOME: delegate send/snapshot/hold on each SOURCE pool (skip if already present)
  for p in $src_pools; do
    if zfs allow "$p" 2>/dev/null | grep -qE "user $huser .*\bsend\b"; then ok "home: send already delegated on $p"
    else warn "home: delegating send,snapshot,hold on $p (one-time sudo)"
      prime_sudo && sudo zfs allow "$huser" send,snapshot,hold "$p" && ok "delegated on $p" || warn "could not delegate on $p"; fi
  done
  chmod +x "$wrapper" 2>/dev/null || true

  # 2. VAULT: dedicated no-passphrase pull key (idempotent); fetch its pubkey
  local pub; pub="$(ssh "$ssh_t" '[ -f ~/.ssh/cairn-pull ] || ssh-keygen -t ed25519 -f ~/.ssh/cairn-pull -N "" -C "cairn-pull -> home" >/dev/null 2>&1; chmod 600 ~/.ssh/cairn-pull; cat ~/.ssh/cairn-pull.pub' 2>/dev/null)"
  [ -n "$pub" ] || { warn "could not create/read the vault pull key"; return; }

  # 3. HOME: authorize the pull key, locked to the forced-command wrapper (idempotent)
  local ak="$HOME/.ssh/authorized_keys" keyfield; mkdir -p "$HOME/.ssh"; touch "$ak"; chmod 600 "$ak"
  keyfield="$(echo "$pub" | awk '{print $2}')"
  if grep -qF "$keyfield" "$ak"; then ok "home: pull key already authorized"
  else printf 'restrict,command="%s" %s\n' "$wrapper" "$pub" >> "$ak"; ok "home: authorized the pull key (restrict + forced-command)"; fi

  # 4. VAULT: delegate receive on each DEST pool (skip if present)
  for p in $dst_pools; do
    if ssh "$ssh_t" "zfs allow $p 2>/dev/null | grep -qE 'user $vuser .*\\breceive\\b'"; then ok "vault: receive already delegated on $p"
    else printf '   \033[1;35m>>> vault sudo (delegate receive on %s) <<<\033[0m\n' "$p"
      ssh -t "$ssh_t" "sudo zfs allow $vuser create,mount,receive,mountpoint $p" <"$TTY" && ok "vault: delegated receive on $p" || warn "vault: could not delegate receive on $p"; fi
  done

  # 5. VAULT: push the runner + units, write the conf, enable the nightly timer
  ssh "$ssh_t" 'mkdir -p ~/cairn/replication ~/.config/cairn ~/.config/systemd/user' 2>/dev/null
  rsync -a "$HERE/replication/vault-pull.sh" "$ssh_t:cairn/replication/vault-pull.sh" 2>/dev/null
  rsync -a "$HERE/replication/cairn-pull.service" "$HERE/replication/cairn-pull.timer" "$ssh_t:.config/systemd/user/" 2>/dev/null
  local cf; cf="$(mktemp)"
  { printf 'HOME_SSH  %s\nKEY  /home/%s/.ssh/cairn-pull\n' "$HOME_SSH" "$vuser"
    while read -r n s d r; do [ -n "$n" ] && printf 'SET  %s  %s  %s  %s\n' "$n" "$s" "$d" "$r"; done <<<"$sets"; } > "$cf"
  rsync -a "$cf" "$ssh_t:.config/cairn/replication.conf" 2>/dev/null; rm -f "$cf"
  ssh "$ssh_t" 'chmod 600 ~/.config/cairn/replication.conf; chmod +x ~/cairn/replication/vault-pull.sh; systemctl --user daemon-reload && systemctl --user enable --now cairn-pull.timer' 2>&1 | sed 's/^/   /' \
    && ok "vault: nightly pull timer enabled" || warn "vault: timer setup returned non-zero"

  if askyn "run the first pull now?" y; then
    printf '   \033[1;35m>>> first pull on the vault <<<\033[0m\n'
    ssh "$ssh_t" '~/cairn/replication/vault-pull.sh' 2>&1 | sed 's/^/   /' || warn "first pull returned non-zero (check on the vault)"
  fi
  ok "Replication configured. Add the replica datasets to the VAULT's targets.yaml (zfs-local) to see their freshness on the dashboard."
}

# add a vault to an already-running home (no home rebuild). Needs the api container up to mint a token.
add_vault_only() {
  ensure_docker_access
  dps --format '{{.Names}}' | grep -qxE 'cairn|cairn-api-1' \
    || die "no api container running - set up home first (./install.sh home), then re-run with --add-vault"
  say "Add a remote vault to this home"
  provision_vault
}

# set up (or re-sync) replication pull for an already-configured home + vault
add_replication_only() {
  [ -f "$HERE/config/targets.yaml" ] || die "no config/targets.yaml - set up home first (./install.sh home)"
  provision_replication "$VAULT_SSH"
}

# ============================================================ VAULT ============================================================
install_vault() {
  local ENVF="$HERE/config/cairn.env" TGT="$HERE/config/targets.yaml"
  mkdir -p "$HERE/config"
  [ -n "$CONFIG_IN" ] || ask CONFIG_IN "path to the vault bundle from home (vault-install.conf)" "$HERE/vault-install.conf"
  [ -f "$CONFIG_IN" ] || die "bundle not found: $CONFIG_IN (generate it on home: install.sh home)"
  # shellcheck disable=SC1090
  . "$CONFIG_IN"
  [ -n "${CAIRN_API_URL:-}" ] && [ -n "${CAIRN_ENROLL_SECRET:-}" ] || die "bundle missing CAIRN_API_URL / CAIRN_ENROLL_SECRET"
  CAIRN_API_URL="$(normurl "$CAIRN_API_URL")"   # tolerate a scheme-less URL in the bundle
  local NAME="${CAIRN_AGENT_NAME:-vault}"

  say "Reachability check: $CAIRN_API_URL"
  curl -fs -o /dev/null "${CAIRN_API_URL%/}/login" && ok "home API reachable" || warn "could not reach $CAIRN_API_URL/login yet - will keep retrying once the agent runs"

  if [ ! -f "$ENVF" ] || grep -q 'CHANGEME\|CAIRN_ENROLL_SECRET=$' "$ENVF" 2>/dev/null; then
    local VINT; ask VINT "seconds between the vault's check-ins (poll interval)" "300"
    say "Writing vault agent config on this host ($(hostname))"
    cat > "$ENVF" <<EOF
# cairn vault agent - generated by install.sh $(date -u +%Y-%m-%dT%H:%M:%SZ)
CAIRN_API_URL=$CAIRN_API_URL
CAIRN_AGENT_NAME=$NAME
CAIRN_ENROLL_SECRET=$CAIRN_ENROLL_SECRET
CAIRN_INTERVAL=$VINT
EOF
    chmod 600 "$ENVF"; ok "wrote $ENVF (checks in every ${VINT}s)"
  else ok "vault config present - keeping it"; fi

  if [ ! -f "$TGT" ]; then
    say "Generating a starter targets.yaml from THIS host's own pools"
    info "(a vault must monitor ITS pools/replicas - never home's, or it reports home's fleet as UNKNOWN)"
    {
      echo "# cairn vault targets - auto-generated $(date -u +%Y-%m-%dT%H:%M:%SZ). Edit to taste."
      echo "# List only what lives on THIS host. Add snapshot-freshness checks for replicas as they land,"
      echo "# e.g.  - { name: Pics-replica, type: zfs-local, source: iwolf/Pics }"
      echo "targets:"
      if command -v zpool >/dev/null 2>&1; then
        for p in $(zpool list -H -o name 2>/dev/null); do echo "  - { name: $p, type: zfs-local, source: $p }"; done
      fi
      echo "  # These need extra access (smartctl wrapper / log + zed read). Uncomment after granting it,"
      echo "  # or they will report UNKNOWN on a plain vault:"
      echo "  # - { name: smart, type: smart }"
      echo "  # - { name: kernel-disk-errors, type: kernel-errors }"
      echo "  # - { name: zfs-events, type: zfs-events }"
    } > "$TGT"
    chmod 644 "$TGT"
    ok "wrote $TGT (this host's pools; smart/kernel/zfs-events left commented so the vault stays clean)"
    askyn "review/edit it now?" n && { "${EDITOR:-vi}" "$TGT" <"$TTY" >/dev/tty 2>&1 || true; }
  fi

  local CAN=0; askyn "should the vault EXECUTE actions (e.g. run its own scrubs)? (default: report-only)" n && CAN=1

  say "Installing the vault agent (systemd --user)"
  mkdir -p "$HOME/.config/systemd/user"
  cat > "$HOME/.config/systemd/user/cairn-agent.service" <<EOF
[Unit]
Description=cairn vault agent (remote, reports to home)
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
Environment=PYTHONUNBUFFERED=1
Environment=CAIRN_ENV=$HERE/config/cairn.env
Environment=CAIRN_TARGETS=$HERE/config/targets.yaml
Environment=CAIRN_CAN_EXECUTE=$CAN
WorkingDirectory=$HERE
ExecStart=/usr/bin/python3 $HERE/agent.py
Restart=on-failure
RestartSec=15
[Install]
WantedBy=default.target
EOF
  # ---- optional: SMART attribute-table detail (per-disk model/temp/health/attributes). Sudoless by
  #      default (disk health from smartd's journal); the full table needs smartmontools + a scoped
  #      read-only smartctl sudo wrapper. Vaults omitted this before, so it never got offered here. ----
  local vsd=""; [ "$SMART_DETAIL" = 1 ] && vsd="--smart-detail"
  [ -z "$vsd" ] && { askyn "enable SMART attribute-table detail on this vault (per-disk model/temp/health; installs smartmontools + a scoped smartctl sudo wrapper)?" n && vsd="--smart-detail"; }
  # An execute-capable vault needs the scoped `zpool scrub` wrapper, or its Scrub button fails
  # "permission denied" (zpool verbs aren't delegable). Report-only vaults skip it.
  local vscrub=""; [ "$CAN" = 1 ] && vscrub="--scrub"
  if [ -n "$vsd" ] || [ -n "$vscrub" ]; then
    if [ -n "$vsd" ]; then
      # SMART detail was explicitly requested, so its smartmontools dependency installs even under --yes
      # (unlike the general optional toolchain, which --yes skips). Best-effort: warn, never die.
      if ! { command -v smartctl >/dev/null 2>&1 || command -v /usr/sbin/smartctl >/dev/null 2>&1; }; then
        prime_sudo && _pkg_do smartmontools && ok "smartmontools ready" || warn "couldn't install smartmontools - SMART detail needs it"
      fi
    fi
    sudo env CAIRN_USER="$USER" bash -c "'$HERE/phase1/grant-access.sh' $vsd $vscrub"
    local vunit="$HOME/.config/systemd/user/cairn-agent.service"
    if [ -n "$vsd" ]; then
      grep -q '^Environment=CAIRN_SMART_DETAIL=' "$vunit" || sed -i '/^ExecStart=/i Environment=CAIRN_SMART_DETAIL=1' "$vunit"
      # surface the disks: ensure an ACTIVE smart target in targets.yaml (uncomment a commented one, else append)
      if ! grep -qE '^[[:space:]]*-[[:space:]]*\{[[:space:]]*name:[[:space:]]*smart,' "$TGT"; then
        if grep -qE '^[[:space:]]*#[[:space:]]*-[[:space:]]*\{[[:space:]]*name:[[:space:]]*smart,' "$TGT"; then
          sed -i -E 's/^([[:space:]]*)#([[:space:]]*-[[:space:]]*\{[[:space:]]*name:[[:space:]]*smart,[^}]*\})/\1\2/' "$TGT"
        else
          printf '  - { name: smart, type: smart }\n' >> "$TGT"
        fi
        ok "added a 'smart' target to $TGT"
      fi
      ok "SMART detail enabled (smartmontools + wrapper + CAIRN_SMART_DETAIL=1)"
    fi
    [ -n "$vscrub" ] && ok "scrub execution enabled (scoped zpool-scrub wrapper) - the Scrub button now works"
  fi

  systemctl --user daemon-reload
  systemctl --user enable cairn-agent.service >/dev/null 2>&1 || true
  # restart (not just enable --now): on a re-run the agent is already active, and only a restart
  # reloads the regenerated unit env + targets.yaml (e.g. a freshly enabled SMART target).
  systemctl --user restart cairn-agent.service
  sudo loginctl enable-linger "$USER" 2>/dev/null || warn "couldn't enable linger (run: sudo loginctl enable-linger $USER) - agent won't survive logout without it"
  sleep 3
  systemctl --user is-active --quiet cairn-agent.service && ok "vault agent running → $CAIRN_API_URL" \
    || warn "agent not active - check: systemctl --user status cairn-agent"
  local shown_int; shown_int="$(grep -m1 '^CAIRN_INTERVAL=' "$ENVF" 2>/dev/null | cut -d= -f2)"; shown_int="${shown_int:-300}"
  say "VAULT setup complete - it should appear in home's Agents card within one poll interval (~${shown_int}s)"
}

case "$ROLE" in
  home)  if [ "$ADD_VAULT" = 1 ]; then add_vault_only
         elif [ "$REPLICATION" = 1 ]; then add_replication_only
         else install_home; fi ;;
  vault) install_vault ;;
esac
