#!/usr/bin/env python3
"""doctor - check this host's cairn setup and list every problem found, each with its fix.

Run it on EVERY box that runs an agent (main box and vault), as the agent's user, from the cairn
checkout. It reads the same settings the agent does (the systemd unit's Environment= lines win over
cairn.env, exactly like the agent) and checks, in order:

  agent      the service is installed, running, enabled and lingering; only ONE agent process runs;
             it was started after the last code update and the last targets.yaml edit
  settings   API url, credentials, agent name, dry-run, cairn.env permissions
  api        the control plane answers, versions match, this agent's credential is accepted, and
             the problems only the control plane can see (pairing with other agents) for this agent
  targets    targets.yaml parses; names, types and keys are valid (typos get a suggestion)
  zfs        datasets exist, replication dest/dest_agent make sense, the vault-pulled sources have
             snapshots, ZFS delegations (same rules as zfs-perms.py), httm
  tools      the programs each target type needs are installed
  pull       (vault only) replication.conf, the pull key, SET names vs targets, ssh to home, timer
  status     a dry collection: what the agent would report right now, every non-OK target with why

  phase1/doctor.py                 # everything
  phase1/doctor.py --offline       # skip network checks (API, ssh to home)
  phase1/doctor.py --no-collect    # skip the dry collection (the slowest part)

Exit code: 0 when nothing FAILed (WARNs allowed), 1 otherwise. Paste the whole output when asking
for help: it holds no secrets.
"""
import argparse, difflib, importlib.util, json, os, re, shlex, shutil, subprocess, sys, time
import urllib.error, urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
import collector as C  # noqa: E402

UNIT = "cairn-agent.service"
PULL_CONF = Path.home() / ".config" / "cairn" / "replication.conf"

TYPES = ("zfs-local", "zfs-repl", "borg-repo", "restic", "rclone", "snapper", "removable", "smart",
         "kernel-errors", "backupninja-handler", "schedules", "zfs-events", "aide", "reachability")
COMMON_KEYS = {"name", "type", "tier", "location", "encrypted", "backs_up", "schedule", "source_agent",
               "note", "cadence", "transport", "pre_cmd", "post_cmd", "hook_actions", "hook_timeout_s"}
FRESH = {"fresh_warn_h", "fresh_crit_h"}
TYPE_KEYS = {
    "zfs-local": {"source", "cap_warn_pct", "cap_crit_pct", "resilver_warn_h"} | FRESH,
    "zfs-repl": {"source", "dest", "repl_warn_h", "repl_crit_h", "vault_keystatus_expected",
                 "dest_agent"} | FRESH,
    "borg-repo": {"source", "passphrase_env"} | FRESH,
    "restic": {"source", "passphrase_env", "password_file"} | FRESH,
    "rclone": {"source", "marker"} | FRESH,
    "snapper": {"source"} | FRESH,
    "removable": {"uuid", "by_id", "mount", "source", "dest_subpath", "tool", "exclude", "mirror",
                  "detach_warn_d", "remind_every_d"} | FRESH,
    "smart": {"smartd_window_h"},
    "kernel-errors": {"window_h", "crit_count", "rescan_storm", "log_file"},
    "backupninja-handler": {"source", "log", "reports", "jobs"} | FRESH,
    "schedules": {"units"},
    "zfs-events": {"window_h", "alert_h"},
    "aide": {"check_cmd", "severity", "label"},
    "reachability": {"host", "ssh", "port", "key", "probe", "tries", "retry_wait_s", "connect_timeout_s"},
}
REQUIRED = {"zfs-local": ["source"], "zfs-repl": ["source", "dest"], "borg-repo": ["source"],
            "restic": ["source"], "rclone": ["source"], "snapper": ["source"],
            "backupninja-handler": ["source"], "removable": ["mount"]}
DEFAULT_KEYS = {"repl_warn_h", "repl_crit_h", "cap_warn_pct", "cap_crit_pct", "scrub_warn_d",
                "scrub_crit_d", "resilver_warn_h", "fresh_warn_h", "fresh_crit_h", "removable_detach_warn_d"}
TOOLS = {"zfs-local": ["zfs", "zpool"], "zfs-repl": ["zfs", "zpool"], "borg-repo": ["borg"],
         "restic": ["restic"], "rclone": ["rclone"], "snapper": ["snapper"],
         "removable": ["rsync", "findmnt"], "smart": ["smartctl"], "reachability": ["ssh"],
         "schedules": ["systemctl"], "zfs-events": ["journalctl"], "kernel-errors": ["journalctl"]}


class Report:
    """Collects (level, section, message, fix) findings and prints them as they come."""
    MARK = {"OK": " ok ", "INFO": "info", "WARN": "WARN", "FAIL": "FAIL"}

    def __init__(self, quiet=False):
        self.items, self.quiet = [], quiet

    def section(self, title):
        if not self.quiet:
            print(f"\n== {title}")

    def add(self, level, msg, fix=None):
        self.items.append((level, msg, fix))
        if not self.quiet:
            print(f"  [{self.MARK[level]}] {msg}")
            if fix:
                print(f"         fix: {fix}")

    def ok(self, msg): self.add("OK", msg)
    def info(self, msg, fix=None): self.add("INFO", msg, fix)
    def warn(self, msg, fix=None): self.add("WARN", msg, fix)
    def fail(self, msg, fix=None): self.add("FAIL", msg, fix)

    def count(self, level):
        return sum(1 for i in self.items if i[0] == level)


def _sh(cmd, timeout=20):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except FileNotFoundError:
        return 127, "", f"{cmd[0]}: not found"
    except subprocess.TimeoutExpired:
        return 124, "", "timed out"


def _suggest(word, choices):
    m = difflib.get_close_matches(word, list(choices), n=1, cutoff=0.6)
    return f" (did you mean '{m[0]}'?)" if m else ""


# ---------------------------------------------------------------- effective settings
def unit_env(text):
    """Parse `systemctl show -p Environment --value` (space-separated, shell-quoted K=V pairs)."""
    env = {}
    try:
        parts = shlex.split(text or "")
    except ValueError:
        parts = (text or "").split()
    for p in parts:
        if "=" in p:
            k, v = p.split("=", 1)
            env[k] = v
    return env


def effective_env():
    """The agent's environment: unit Environment= first (it wins), then cairn.env via setdefault."""
    rc, out, _ = _sh(["systemctl", "--user", "show", UNIT, "-p", "Environment", "--value"])
    uenv = unit_env(out) if rc == 0 else {}
    os.environ.update(uenv)
    if "CAIRN_ENV" not in os.environ and (ROOT / "config" / "cairn.env").is_file():
        os.environ["CAIRN_ENV"] = str(ROOT / "config" / "cairn.env")
    C.load_env()
    return uenv


# ---------------------------------------------------------------- agent process checks
def agent_processes(proc="/proc"):
    """[(pid, start_epoch, cgroup)] of every python process running cairn's agent.py on this host,
    containers included (their processes are visible in the host's /proc)."""
    out = []
    try:
        btime = next(int(ln.split()[1]) for ln in Path(proc, "stat").read_text().splitlines()
                     if ln.startswith("btime "))
    except (OSError, StopIteration, ValueError):
        btime = 0
    hz = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100
    for d in Path(proc).iterdir():
        if not d.name.isdigit():
            continue
        try:
            argv = (d / "cmdline").read_bytes().split(b"\0")
            argv = [a.decode(errors="replace") for a in argv if a]
            if not argv or not os.path.basename(argv[0]).startswith("python"):
                continue
            if not any(a.endswith("agent.py") for a in argv[1:3]):
                continue
            stat = (d / "stat").read_text()
            start = int(stat.rsplit(")", 1)[1].split()[19]) // hz + btime
            cg = (d / "cgroup").read_text().strip().splitlines()[-1].split(":", 2)[-1]
        except (OSError, ValueError, IndexError):
            continue
        out.append((int(d.name), start, cg))
    return sorted(out)


def check_agent(r, uenv):
    r.section("agent")
    rc, _, _ = _sh(["systemctl", "--user", "cat", UNIT])
    if rc != 0:
        r.fail(f"no systemd user unit {UNIT}", "run ./install.sh home (main box) or ./install.sh vault")
    else:
        _, active, _ = _sh(["systemctl", "--user", "is-active", UNIT])
        _, enabled, _ = _sh(["systemctl", "--user", "is-enabled", UNIT])
        if active == "active":
            r.ok(f"{UNIT} is running")
        else:
            r.fail(f"{UNIT} is {active or 'not running'}",
                   f"systemctl --user start {UNIT}; journalctl --user -u {UNIT} -n 50")
        if enabled != "enabled":
            r.warn(f"{UNIT} is {enabled or 'not enabled'}: it won't start at boot",
                   f"systemctl --user enable {UNIT}")
        _, nr, _ = _sh(["systemctl", "--user", "show", UNIT, "-p", "NRestarts", "--value"])
        if nr.isdigit() and int(nr) >= 3:
            r.warn(f"the agent has restarted {nr} times since the unit last started (crash loop?)",
                   f"journalctl --user -u {UNIT} -n 80")
    user = os.environ.get("USER") or C._whoami()[0]
    _, linger, _ = _sh(["loginctl", "show-user", user, "-p", "Linger", "--value"])
    if linger == "no":
        r.warn(f"lingering is off for {user}: the agent stops when you log out and won't start at "
               "boot until you log in", f"sudo loginctl enable-linger {user}")
    procs = agent_processes()
    if len(procs) > 1:
        lines = "; ".join(f"pid {p} in {cg}" for p, _, cg in procs)
        r.fail(f"{len(procs)} cairn agents are running on this host ({lines})",
               "keep only the systemd one: a container agent from docker-compose.yml only starts with "
               "--profile container-agent, so `podman compose down` / `docker compose down` and bring "
               "the API back with `... up -d api`")
    elif procs:
        pid, start, _ = procs[0]
        r.ok(f"one agent process (pid {pid}, started {time.strftime('%Y-%m-%d %H:%M', time.localtime(start))})")
        for label, path in (("the cairn code", ROOT / "VERSION"),
                            ("targets.yaml", Path(os.environ.get("CAIRN_TARGETS", ROOT / "targets.yaml")))):
            try:
                if path.stat().st_mtime > start + 2:
                    r.warn(f"{label} changed after the agent started, so it isn't loaded yet",
                           f"systemctl --user restart {UNIT}")
            except OSError:
                pass


# ---------------------------------------------------------------- settings
def check_settings(r, uenv):
    r.section("settings")
    env_file = Path(os.environ.get("CAIRN_ENV", "/etc/cairn/cairn.env"))
    if env_file.is_file():
        mode = env_file.stat().st_mode & 0o777
        if mode & 0o077:
            r.warn(f"{env_file} is readable by other users (mode {mode:o}) and holds the agent's secret",
                   f"chmod 600 {env_file}")
        else:
            r.ok(f"settings file {env_file}")
    else:
        r.warn(f"no settings file at {env_file}", "copy config/cairn.env.example and fill it in, or re-run install.sh")
    api = os.environ.get("CAIRN_API_URL")
    if not api:
        r.warn("CAIRN_API_URL is not set: the agent talks to http://localhost:8929",
               "set CAIRN_API_URL in cairn.env (the unit's Environment= wins if it sets one)")
    else:
        src = "unit" if "CAIRN_API_URL" in uenv else "cairn.env"
        r.ok(f"API url {api} (from the {src})")
    if not (os.environ.get("CAIRN_ENROLL_SECRET") or os.environ.get("CAIRN_API_TOKEN")):
        r.fail("no credential: neither CAIRN_ENROLL_SECRET nor CAIRN_API_TOKEN is set",
               "mint one on the API host (phase1/cairn-token.py) and put it in cairn.env")
    name = os.environ.get("CAIRN_AGENT_NAME", "local")
    r.info(f"agent name '{name}'" + ("" if "CAIRN_AGENT_NAME" in os.environ else " (default)"))
    if os.environ.get("CAIRN_DRYRUN", "0") == "1":
        r.warn("CAIRN_DRYRUN=1: every dashboard action only logs what it would do",
               "set Environment=CAIRN_DRYRUN=0 in the unit, then restart the agent")
    if os.environ.get("CAIRN_CAN_EXECUTE", "0") != "1":
        r.info("CAIRN_CAN_EXECUTE is off: report-only, no dashboard action buttons for this agent")
    try:
        file_env = {}
        if env_file.is_file():
            for ln in env_file.read_text().splitlines():
                ln = ln.strip()
                if ln and not ln.startswith("#") and "=" in ln:
                    k, v = ln.split("=", 1)
                    file_env[k.strip()] = re.split(r"\s+#", v, maxsplit=1)[0].strip()
        for k, v in sorted(file_env.items()):
            if k in uenv and uenv[k] != v and "SECRET" not in k and "TOKEN" not in k:
                r.info(f"{k}={v} in cairn.env is ignored: the unit sets {k}={uenv[k]}")
    except OSError:
        pass


# ---------------------------------------------------------------- control plane
def _vt(v):
    try:
        return tuple(int(x) for x in v.split("."))
    except (AttributeError, ValueError):
        return ()


def _http(method, url, headers=None, body=None, timeout=15):
    h = {"User-Agent": os.environ.get("CAIRN_USER_AGENT", "cairn-agent/1.0"), "Content-Type": "application/json"}
    h.update(headers or {})
    req = urllib.request.Request(url, data=body, method=method, headers=h)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read() or "null")


def check_api(r):
    r.section("api")
    api = os.environ.get("CAIRN_API_URL", "http://localhost:8929").rstrip("/")
    local_v = (ROOT / "VERSION").read_text().strip() if (ROOT / "VERSION").is_file() else "?"
    try:
        ident = _http("GET", f"{api}/api/v1/identify")
    except Exception as e:
        r.fail(f"cannot reach the API at {api}: {e}",
               "check the url, that the API container is up (`podman compose ps`), and the firewall/proxy")
        return
    sv = ident.get("version", "?")
    if sv == local_v:
        r.ok(f"API '{ident.get('name')}' reachable, version {sv} (same as this checkout)")
    elif _vt(sv) < _vt(local_v):
        r.warn(f"the API runs {sv}, older than this checkout ({local_v})",
               "on the API host: git pull, then `podman compose up -d --build api` (or docker compose)")
    else:
        r.warn(f"this checkout is {local_v}, older than the API ({sv})",
               f"git pull && systemctl --user restart {UNIT} (or the Update button on the Agents card)")
    token = os.environ.get("CAIRN_API_TOKEN", "")
    secret = os.environ.get("CAIRN_ENROLL_SECRET", "")
    try:
        if secret:
            token = _http("POST", f"{api}/api/v1/backup/enroll", {"X-Backup-Enroll": secret}, b"{}")["access_token"]
        if not token:
            return
        name = os.environ.get("CAIRN_AGENT_NAME", "local")
        who = _http("GET", f"{api}/api/v1/backup/agent/doctor?name={urllib.request.quote(name)}",
                    {"X-Backup-Token": token})
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            r.fail(f"the API rejected this agent's credential (HTTP {e.code})",
                   "mint a fresh one on the API host (phase1/cairn-token.py) and update cairn.env")
        elif e.code == 404:
            r.info("the API predates the fleet check (update the API to get it)")
        else:
            r.warn(f"credential check failed: HTTP {e.code}")
        return
    except Exception as e:
        r.warn(f"credential check failed: {e}")
        return
    r.ok("the API accepts this agent's credential")
    if not who.get("known"):
        r.info(f"the API hasn't heard from an agent named '{who.get('agent')}' yet "
               "(normal before its first report)")
    for f in who.get("findings", []):
        lvl = {"CRIT": "FAIL", "WARN": "WARN"}.get(f.get("severity"), "INFO")
        r.add(lvl, f.get("problem", ""), f.get("fix"))


# ---------------------------------------------------------------- targets.yaml
def check_targets_cfg(r, cfg, path):
    """Structural checks on a parsed targets.yaml. Returns the list of usable target dicts."""
    r.section(f"targets ({path})")
    if not isinstance(cfg, dict):
        r.fail("targets.yaml is empty or not a mapping", "see config/targets.example.yaml")
        return []
    for k in cfg:
        if k not in ("targets", "defaults", "scrub_cadence"):
            r.warn(f"unknown top-level key '{k}'{_suggest(k, ['targets', 'defaults', 'scrub_cadence'])}")
    for k in (cfg.get("defaults") or {}):
        if k not in DEFAULT_KEYS:
            r.warn(f"defaults: unknown key '{k}'{_suggest(k, DEFAULT_KEYS)}: it is ignored")
    for pool, ent in (cfg.get("scrub_cadence") or {}).items():
        if not isinstance(ent, dict) or not {"warn_d", "crit_d"} <= set(ent):
            r.fail(f"scrub_cadence: '{pool}' needs both warn_d and crit_d (a partial entry breaks that pool's card)",
                   f"scrub_cadence: {{ {pool}: {{ warn_d: 40, crit_d: 70 }} }}")
    ts = cfg.get("targets")
    if not isinstance(ts, list) or not ts:
        r.fail("no `targets:` list", "see config/targets.example.yaml")
        return []
    good, seen = [], {}
    for i, t in enumerate(ts):
        where = f"targets[{i}]"
        if not isinstance(t, dict):
            r.fail(f"{where} is not a mapping (check the indentation and the leading '- ')")
            continue
        name, typ = t.get("name"), t.get("type")
        if not name:
            r.fail(f"{where} has no name (the agent stops reporting on a missing name or type)")
            continue
        where = f"'{name}'"
        if name in seen:
            r.fail(f"{where} is defined twice (targets[{seen[name]}] and targets[{i}]): the second overwrites the first")
        seen[name] = i
        if not typ:
            r.fail(f"{where} has no type (the agent can't report at all without it)", f"one of: {', '.join(TYPES)}")
            continue
        if typ not in TYPES:
            r.fail(f"{where}: unknown type '{typ}'{_suggest(typ, TYPES)}")
            continue
        known = COMMON_KEYS | TYPE_KEYS[typ]
        for k in t:
            if k not in known:
                r.warn(f"{where}: key '{k}' isn't used by {typ}{_suggest(k, known)}: it is ignored")
        for k in REQUIRED.get(typ, []):
            if not t.get(k):
                r.fail(f"{where}: {typ} needs '{k}'")
        if typ == "removable" and not (t.get("uuid") or t.get("by_id")):
            r.fail(f"{where}: removable needs 'uuid' or 'by_id' (never /dev/sdX)")
        if typ == "reachability" and not (t.get("host") or t.get("ssh")):
            r.fail(f"{where}: reachability needs 'host'")
        if typ == "zfs-repl":
            d = str(t.get("dest") or "")
            if d.startswith("/") or ":" in d or "@" in d:
                r.fail(f"{where}: dest '{d}' must be a dataset name like pool/photos, not a path or user@host",
                       "use the dataset as `zfs list` prints it on the receiving pool; set dest_agent if that pool is on another box")
        if t.get("tier") == "A" and typ != "zfs-repl":
            r.info(f"{where}: tier A only counts on a zfs-repl target (the 3-2-1 scorecard); here it's just a badge")
        if t.get("source_agent") and typ != "zfs-local":
            r.warn(f"{where}: source_agent belongs on the vault's zfs-local that receives the copy")
        good.append(t)
    if good and r.count("FAIL") == 0:
        r.ok(f"{len(good)} targets parse cleanly")
    return good


# ---------------------------------------------------------------- zfs
def _ds_exists(ds):
    return _sh(["zfs", "list", "-H", "-o", "name", ds])[0] == 0


def _snap_count(ds):
    rc, out, _ = _sh(["zfs", "list", "-H", "-t", "snapshot", "-o", "name", "-d", "1", ds], timeout=60)
    return len(out.splitlines()) if rc == 0 else None


def check_zfs(r, targets, pools):
    zt = [t for t in targets if t.get("type") in ("zfs-local", "zfs-repl")]
    if not zt:
        return
    r.section("zfs")
    if not shutil.which("zfs"):
        r.fail("zfs isn't installed or not on PATH, but targets.yaml has ZFS targets")
        return
    r.info(f"pools on this host: {', '.join(sorted(pools)) or 'none'}")
    for t in zt:
        n, src = t["name"], t.get("source") or ""
        if src and not _ds_exists(src):
            pool = src.split("/")[0]
            hint = (f"pool '{pool}' isn't imported here" if pool not in pools else
                    "check the spelling against `zfs list`")
            r.fail(f"'{n}': source {src} doesn't exist on this host ({hint})")
        if t["type"] != "zfs-repl":
            continue
        dst, da = t.get("dest") or "", t.get("dest_agent")
        dpool = dst.split("/")[0]
        if dpool in pools:
            if da:
                r.warn(f"'{n}': dest_agent '{da}' is set but dest pool '{dpool}' is on THIS host",
                       "drop dest_agent for a local copy (it makes this half stop checking the dest)")
            elif not _ds_exists(dst):
                r.warn(f"'{n}': {dst} doesn't exist yet: nothing has been received (press Replicate, or wait for syncoid)")
            if not shutil.which("syncoid"):
                r.warn(f"'{n}': syncoid isn't installed, so Replicate can't run", "apt install sanoid")
        elif not da:
            r.warn(f"'{n}': dest pool '{dpool}' isn't on this host and dest_agent isn't set, so this card "
                   "can only say UNKNOWN", "if a vault pulls it, add `dest_agent: <the vault's CAIRN_AGENT_NAME>`")
        else:
            c = _snap_count(src) if src else None
            if c == 0:
                r.fail(f"'{n}': {src} has no snapshots, and the vault pull only copies existing snapshots",
                       f"give {src} a sanoid policy (sanoid.conf) or take one: zfs snapshot {src}@first")
            elif c:
                r.ok(f"'{n}': {src} -> '{da}':{dst} (source has {c} snapshots)")
    if os.geteuid() == 0:
        r.info("running as root: ZFS delegation not needed")
    else:
        zp = _load_zfs_perms()
        user, groups = C._whoami()
        rows = zp.plan(targets, set(pools))
        gaps = []
        for ds, ess, extra, why, req in rows:
            miss = zp.missing(ds, ess, user, groups)
            if miss and req:
                gaps.append(ds)
                r.fail(f"'{user}' lacks ZFS permission {','.join(miss)} on {ds} ({'; '.join(why)})",
                       "phase1/zfs-perms.py --apply")
        if rows and not gaps:
            r.ok(f"'{user}' holds every required ZFS delegation (details: phase1/zfs-perms.py)")
    if any(t["type"] == "zfs-local" for t in zt):
        if C.httm_disabled():
            r.info("httm is off (CAIRN_HTTM=0): Versions and Deleted are hidden")
        elif not shutil.which("httm"):
            r.warn("httm isn't installed: the Versions and Deleted buttons won't work",
                   "install httm (github.com/kimono-koans/httm), or set CAIRN_HTTM=0 in cairn.env to opt out")
        stuck = C.stuck_httm()
        if stuck:
            r.warn(f"httm processes stuck from an earlier scan: {stuck} (they block agent restarts)",
                   f"kill -9 {' '.join(map(str, stuck))}; if they won't die they're in D state (a hung dataset)")


def _load_zfs_perms():
    spec = importlib.util.spec_from_file_location("zfs_perms", HERE / "zfs-perms.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------- tools
def check_tools(r, targets):
    r.section("tools")
    need = {}
    for t in targets:
        for tool in TOOLS.get(t.get("type"), []):
            need.setdefault(tool, set()).add(t["type"])
    missing = [(tool, types) for tool, types in sorted(need.items()) if not shutil.which(tool)]
    for tool, types in missing:
        r.fail(f"{tool} isn't installed, needed by {', '.join(sorted(types))}")
    if not missing:
        r.ok("every program the configured targets need is installed")


# ---------------------------------------------------------------- vault pull
def parse_pull_conf(text):
    """Mirror vault-pull.sh's parser: {'HOME_SSH','KEY','PORT','SETS':[(name,src,dst,raw)]}."""
    c = {"HOME_SSH": "", "KEY": "", "PORT": "", "SETS": []}
    for ln in text.splitlines():
        f = ln.split()
        if not f or f[0].startswith("#"):
            continue
        if f[0] in ("HOME_SSH", "KEY", "PORT") and len(f) > 1:
            c[f[0]] = f[1]
        elif f[0] == "SET":
            f += [""] * (5 - len(f))
            c["SETS"].append((f[1], f[2], f[3], f[4]))
    return c


def pull_set_findings(conf, targets, pools):
    """[(level, msg, fix)] for the SET lines vs this vault's targets. Pure, for tests."""
    out = []
    locs = [t for t in targets if t.get("type") == "zfs-local"]
    by_name = {t["name"]: t for t in locs}
    by_src = {t.get("source"): t for t in locs}
    set_names = set()
    for name, src, dst, _ in conf["SETS"]:
        set_names.add(name)
        if not (name and src and dst):
            out.append(("FAIL", f"SET '{name}' is incomplete: SET <name> <source-on-home> <dest-on-vault> [raw]", None))
            continue
        if dst.split("/")[0] not in pools:
            out.append(("FAIL", f"SET '{name}': dest pool '{dst.split('/')[0]}' isn't on this vault", None))
        t = by_name.get(name)
        if t is None:
            other = by_src.get(dst)
            if other:
                out.append(("FAIL", f"SET '{name}' pulls into {dst}, but the target watching {dst} is named "
                            f"'{other['name']}', so its Replicate now runs `--only {other['name']}` and finds no SET",
                            f"rename the target '{other['name']}' to '{name}' in targets.yaml (the home zfs-repl uses '{name}' too)"))
            else:
                out.append(("WARN", f"SET '{name}' pulls into {dst} but no zfs-local target watches it",
                            f"add `- {{ name: {name}, type: zfs-local, source: {dst}, source_agent: <home agent> }}`"))
            continue
        if t.get("source") != dst:
            out.append(("FAIL", f"target '{name}' watches {t.get('source')} but its SET pulls into {dst}",
                        "make them the same dataset"))
        if not t.get("source_agent"):
            out.append(("WARN", f"target '{name}' has no source_agent, so its card has no Replicate now button",
                        f"add `source_agent: <home agent name>` to '{name}'"))
    for t in locs:
        if t.get("source_agent") and t["name"] not in set_names:
            out.append(("WARN", f"'{t['name']}' says it receives from '{t['source_agent']}' but no SET is named "
                        f"'{t['name']}', so nothing pulls into it and Replicate now fails",
                        "on the main box re-run ./install.sh home --replication, or rename the target to match its SET"))
    return out


def check_pull(r, targets, pools, offline):
    receiving = [t for t in targets if t.get("type") == "zfs-local" and t.get("source_agent")]
    if not PULL_CONF.is_file() and not receiving:
        return
    r.section(f"pull ({PULL_CONF})")
    if not PULL_CONF.is_file():
        r.fail(f"targets have source_agent ({', '.join(t['name'] for t in receiving)}) but there is no pull config",
               "on the MAIN box: ./install.sh home --replication --vault-ssh <user>@<this vault>")
        return
    conf = parse_pull_conf(PULL_CONF.read_text())
    if not conf["HOME_SSH"] or not conf["KEY"] or not conf["SETS"]:
        r.fail("replication.conf is incomplete: it needs HOME_SSH, KEY and at least one SET")
        return
    if conf["PORT"] and not conf["PORT"].isdigit():
        r.fail(f"PORT '{conf['PORT']}' isn't a number")
    key = Path(os.path.expanduser(conf["KEY"]))
    if not key.is_file():
        r.fail(f"pull key {key} doesn't exist", "re-run ./install.sh home --replication on the main box")
    elif key.stat().st_mode & 0o077:
        r.warn(f"pull key {key} is readable by others (ssh refuses it)", f"chmod 600 {key}")
    if not shutil.which("syncoid"):
        r.fail("syncoid isn't installed, so the pull can't run", "apt install sanoid")
    for lvl, msg, fix in pull_set_findings(conf, targets, pools):
        r.add(lvl, msg, fix)
    if not offline and key.is_file():
        cmd = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-i", str(key)]
        if conf["PORT"]:
            cmd += ["-p", conf["PORT"]]
        rc, _, err = _sh(cmd + [conf["HOME_SSH"], "true"], timeout=30)
        port = f" port {conf['PORT']}" if conf["PORT"] else ""
        if rc == 0:
            r.ok(f"ssh to home {conf['HOME_SSH']}{port} with the pull key works")
        else:
            r.fail(f"ssh to home {conf['HOME_SSH']}{port} failed: {err.splitlines()[-1] if err else rc}",
                   "check the address/port (PORT line), the VPN, and that home's authorized_keys still has the cairn-pull key")
    _, en, _ = _sh(["systemctl", "--user", "is-enabled", "cairn-pull.timer"])
    if en != "enabled":
        r.fail(f"cairn-pull.timer is {en or 'missing'}: the nightly pull won't run",
               "systemctl --user enable --now cairn-pull.timer")
    _, st, _ = _sh(["systemctl", "--user", "show", "cairn-pull.service", "-p", "ExecMainStatus", "--value"])
    _, when, _ = _sh(["systemctl", "--user", "show", "cairn-pull.service", "-p", "ExecMainExitTimestamp", "--value"])
    if st.isdigit() and int(st) != 0:
        r.warn(f"the last pull ({when or 'unknown time'}) exited {st} (3 = home unreachable)",
               "journalctl --user -u cairn-pull -n 60")
    elif when:
        r.ok(f"last pull finished OK at {when}")


# ---------------------------------------------------------------- dry collection
def _reasons(st):
    try:
        d = json.loads(st.get("detail_json") or "{}")
    except (ValueError, TypeError):
        d = {}
    rs = [x for x in (d.get("reasons") or []) if isinstance(x, str)]
    if st.get("last_error"):
        rs.append(st["last_error"])
    return "; ".join(rs) or "no reason given"


def check_status(r, cfg):
    r.section("status (what the agent would report now)")
    try:
        res = C.collect_all(cfg)
    except Exception as e:
        r.fail(f"collection crashed: {e}", "fix the targets problems above; this is what the agent hits every cycle")
        return
    bad = [(t, st) for t, st in res if st.get("severity", "UNKNOWN") != "OK"]
    for t, st in bad:
        lvl = "FAIL" if st.get("severity") == "CRIT" else "WARN"
        r.add(lvl, f"{t['name']} ({t.get('type')}): {st.get('severity')} - {_reasons(st)}")
    r.ok(f"{len(res) - len(bad)} of {len(res)} statuses OK") if res else r.warn("nothing to report")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--offline", action="store_true", help="skip the API and ssh checks")
    ap.add_argument("--no-collect", action="store_true", help="skip the dry collection")
    a = ap.parse_args()
    r = Report()
    print(f"cairn doctor {(ROOT / 'VERSION').read_text().strip() if (ROOT / 'VERSION').is_file() else ''} "
          f"on {os.uname().nodename} as {os.environ.get('USER') or C._whoami()[0]}")
    uenv = effective_env()
    check_agent(r, uenv)
    check_settings(r, uenv)
    if not a.offline:
        check_api(r)
    tpath = Path(os.environ.get("CAIRN_TARGETS", ROOT / "targets.yaml"))
    cfg = None
    try:
        import yaml
        cfg = yaml.safe_load(tpath.read_text())
    except FileNotFoundError:
        r.section("targets")
        r.fail(f"{tpath} doesn't exist", "set CAIRN_TARGETS or copy config/targets.example.yaml")
    except Exception as e:
        r.section("targets")
        r.fail(f"{tpath} doesn't parse: {e}", "check the indentation (spaces, not tabs) around the line named")
    targets = check_targets_cfg(r, cfg, tpath) if cfg is not None else []
    pools = set(C.zpool_list())
    check_zfs(r, targets, pools)
    check_tools(r, targets)
    check_pull(r, targets, pools, a.offline)
    if targets and not a.no_collect:
        check_status(r, cfg)
    f, w = r.count("FAIL"), r.count("WARN")
    print(f"\n{f} problem(s), {w} warning(s)." + ("" if f or w else " All good."))
    return 1 if f else 0


if __name__ == "__main__":
    sys.exit(main())
