#!/usr/bin/env python3
"""cairn Phase 1 collector.

Reads targets.yaml, runs one adapter per target type, computes severity, and writes
a status row per target into SQLite. Read-only against all backups. Designed to run
as root at deploy (borg repos + backupninja reports + smartctl are root-only); degrades
each unreadable signal to UNKNOWN (with last_error) rather than crashing, so it also
runs partially as an unprivileged user for testing.

Usage:
  collector.py [--once] [--db PATH] [--targets PATH] [--alert]
Env (or /etc/cairn/cairn.env): CAIRN_DB, CAIRN_TARGETS, BORG_PASSPHRASE_*
"""
import argparse, json, os, re, shutil, sqlite3, subprocess, sys, time
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("PyYAML required: pip install pyyaml  (see requirements.txt)")

HERE = Path(__file__).resolve().parent
NOTIFY = HERE.parent / "phase0" / "notify.sh"
DAY = 86400

# ---------- small shell helpers ----------
def run(cmd, timeout=60, env=None):
    """Return (rc, stdout, stderr). Never raises on nonzero."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           env={**os.environ, **(env or {})})
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except FileNotFoundError as e:
        return 127, "", str(e)

def load_env(path="/etc/cairn/cairn.env"):
    p = Path(os.environ.get("CAIRN_ENV", path))
    if p.is_file():
        for line in p.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip())

# ---------- ZFS primitives ----------
def zpool_list():
    rc, out, _ = run(["zpool", "list", "-Hp", "-o", "name,health,capacity,size,alloc,free"])
    pools = {}
    if rc == 0:
        for ln in out.splitlines():
            f = ln.split("\t")
            if len(f) == 6:
                pools[f[0]] = dict(health=f[1], cap=int(f[2]), size=int(f[3]),
                                   alloc=int(f[4]), free=int(f[5]))
    return pools

def zpool_scrub_ts(pool):
    rc, out, _ = run(["zpool", "status", pool])
    if rc != 0:
        return None, None
    m = re.search(r"scan:\s*(.+)", out)
    if not m:
        return None, None
    line = m.group(1)
    if "in progress" in line:
        return "in_progress", None
    if "none requested" in line:
        return "never", None
    dm = re.search(r" on (.+)$", line.strip())
    if not dm:
        return line.strip(), None
    rc2, ep, _ = run(["date", "-d", dm.group(1), "+%s"])
    try:
        return line.strip(), int(ep.strip())
    except ValueError:
        return line.strip(), None

def zpool_scrub_progress(pool):
    """Live scrub state for the pool card: whether a scrub is running, how far (%), ETA, bytes
    repaired, and the pool's bottom-line data-error state. Returns {} when status is unreadable.
    Keys: state (in_progress|finished|never), pct, eta, repaired, scrub_errors, errors."""
    rc, out, _ = run(["zpool", "status", pool])
    if rc != 0:
        return {}
    d = {}
    m = re.search(r"scan:\s*(.+(?:\n[ \t]+.+)*)", out)   # scan line + its indented continuation lines
    scan = m.group(1) if m else ""
    if "in progress" in scan:
        d["state"] = "in_progress"
        pm = re.search(r"([\d.]+)%\s+done", scan)
        if pm: d["pct"] = float(pm.group(1))
        em = re.search(r"([\d:]+)\s+to go", scan)
        if em: d["eta"] = em.group(1)
        rm = re.search(r"([\d.]+\s*[BKMGTP]?)\s+repaired", scan)
        if rm: d["repaired"] = rm.group(1).strip()
    elif "none requested" in scan:
        d["state"] = "never"
    elif scan:
        d["state"] = "finished"
        rm = re.search(r"repaired\s+([\d.]+\s*[BKMGTP]?)\s+in", scan)
        if rm: d["repaired"] = rm.group(1).strip()
        ecm = re.search(r"with\s+(\d+)\s+errors?", scan)
        if ecm: d["scrub_errors"] = int(ecm.group(1))
    errm = re.search(r"errors:\s*(.+)", out)              # e.g. "No known data errors" or a corruption summary
    if errm:
        d["errors"] = errm.group(1).strip()
    return d

def zpool_status_detail(pool):
    """Parse `zpool status <pool>` for the health signals a resilver/flaky-link event produces:
    resilver state, non-ONLINE vdevs, and per-vdev READ/WRITE/CKSUM error counts. ZFS often
    self-heals a transient (0B resilver, counters cleared), so a *recent resilver* is itself a flag."""
    d = {"resilver": None, "resilver_ts": None, "bad_vdevs": [], "err_vdevs": []}
    rc, out, _ = run(["zpool", "status", pool])
    if rc != 0:
        return d
    in_table = False
    STATES = ("ONLINE", "DEGRADED", "FAULTED", "OFFLINE", "UNAVAIL", "REMOVED", "SPARE", "REPLACING")
    for ln in out.splitlines():
        s = ln.strip()
        if s.startswith("scan:"):
            if "resilver in progress" in s:
                d["resilver"] = "in_progress"
            elif "resilvered" in s:
                d["resilver"] = "done"
                m = re.search(r" on (.+)$", s)
                if m:
                    rc2, ep, _ = run(["date", "-d", m.group(1), "+%s"])
                    if rc2 == 0:
                        try:
                            d["resilver_ts"] = int(ep.strip())
                        except ValueError:
                            pass
        if s.startswith("NAME") and "STATE" in s:
            in_table = True; continue
        if in_table:
            if not s or s.startswith("errors:"):
                in_table = False; continue
            p = s.split()
            if len(p) >= 5 and p[1] in STATES:
                name, state, r, w, ck = p[0], p[1], p[2], p[3], p[4]
                if state != "ONLINE" and name != pool:
                    d["bad_vdevs"].append((name, state))
                if any(x not in ("0",) for x in (r, w, ck)):
                    d["err_vdevs"].append((name, r, w, ck))
    return d

def zfs_snapshots(ds):
    """[(name, guid, creation_epoch)] oldest->newest for a dataset (non-recursive)."""
    rc, out, _ = run(["zfs", "list", "-Hp", "-t", "snapshot", "-o", "name,guid,creation",
                      "-s", "creation", "-d", "1", ds])
    snaps = []
    if rc == 0:
        for ln in out.splitlines():
            f = ln.split("\t")
            if len(f) == 3:
                snaps.append((f[0], f[1], int(f[2])))
    return snaps

def zfs_props(ds, props):
    rc, out, _ = run(["zfs", "get", "-Hp", "-o", "property,value", ",".join(props), ds])
    d = {}
    if rc == 0:
        for ln in out.splitlines():
            f = ln.split("\t")
            if len(f) == 2:
                d[f[0]] = f[1]
    return d

def newest_age(snaps, now):
    return (now - snaps[-1][2]) if snaps else None

# ---------- adapters ----------
def worst(*sevs):
    order = {"OK": 0, "UNKNOWN": 1, "WARN": 2, "CRIT": 3}
    return max((s for s in sevs if s), key=lambda s: order.get(s, 0), default="OK")

# Built-in thresholds so a minimal targets.yaml (no `defaults:` block, e.g. a fresh vault) still
# works. A user's `defaults:` overrides these key-by-key.
DEFAULT_THRESHOLDS = {
    "repl_warn_h": 28, "repl_crit_h": 50,
    "cap_warn_pct": 85, "cap_crit_pct": 92,
    "scrub_warn_d": 40, "scrub_crit_d": 70,
    "resilver_warn_h": 48,
    "fresh_warn_h": 28, "fresh_crit_h": 50,
}

def th(t, defaults, key):
    return t.get(key, defaults.get(key))

_WHOAMI = None
def _whoami():
    """(user, [groups]) for the agent process, cached. Used to read zfs delegation for THIS user."""
    global _WHOAMI
    if _WHOAMI is None:
        try:
            import getpass; u = getpass.getuser()
        except Exception:
            u = os.environ.get("USER") or ""
        rc, out, _ = run(["id", "-Gn"])
        _WHOAMI = (u, out.split() if rc == 0 else [])
    return _WHOAMI

def zfs_delegated(ds, perm, user, groups=()):
    """True if `user` (or a group they're in, or everyone) holds `perm` on `ds` via `zfs allow` -
    i.e. the user-mode agent can run that zfs verb WITHOUT sudo. Best-effort; False on any doubt."""
    rc, out, _ = run(["zfs", "allow", ds])
    if rc != 0:
        return False
    gset = set(groups)
    for raw in out.splitlines():
        toks = raw.strip().split()
        if len(toks) >= 3 and toks[0] == "user" and toks[1] == user and perm in toks[2].split(","):
            return True
        if len(toks) >= 3 and toks[0] == "group" and toks[1] in gset and perm in toks[2].split(","):
            return True
        if len(toks) >= 2 and toks[0] == "everyone" and perm in toks[1].split(","):
            return True
    return False

def can_sudo(cmd_path):
    """True if the agent user may run cmd_path as root with NO password (a provisioned NOPASSWD rule).
    `sudo -n -l` only QUERIES the policy - it never runs the command, and -n never prompts."""
    rc, _, _ = run(["sudo", "-n", "-l", cmd_path])
    return rc == 0

def adapter_zfs_local(t, defaults, scrub_cad, now, pools):
    ds = t["source"]; pool = ds.split("/")[0]
    st = dict(severity="OK", detail_json=None, last_error=None)
    reasons = []
    scrub_info = {}
    # pool health/capacity (only when the target IS a pool root)
    if ds == pool and pool in pools:
        p = pools[pool]
        st["pool_health"] = p["health"]; st["pool_cap_pct"] = p["cap"]
        if p["health"] != "ONLINE":
            st["severity"] = worst(st["severity"], "CRIT"); reasons.append(f"health={p['health']}")
        cw, cc = th(t, defaults, "cap_warn_pct"), th(t, defaults, "cap_crit_pct")
        if p["cap"] >= cc:
            st["severity"] = worst(st["severity"], "CRIT"); reasons.append(f"cap {p['cap']}%>={cc}")
        elif p["cap"] >= cw:
            st["severity"] = worst(st["severity"], "WARN"); reasons.append(f"cap {p['cap']}%>={cw}")
        # resilver + per-vdev errors (catches the flaky-link/transient-drop class that ZFS self-heals)
        det = zpool_status_detail(pool)
        st["last_resilver_ts"] = det.get("resilver_ts")
        if det["resilver"] == "in_progress":
            st["severity"] = worst(st["severity"], "CRIT"); reasons.append("resilver IN PROGRESS")
        elif det["resilver_ts"]:
            rwh = th(t, defaults, "resilver_warn_h") * 3600
            age = now - det["resilver_ts"]
            if age < rwh:
                st["severity"] = worst(st["severity"], "WARN")
                reasons.append(f"resilvered {age // 3600}h ago (investigate a dropped/flaky disk)")
        if det["bad_vdevs"]:
            st["severity"] = worst(st["severity"], "CRIT")
            reasons.append("vdev not ONLINE: " + ", ".join(f"{n}={s}" for n, s in det["bad_vdevs"]))
        if det["err_vdevs"]:
            st["severity"] = worst(st["severity"], "CRIT")
            reasons.append("vdev I/O errors: " + ", ".join(f"{n}(r{r}/w{w}/c{c})" for n, r, w, c in det["err_vdevs"]))
        # scrub age
        cad = scrub_cad.get(pool, {"warn_d": defaults["scrub_warn_d"], "crit_d": defaults["scrub_crit_d"]})
        line, sepoch = zpool_scrub_ts(pool)
        st["last_scrub_ts"] = sepoch
        if line == "never":
            st["severity"] = worst(st["severity"], "WARN"); reasons.append("never scrubbed")
        elif sepoch:
            age_d = (now - sepoch) // DAY
            if age_d >= cad["crit_d"]:
                st["severity"] = worst(st["severity"], "CRIT"); reasons.append(f"scrub {age_d}d>={cad['crit_d']}")
            elif age_d >= cad["warn_d"]:
                st["severity"] = worst(st["severity"], "WARN"); reasons.append(f"scrub {age_d}d>={cad['warn_d']}")
        # live scrub progress (%, ETA) + bottom-line data-error state, for the pool card + Scrub button
        scrub_info = zpool_scrub_progress(pool)
        errline = scrub_info.get("errors")
        if errline and "No known data errors" not in errline:
            st["severity"] = worst(st["severity"], "CRIT"); reasons.append("data errors: " + errline)
        if scrub_info.get("scrub_errors"):
            st["severity"] = worst(st["severity"], "CRIT")
            reasons.append(f"last scrub found {scrub_info['scrub_errors']} error(s)")
    # dataset props + snapshot freshness
    pr = zfs_props(ds, ["usedbysnapshots", "compressratio", "keystatus"])
    st["usedbysnapshots"] = int(pr["usedbysnapshots"]) if pr.get("usedbysnapshots", "").isdigit() else None
    try:
        st["compressratio"] = float(pr.get("compressratio", "").rstrip("x"))
    except ValueError:
        pass
    st["key_status"] = pr.get("keystatus")
    snaps = zfs_snapshots(ds)
    age = newest_age(snaps, now)
    st["snap_age_src_s"] = age
    if age is not None:
        fw, fc = th(t, defaults, "fresh_warn_h") * 3600, th(t, defaults, "fresh_crit_h") * 3600
        if age >= fc:
            st["severity"] = worst(st["severity"], "CRIT"); reasons.append(f"newest snap {age//3600}h old")
        elif age >= fw:
            st["severity"] = worst(st["severity"], "WARN"); reasons.append(f"newest snap {age//3600}h old")
    elif t.get("note", "").find("not in sanoid") >= 0 or ds != pool:
        # a dataset with no snapshots at all is worth noting (coverage signal)
        reasons.append("no snapshots")
    # Per-target action capabilities so the UI only offers actions this agent can actually perform
    # (snapshot needs zfs delegation; scrub needs a pool root + the provisioned sudo wrapper).
    user, groups = _whoami()
    wrapper = os.environ.get("CAIRN_ZPOOL_WRAPPER", "/opt/cairn/phase1/zpool-scrub.sh")
    _mp, _mperr = _mountpoint(ds)      # file-level recovery (Deleted/Versions/Restore) needs a real mount
    caps = {"snapshot": zfs_delegated(ds, "snapshot", user, groups),
            "scrub": (ds == pool) and can_sudo(wrapper),
            "recoverable": _mperr is None}   # e.g. an unmounted pool (mountpoint=none) can't be browsed
    st["detail_json"] = json.dumps(dict(reasons=reasons, snap_count=len(snaps),
                                        scrub=scrub_info, caps=caps))
    return [st]

def adapter_zfs_repl(t, defaults, now, pools):
    src, dst = t["source"], t["dest"]
    st = dict(severity="OK", last_error=None)
    ssnaps = zfs_snapshots(src); dsnaps = zfs_snapshots(dst)
    st["snap_age_src_s"] = newest_age(ssnaps, now)
    st["snap_age_dst_s"] = newest_age(dsnaps, now)
    reasons = []
    if not ssnaps or not dsnaps:
        dpool = (dst or "").split("/")[0]
        if dpool and dpool not in pools:           # dest pool absent locally: on another host (paired
            reason = f"dest '{dst}' not on this host"   # across the net) or genuinely gone - pairing decides
        elif not dsnaps:
            reason = "dest has no snapshots (replication never ran?)"
        else:
            reason = "src has no snapshots"
        st["severity"] = "UNKNOWN"; st["last_error"] = reason
        st["detail_json"] = json.dumps(dict(reasons=[reason], src_n=len(ssnaps), dst_n=len(dsnaps)))
        return [st]
    dguids = {g for _, g, _ in dsnaps}
    common = [(n, g, c) for (n, g, c) in ssnaps if g in dguids]
    if not common:
        st["severity"] = "CRIT"; st["last_error"] = "no common snapshot (never replicated / diverged)"
        st["detail_json"] = json.dumps(dict(reasons=["no common snapshot"]))
        return [st]
    newest_common = max(common, key=lambda x: x[2])
    lag = now - newest_common[2]
    st["repl_lag_s"] = lag
    rw, rc = th(t, defaults, "repl_warn_h") * 3600, th(t, defaults, "repl_crit_h") * 3600
    if lag >= rc:
        st["severity"] = worst(st["severity"], "CRIT"); reasons.append(f"repl lag {lag//3600}h>={rc//3600}")
    elif lag >= rw:
        st["severity"] = worst(st["severity"], "WARN"); reasons.append(f"repl lag {lag//3600}h>={rw//3600}")
    # encrypted-vault key check: dest must stay 'unavailable' for zero-knowledge targets
    if t.get("encrypted"):
        ks = zfs_props(dst, ["keystatus"]).get("keystatus")
        st["key_status"] = ks
        exp = t.get("vault_keystatus_expected", "unavailable")
        if ks and ks != exp:
            st["severity"] = worst(st["severity"], "CRIT")
            reasons.append(f"dest keystatus={ks} (expected {exp}!)")
    st["detail_json"] = json.dumps(dict(reasons=reasons, common_snap=newest_common[0]))
    return [st]

def adapter_borg(t, defaults, now):
    repo = t["source"]
    st = dict(severity="UNKNOWN", last_error=None)
    if not os.path.isdir(repo):
        st["last_error"] = f"repo path not found: {repo}"; return [st]
    if os.path.exists(os.path.join(repo, "lock.exclusive")):
        st["lock_state"] = "locked"
    env = {}
    pe = t.get("passphrase_env")
    if pe and os.environ.get(pe):
        env["BORG_PASSPHRASE"] = os.environ[pe]
    env["BORG_RELOCATED_REPO_ACCESS_IS_OK"] = "yes"
    # borg 1.4 refuses non-interactive access to an unknown *unencrypted* repo; allow it.
    env["BORG_UNKNOWN_UNENCRYPTED_REPO_ACCESS_IS_OK"] = "yes"
    # keep borg's cache/security dirs on a writable path (repos are often mounted read-only).
    env["BORG_BASE_DIR"] = os.environ.get("BORG_BASE_DIR", "/tmp/borg-base")
    env["BORG_CACHE_DIR"] = os.environ.get("BORG_CACHE_DIR", "/tmp/borg-cache")
    rc, out, err = run(["borg", "info", "--json", "--bypass-lock", repo], timeout=120, env=env)
    if rc != 0:
        lines = [l.strip() for l in (err or out).splitlines() if l.strip()]
        keys = ("Permission denied", "does not exist", "passphrase", "not a valid repository",
                "acquire the lock", "No such file")
        msg = next((l for l in lines if any(k in l for k in keys)), lines[-1] if lines else f"rc={rc}")
        st["last_error"] = (("borg segments unreadable by the agent user - nightly root borg wrote them "
                             "root-only; run grant-access.sh (adds --umask 0027), see AGENT.md")
                            if "Permission denied" in msg else msg)[:170]
        # unreadable/needs-passphrase -> stays UNKNOWN (resolves once the 'backup' group can read)
        return [st]
    try:
        info = json.loads(out)
        cache = info.get("cache", {}).get("stats", {})
        st["logical_size"] = cache.get("total_size")
        st["physical_size"] = cache.get("unique_csize") or cache.get("total_unique_chunks")
        tot, uniq = cache.get("total_size"), cache.get("unique_csize")
        if tot and uniq:
            st["dedup_ratio"] = round(tot / uniq, 2)
        enc = info.get("encryption", {}).get("mode")
        st.setdefault("detail_json", None)
    except (ValueError, KeyError) as e:
        st["last_error"] = f"parse borg info: {e}"; return [st]
    rc2, out2, _ = run(["borg", "list", "--json", "--bypass-lock", "--last", "1", repo], timeout=120, env=env)
    last_ts = None; count = None
    if rc2 == 0:
        try:
            lst = json.loads(out2)
            archives = lst.get("archives", [])
            if archives:
                # borg 'start' like 2026-09-08T01:00:00.000000
                ts = archives[-1].get("start")
                rc3, ep, _ = run(["date", "-d", ts, "+%s"]) if ts else (1, "", "")
                if rc3 == 0:
                    last_ts = int(ep.strip())
        except (ValueError, KeyError):
            pass
    # full archive count
    rc4, out4, _ = run(["borg", "list", "--json", "--bypass-lock", repo], timeout=180, env=env)
    if rc4 == 0:
        try:
            count = len(json.loads(out4).get("archives", []))
        except ValueError:
            pass
    st["archive_count"] = count
    st["last_run_ts"] = last_ts
    st["severity"] = "OK"
    reasons = []
    if last_ts:
        age = now - last_ts
        fw, fc = th(t, defaults, "fresh_warn_h") * 3600, th(t, defaults, "fresh_crit_h") * 3600
        if age >= fc:
            st["severity"] = worst(st["severity"], "CRIT"); reasons.append(f"last archive {age//3600}h old")
        elif age >= fw:
            st["severity"] = worst(st["severity"], "WARN"); reasons.append(f"last archive {age//3600}h old")
    else:
        st["severity"] = "WARN"; reasons.append("no archives / can't read last archive time")
    if st.get("lock_state") == "locked":
        st["severity"] = worst(st["severity"], "WARN"); reasons.append("stale lock.exclusive")
    st["detail_json"] = json.dumps(dict(reasons=reasons, encryption=enc if 'enc' in dir() else None))
    return [st]

def _have(cmd):
    """True if `cmd` is an executable on PATH."""
    return shutil.which(cmd) is not None

def _epoch(s):
    """Parse a date string to unix epoch via `date -d` (handles ISO + snapper's 'YYYY-MM-DD HH:MM:SS')."""
    if not s:
        return None
    rc, ep, _ = run(["date", "-d", s, "+%s"])
    return int(ep.strip()) if rc == 0 and ep.strip().isdigit() else None

def _fresh(st, t, defaults, now, last_ts, noun):
    """Shared freshness verdict: OK/WARN/CRIT off the fresh_warn_h/fresh_crit_h thresholds."""
    reasons = []
    if last_ts:
        st["last_run_ts"] = last_ts
        age = now - last_ts
        fw, fc = th(t, defaults, "fresh_warn_h") * 3600, th(t, defaults, "fresh_crit_h") * 3600
        if age >= fc:
            st["severity"] = worst(st["severity"], "CRIT"); reasons.append(f"{noun} {age//3600}h old")
        elif age >= fw:
            st["severity"] = worst(st["severity"], "WARN"); reasons.append(f"{noun} {age//3600}h old")
    else:
        st["severity"] = worst(st["severity"], "WARN"); reasons.append(f"no {noun} found")
    return reasons

def _errline(err, out, rc):
    lines = [l.strip() for l in ((err or out) or "").splitlines() if l.strip()]
    return (lines[-1] if lines else f"rc={rc}")[:170]

def adapter_restic(t, defaults, now):
    """restic repo: newest snapshot age (freshness) + snapshot count. Repo in `source`; the password
    comes from `passphrase_env` (env var name) or RESTIC_PASSWORD / `password_file`."""
    repo = t["source"]
    st = dict(severity="UNKNOWN", last_error=None)
    if not _have("restic"):
        st["last_error"] = "restic not installed"; return [st]
    env = {"RESTIC_REPOSITORY": repo}
    pe = t.get("passphrase_env") or "RESTIC_PASSWORD"
    if os.environ.get(pe):
        env["RESTIC_PASSWORD"] = os.environ[pe]
    if t.get("password_file"):
        env["RESTIC_PASSWORD_FILE"] = t["password_file"]
    rc, out, err = run(["restic", "snapshots", "--json", "--no-lock"], timeout=180, env=env)
    if rc != 0:
        st["last_error"] = _errline(err, out, rc)   # unreadable / locked / bad password -> UNKNOWN
        return [st]
    try:
        snaps = json.loads(out or "[]")
    except ValueError as e:
        st["last_error"] = f"parse restic snapshots: {e}"; return [st]
    last_ts = _epoch(snaps[-1].get("time")) if snaps else None
    st["archive_count"] = len(snaps)
    st["severity"] = "OK"
    reasons = _fresh(st, t, defaults, now, last_ts, "last snapshot")
    st["detail_json"] = json.dumps(dict(reasons=reasons, tool="restic"))
    return [st]

def adapter_rclone(t, defaults, now):
    """rclone remote: confirm the remote is configured + reachable; optional freshness from a `marker`
    file the sync job touches (rclone keeps no backup-time state of its own). Remote in `source`."""
    remote = t["source"]
    st = dict(severity="UNKNOWN", last_error=None)
    if not _have("rclone"):
        st["last_error"] = "rclone not installed"; return [st]
    rc, out, err = run(["rclone", "lsjson", "--max-depth", "0", remote], timeout=90)
    if rc != 0:
        st["severity"] = "CRIT"; st["last_error"] = f"remote unreachable: {_errline(err, out, rc)}"
        st["detail_json"] = json.dumps(dict(reasons=["remote unreachable"], tool="rclone")); return [st]
    st["severity"] = "OK"
    marker = t.get("marker")
    if marker and os.path.exists(marker):
        reasons = _fresh(st, t, defaults, now, int(os.path.getmtime(marker)), "last sync")
    elif marker:
        st["severity"] = "WARN"; reasons = ["sync marker missing"]
    else:
        reasons = ["remote reachable (no freshness marker configured)"]
    st["detail_json"] = json.dumps(dict(reasons=reasons, tool="rclone"))
    return [st]

# ---------------- removable 2nd-leg (an external drive as the 3-2-1 "2nd media") ----------------
# Monitoring is READ-ONLY and needs NO privilege: it reads /dev/disk/by-* symlinks and the mount
# table only. Backups run on demand via the 'backup-now' action (rsync incremental); absence of the
# drive is a NEUTRAL state, never CRIT (an unplugged 2nd-leg is expected).
def _cairn_state_dir():
    d = os.environ.get("CAIRN_STATE_DIR") or os.path.expanduser("~/.local/state/cairn")
    try:
        os.makedirs(d, exist_ok=True)
    except OSError:
        pass
    return d

def _removable_state_path(t):
    slug = re.sub(r"[^A-Za-z0-9_.-]", "_", str(t.get("name", "x")))
    return os.path.join(_cairn_state_dir(), f"removable-{slug}.json")

def removable_state(t):
    try:
        with open(_removable_state_path(t)) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}

def removable_write_state(t, **kw):
    s = removable_state(t); s.update(kw)
    try:
        with open(_removable_state_path(t), "w") as f:
            json.dump(s, f)
    except OSError:
        pass

def _removable_dest(t):
    """Absolute path the backup writes INTO: <mount>/<dest_subpath>."""
    mount = t.get("mount"); sub = (t.get("dest_subpath") or "").strip("/")
    if not mount:
        return None
    return os.path.join(mount, sub) if sub else mount

def _removable_log_path(t):
    """Persistent rsync log for this removable target - appended each real run so a backup can be
    inspected at any time (long after the intent output scrolled off). Lives off the drive so it
    survives the drive being unplugged."""
    slug = re.sub(r"[^A-Za-z0-9_.-]", "_", str(t.get("name", "x")))
    return os.path.join(_cairn_state_dir(), f"removable-{slug}.rsync.log")

def removable_probe(t):
    """Locate the drive by a STABLE id (fs UUID or /dev/disk/by-id, never /dev/sdX) and read its mount.
    Returns dict(attached, mounted, ro, mount, dev). No root needed."""
    uuid = t.get("uuid"); byid = t.get("by_id"); dev = None
    if uuid and os.path.exists(f"/dev/disk/by-uuid/{uuid}"):
        dev = os.path.realpath(f"/dev/disk/by-uuid/{uuid}")
    elif byid and os.path.exists(f"/dev/disk/by-id/{byid}"):
        dev = os.path.realpath(f"/dev/disk/by-id/{byid}")
    mount = t.get("mount"); mounted = False; ro = False
    if mount:
        rc, out, _ = run(["findmnt", "-nro", "SOURCE,OPTIONS", mount])
        if rc == 0 and out.strip():
            mounted = True
            parts = out.strip().split()
            opts = parts[-1] if parts else ""
            ro = "ro" in opts.split(",")
    return dict(attached=dev is not None, mounted=mounted, ro=ro, mount=mount, dev=dev)

def _removable_last_backup(t, pr):
    """Authoritative last-backup epoch: the on-drive stamp when the drive is present+mounted, else the
    host-side state written on the last successful run."""
    dest = _removable_dest(t)
    if pr["mounted"] and dest:
        stamp = os.path.join(dest, ".cairn-lastbackup")
        try:
            with open(stamp) as f:
                return int(f.read().strip())
        except (OSError, ValueError):
            pass
    return removable_state(t).get("last_backup_ts")

def human_bytes(n):
    """1000-based human size (matches the dashboard's _cap), for result/log messages."""
    n = float(n or 0)
    if n >= 1e12: return f"{n/1e12:.1f} TB"
    if n >= 1e9: return f"{n/1e9:.1f} GB"
    if n >= 1e6: return f"{n/1e6:.0f} MB"
    if n >= 1e3: return f"{n/1e3:.0f} KB"
    return f"{n:.0f} B"

def cairn_subpath(dataset_source, host=None):
    """Where a cairn-managed copy of a dataset lives on a drive: cairn/<host>/<slugged-source>. Every
    cairn-written tree sits under one `cairn/` folder, namespaced by SOURCE HOST (so a drive used on
    two boxes can't collide - cairn/mclife/evo500 vs cairn/other/evo500) then per-dataset (so datasets
    never mix). E.g. host=mclife, source=mcz/mclife/Pics -> cairn/mclife/mcz_mclife_Pics."""
    def _slug(s):
        return re.sub(r"[^A-Za-z0-9._-]+", "_", (s or "").strip("/")).strip("_")
    ds = _slug(dataset_source) or "dataset"
    h = _slug(host)
    return f"cairn/{h}/{ds}" if h else f"cairn/{ds}"

def removable_relocate(mount, from_sub, to_sub):
    """Rename a subtree WITHIN a drive (from_sub -> to_sub) - an intra-filesystem move, so it's an
    instant metadata rename, not a copy. Guards: both paths stay under `mount`, source exists, dest
    does not (never overwrite). Returns (ok, message)."""
    mount = os.path.realpath(mount)
    src = os.path.realpath(os.path.join(mount, (from_sub or "").strip("/")))
    dst = os.path.abspath(os.path.join(mount, (to_sub or "").strip("/")))
    under = lambda p: p == mount or p.startswith(mount + os.sep)
    if not under(src):
        return False, "source escapes the drive"
    if not under(dst):
        return False, "destination escapes the drive"
    if not os.path.isdir(src):
        return False, f"source '{from_sub}' not found on the drive"
    if os.path.exists(dst):
        return False, f"destination '{to_sub}' already exists - not overwriting"
    try:
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        os.rename(src, dst)                     # same filesystem => atomic, no data copy
    except OSError as e:
        return False, f"move failed: {e}"
    # prune the now-empty parent chain left behind (e.g. michlife_backup/ after moving its only child
    # Pics out). os.rmdir only removes an EMPTY dir, so a parent that still holds other things is kept.
    parent = os.path.dirname(src); pruned = 0
    while parent and parent != mount and parent.startswith(mount + os.sep):
        try:
            os.rmdir(parent); pruned += 1
        except OSError:
            break                               # not empty (or can't remove) -> stop climbing
        parent = os.path.dirname(parent)
    return True, (f"moved '{from_sub}' -> '{to_sub}'"
                  + (f" (removed {pruned} empty parent dir(s))" if pruned else ""))

def rsync_census(src, dest, excludes=None, timeout=1800):
    """Dry-run rsync to compare a dataset SOURCE against a drive SUBPATH - the honest diff + fit, with
    NO transfer and NO delete (both -n). dest need not exist (then everything is 'add'). Returns
    (summary, err). summary = counts (add/update/delete/unchanged of `reg_total`), match `pct`,
    `bytes_add` (what a real backup would write), and a few sample itemized lines for a diff view."""
    cmd = ["rsync", "-aHni", "--delete", "--stats", "--dry-run"]
    for ex in (excludes or []):
        cmd += ["--exclude", str(ex)]
    cmd += ["--", src.rstrip("/") + "/", dest.rstrip("/") + "/"]
    rc, out, err = run(cmd, timeout=timeout)
    if rc not in (0, 24):                       # 24 = a source file vanished mid-scan; harmless here
        return None, _errline(err, out, rc)

    def num(pat):
        m = re.search(pat, out)
        return int(m.group(1).replace(",", "")) if m else 0
    reg_total = num(r"Number of files:.*?reg:\s*([\d,]+)")
    transferred = num(r"Number of regular files transferred:\s*([\d,]+)")
    created_reg = num(r"Number of created files:.*?reg:\s*([\d,]+)")
    bytes_add = num(r"Total transferred file size:\s*([\d,]+)")
    deletes = len(re.findall(r"(?m)^\*deleting ", out))
    add = min(created_reg, transferred)
    update = max(transferred - add, 0)
    unchanged = max(reg_total - transferred, 0)
    pct = round(unchanged / reg_total, 4) if reg_total else 0.0
    # Aggregate the (up to 100k+) itemized lines by TOP-LEVEL folder, so the diff is a readable "where
    # is the churn" table instead of an unreadable per-file scroll.
    buckets = {}
    for line in out.splitlines():
        if line.startswith("*deleting"):
            p = line[9:].strip("/ \t"); cat = "delete"
        elif len(line) > 12 and line[1] == "f":            # a file entry: YXcstpoguax<space>path
            p = line[12:]; cat = "add" if set(line[2:11]) <= {"+"} else "update"
        else:
            continue
        top = p.split("/", 1)[0] or "(root)"
        b = buckets.setdefault(top, {"add": 0, "update": 0, "delete": 0})
        b[cat] += 1
    by_folder = sorted(({"folder": k, "add": v["add"], "update": v["update"], "delete": v["delete"]}
                        for k, v in buckets.items()),
                       key=lambda x: -(x["add"] + x["update"] + x["delete"]))
    return {"pct": pct, "reg_total": reg_total, "transfer": transferred, "add": add,
            "update": update, "delete": deletes, "unchanged": unchanged, "bytes_add": bytes_add,
            "folders_total": len(by_folder), "by_folder": by_folder[:40]}, None

def _xattr_hashset(root):
    """Set of full-hash b3sig values (hex, F stripped) under a tree, via cached xattrs. Also returns
    how many files carried NO usable sig (untagged)."""
    hs = set(); untagged = 0
    for r, _d, files in os.walk(root):
        for f in files:
            try:
                s = os.getxattr(os.path.join(r, f), "user.b3sig").decode("ascii", "replace")
            except OSError:
                s = None
            if s and s[:1] == "F":
                hs.add(s[1:])
            else:
                untagged += 1
    return hs, untagged

def drive_tagged_fraction(dest, sample=300):
    """Quick probe: of the first `sample` files on the drive, what fraction carry a b3sig xattr? Used to
    auto-pick the content-verify method - xattrs (free) if the drive is tagged, else a full hash."""
    seen = tagged = 0
    for r, _d, files in os.walk(dest):
        for f in files:
            seen += 1
            try:
                if os.getxattr(os.path.join(r, f), "user.b3sig"):
                    tagged += 1
            except OSError:
                pass
            if seen >= sample:
                return tagged / seen
    return (tagged / seen) if seen else 0.0

def xattr_verify(src, dest, cap=1000000):
    """Tier-2 CONTENT coverage with NO file reads - PATH-INDEPENDENT: is each source file's content
    present ANYWHERE on the drive (by cached b3sig hash)? Ignores reorganization (unlike the path-based
    census). Needs both sides tagged (an -X sync or a hash-ledger apply seeds the drive). `clean` =
    every source file's content is on the drive (a complete copy); `missing`/`missing_bytes` = the true
    content gap; `dest_untagged` flags a drive that isn't hash-tagged yet (=> re-sync with -X)."""
    src = src.rstrip("/"); dest = dest.rstrip("/")
    drive, dest_untagged = _xattr_hashset(dest)
    present = missing = no_src_sig = 0; missing_bytes = 0
    for r, _d, files in os.walk(src):
        for f in files:
            p = os.path.join(r, f)
            try:
                s = os.getxattr(p, "user.b3sig").decode("ascii", "replace")
            except OSError:
                s = None
            if not s or s[:1] != "F":
                no_src_sig += 1; continue
            if s[1:] in drive:
                present += 1
            else:
                missing += 1
                try:
                    missing_bytes += os.path.getsize(p)
                except OSError:
                    pass
    total = present + missing
    pct = round(present / total, 4) if total else 0.0
    clean = missing == 0 and present > 0
    return {"method": "xattr", "present": present, "missing": missing, "missing_bytes": missing_bytes,
            "dest_untagged": dest_untagged, "no_src_sig": no_src_sig, "pct": pct, "clean": clean}, None

def _ledger_path(removable, dataset):
    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", f"{removable}-{dataset}").strip("_")
    return os.path.join(_cairn_state_dir(), f"ledger-{slug}.b3.tsv")

def hash_ledger_verify(src, dest, ledger_path=None, batch=400, timeout=None):
    """Tier-3 DEFINITIVE verify: BLAKE3 every file on the drive (dest) and compare to the source's
    authoritative full-hash b3sig xattr (mcz carries F<hash>). Expensive (reads all bytes) - opt-in,
    NICE-throttled. Writes a durable ledger (F<hash>\\t<relpath>) so the work is reusable. Needs
    `b3sum`. Returns (summary, err). Source sigs that are edge-sigs (Q...) can't be full-compared and
    count as `no_src_sig`."""
    if not _have("b3sum"):
        return None, "b3sum not installed on this host - can't build a full-hash ledger"
    dest = dest.rstrip("/"); src = src.rstrip("/")
    # 1) BLAKE3 every drive file -> the drive's content SET (+ a durable ledger, reusable later).
    rels = [os.path.relpath(os.path.join(r, f), dest) for r, _d, fs in os.walk(dest) for f in fs]
    drive = set(); lines = []
    for i in range(0, len(rels), batch):
        chunk = rels[i:i + batch]
        rc, out, err = run(NICE + ["b3sum", "--"] + [os.path.join(dest, r) for r in chunk],
                           timeout=timeout or 3600)
        hmap = {}
        for line in out.splitlines():
            m = re.match(r"^([0-9a-f]{64})\s{1,2}(.*)$", line)
            if m:
                hmap[m.group(2)] = m.group(1)
        for r in chunk:
            h = hmap.get(os.path.join(dest, r))
            if h:
                drive.add(h); lines.append(f"F{h}\t{r}")
    if ledger_path:
        try:
            with open(ledger_path, "w") as fh:
                fh.write("\n".join(lines) + ("\n" if lines else ""))
        except OSError:
            pass
    # 2) content coverage: is each SOURCE file's content on the drive (path-independent)? Source (mcz)
    #    carries authoritative F<hash> xattrs, so trust those rather than re-reading the source.
    present = missing = no_src_sig = 0; missing_bytes = 0
    for r, _d, files in os.walk(src):
        for f in files:
            p = os.path.join(r, f)
            try:
                s = os.getxattr(p, "user.b3sig").decode("ascii", "replace")
            except OSError:
                s = None
            if not s or s[:1] != "F":
                no_src_sig += 1; continue
            if s[1:] in drive:
                present += 1
            else:
                missing += 1
                try:
                    missing_bytes += os.path.getsize(p)
                except OSError:
                    pass
    total = present + missing
    pct = round(present / total, 4) if total else 0.0
    clean = missing == 0 and present > 0
    return {"method": "hash", "hashed": len(lines), "present": present, "missing": missing,
            "missing_bytes": missing_bytes, "no_src_sig": no_src_sig, "pct": pct, "clean": clean,
            "ledger": ledger_path}, None

def _dir_children(path, cap=1000):
    """Immediate child names of a directory (the cheap structural fingerprint). None if unreadable."""
    try:
        with os.scandir(path) as it:
            out = set()
            for i, e in enumerate(it):
                if i >= cap:
                    break
                out.add(e.name)
            return out
    except OSError:
        return None

def discover_removable_links(mount, datasets, max_depth=3, min_score=0.6, min_children=3, dir_cap=6000):
    """Match subtrees on a removable drive to monitored datasets by DIRECTORY STRUCTURE - comparing
    immediate child-name sets (the rsync / bare-tree case; ZFS matches by snapshot GUID and borg/restic
    by repo metadata, which are exact and handled elsewhere). `datasets` = [{name, path}] where path is
    the dataset's live root (a zfs mountpoint, resolved by the caller). Returns the best match per
    dataset above `min_score`: {dataset, subpath, score, matched, total, added}. READ-ONLY.
      subpath : drive path relative to `mount` ('.' = the mount root itself).
      score   : |drive_children ∩ dataset_children| / |dataset_children| (fuzzy: a stale copy that has
                drifted still matches strongly; exact identity is NOT required).
      added   : dataset children absent from the drive = exactly what a sync would add (the delta)."""
    sigs = []
    for d in datasets:
        c = _dir_children(d["path"]) if d.get("path") else None
        if c and len(c) >= min_children:
            sigs.append((d["name"], c))
    if not sigs:
        return []
    mount = mount.rstrip("/"); base = mount.count(os.sep); best = {}; seen = 0
    for root, dirs, files in os.walk(mount):
        seen += 1
        if seen > dir_cap:
            break
        if (root.count(os.sep) - base) >= max_depth:
            dirs[:] = []                          # don't descend past max_depth
        here = set(dirs) | set(files)
        if len(here) < min_children:
            continue
        for name, sig in sigs:
            inter = len(here & sig); score = inter / len(sig)
            if score >= min_score and inter >= min_children and (
                    name not in best or score > best[name]["score"]):
                best[name] = {"dataset": name, "subpath": os.path.relpath(root, mount),
                              "score": round(score, 3), "matched": inter, "total": len(sig),
                              "added": sorted(sig - here)[:50]}
    return sorted(best.values(), key=lambda r: -r["score"])

def adapter_removable(t, defaults, now):
    """A removable external drive as a 2nd-media leg. Reports PRESENCE + freshness; the actual backup
    runs on demand (see the 'backup-now' action). Absence never escalates past WARN (and only after a
    long grace), so an unplugged drive is a calm 'detached', not a CRIT."""
    tool = t.get("tool", "rsync")
    pr = removable_probe(t)
    last = _removable_last_backup(t, pr)
    detail = dict(tool=tool, removable=True, attached=pr["attached"], mounted=pr["mounted"],
                  mount=pr["mount"], location=t.get("location", "removable"))
    if last:
        detail["last_backup_ts"] = last
    caps = {"backupable": False}
    st = dict(severity="OK", last_error=None, last_run_ts=last)
    reasons = []
    if not pr["attached"]:
        # neutral detached state; only nudge WARN after a long grace since the last backup
        if last:
            age_d = (now - last) // 86400
            reasons.append(f"detached · last backup {age_d}d ago")
            dw = int(t.get("detach_warn_d", defaults.get("removable_detach_warn_d", 45)))
            if age_d >= dw:
                st["severity"] = "WARN"; reasons.append(f"over {dw}d - attach it to refresh the 2nd copy")
        else:
            reasons.append("detached · never backed up by cairn")
        st["detail_json"] = json.dumps(dict(detail, reasons=reasons, caps=caps)); return [st]
    if not pr["mounted"]:
        st["severity"] = "WARN"; reasons.append(f"attached but not mounted at {pr['mount']}")
        st["detail_json"] = json.dumps(dict(detail, reasons=reasons, caps=caps)); return [st]
    try:                                        # drive capacity, for the fit ("will it hold X?") check
        sv = os.statvfs(pr["mount"])
        detail["free_bytes"] = sv.f_bavail * sv.f_frsize
        detail["total_bytes"] = sv.f_blocks * sv.f_frsize
    except OSError:
        pass
    try:                                        # is the drive hash-tagged? (lets the UI warn before a
        detail["tagged"] = round(drive_tagged_fraction(pr["mount"]), 3)   # slow full-hash verify)
    except OSError:
        pass
    reasons.append("attached (read-only)" if pr["ro"] else "attached")
    if pr["ro"]:
        st["severity"] = worst(st["severity"], "WARN"); reasons.append("mounted READ-ONLY - remount rw to back up")
    else:
        caps["backupable"] = True
    reasons += _fresh(st, t, defaults, now, last, "last backup")
    st["detail_json"] = json.dumps(dict(detail, reasons=reasons, caps=caps))
    return [st]

def adapter_snapper(t, defaults, now):
    """snapper (btrfs) config: newest snapshot age (freshness) + count. Config name in `source`
    (e.g. root, home). Uses snapper --jsonout (0.10+); needs read access to the config."""
    cfg = t["source"]
    st = dict(severity="UNKNOWN", last_error=None)
    if not _have("snapper"):
        st["last_error"] = "snapper not installed"; return [st]
    rc, out, err = run(["snapper", "--jsonout", "-c", cfg, "list"], timeout=60)
    if rc != 0:
        st["last_error"] = (f"needs permission for config '{cfg}'"
                            if "permission" in (err or "").lower() else _errline(err, out, rc))
        return [st]
    try:
        data = json.loads(out or "{}")
        snaps = data.get(cfg) if isinstance(data, dict) else (data or [])
        if snaps is None and isinstance(data, dict) and data:
            snaps = next(iter(data.values()))
        snaps = [s for s in (snaps or []) if s.get("number")]   # skip snapshot 0 (the live subvolume)
    except (ValueError, StopIteration):
        st["last_error"] = "parse snapper --jsonout"; return [st]
    last_ts = _epoch(snaps[-1].get("date")) if snaps else None   # jsonout list is chronological
    st["archive_count"] = len(snaps)
    st["severity"] = "OK"
    reasons = _fresh(st, t, defaults, now, last_ts, "newest snapshot")
    st["detail_json"] = json.dumps(dict(reasons=reasons, tool="snapper", config=cfg))
    return [st]

def adapter_kernel_errors(t, defaults, now):
    """Scan the recent kernel log for disk I/O / link-reset / HBA-storm errors. This is the ONLY
    durable evidence when ZFS self-heals a transient (0B resilver, counters cleared) - e.g. a brief
    disk link reset that leaves the pool ONLINE. Source: `journalctl -k` if available (host agent), else a plain-text
    kernel log (rsyslog /var/log/kern.log or /var/log/syslog) - mount it ro into a container."""
    win = int(t.get("window_h", 24))
    lines, source = None, None
    # 1) journalctl (host agent, or a container with journalctl + /var/log/journal mounted)
    rc, out, err = run(["journalctl", "-k", "--since", f"-{win}h", "--no-pager"], timeout=60)
    if rc == 0 and out:
        lines, source = out.splitlines(), f"journalctl -k (last {win}h)"
    else:
        # 2) plain-text kernel log fallback (rsyslog) - mount it ro; container root reads it.
        cands = ([t["log_file"]] if t.get("log_file") else []) + ["/var/log/kern.log", "/var/log/syslog"]
        for f in cands:
            if f and os.path.isfile(f):
                try:
                    lines = Path(f).read_text(errors="replace").splitlines()[-20000:]
                    source = f"{f} (current file)"
                    break
                except OSError:
                    continue
    if lines is None:
        return [dict(severity="UNKNOWN",
                     last_error="no kernel log source: install journalctl + mount /var/log/journal, "
                                "or mount a plain-text /var/log/kern.log (rsyslog)")]
    hard = re.compile(r"I/O error|hard resetting link|exception Emask|failed command|"
                      r"medium error|Unrecovered read error|ATA bus error|"
                      r"link is slow to respond|READ FPDMA|WRITE FPDMA|offline uncorrect", re.I)
    rescan = re.compile(r"scsi \d+:\d+:\d+:\d+: .*(atapi|Direct-Access)|rejecting I/O to offline device", re.I)
    hits = [l for l in lines if hard.search(l)]
    rescans = sum(1 for l in lines if rescan.search(l))
    # which devices? pull /dev/sdX mentions from the error lines
    devs = sorted({m.group(0) for l in hits for m in re.finditer(r"sd[a-z]+", l)})
    st = dict(severity="OK",
              detail_json=json.dumps(dict(source=source, window_h=win, errors=len(hits),
                                          rescans=rescans, devices=devs, sample=hits[-3:])))
    crit_n = int(t.get("crit_count", 10))
    if len(hits) >= crit_n:
        st["severity"] = "CRIT"; st["last_error"] = f"{len(hits)} disk/link errors in {win}h ({','.join(devs)})"
    elif hits:
        st["severity"] = "WARN"; st["last_error"] = f"{len(hits)} disk/link error(s) in {win}h ({','.join(devs)})"
    elif rescans >= int(t.get("rescan_storm", 20)):
        st["severity"] = "WARN"; st["last_error"] = f"HBA rescan storm: {rescans} target rescans in {win}h"
    return [st]

def adapter_zfs_events(t, defaults, now):
    """A ZFS event timeline from zed's journal (the all-syslog.sh zedlet). Portable: needs only a
    default OpenZFS + systemd box, no custom script. Lists recent pool events (scrub/resilver,
    vdev state changes, checksum/io/data errors) and warns on genuinely bad ones in a recent window.
    Complements kernel-disk-errors (which sees SCSI/HBA-layer faults zed cannot)."""
    win = int(t.get("window_h", 168))          # timeline span (default 7d)
    alert_h = int(t.get("alert_h", 48))         # only recent bad events drive severity
    days = max(1, win // 24)
    rc, o, _ = run(["journalctl", "-t", "zed", "--since", f"{win} hours ago",
                    "-o", "short-unix", "--no-pager", "-q"])
    events = []
    for ln in o.splitlines():
        if "class=" not in ln:
            continue
        mt = re.match(r"(\d+)(?:\.\d+)?\s", ln)
        ts = int(mt.group(1)) if mt else 0
        def g(pat):
            m = re.search(pat, ln)
            return m.group(1) if m else None
        cls = (g(r"class=(\S+)") or "").split(".")[-1]
        if not cls or cls == "history_event":
            continue
        events.append(dict(ts=ts, cls=cls, pool=g(r"pool='([^']+)'"), vdev=g(r"vdev=(\S+)"),
                           vstate=g(r"vdev_state=(\S+)"), pstate=g(r"pool_state=(\S+)"),
                           err=g(r"\berr=(\d+)"), delay=g(r"delay=(\d+)ms")))
    st = dict(severity="OK", name_suffix="zed", last_error=None)
    if not events:
        st["detail_json"] = json.dumps({"label": "ZFS events (zed)", "log_label": "ZFS events",
                                        "summary": f"no ZFS events in {days}d"})
        return [st]
    # Severity reflects CURRENT concern, not historical churn: a vdev that flapped but ended ONLINE
    # is resolved (and the pool's resilver-WARN already flagged it) - don't re-alert on the history.
    sev, reasons, recent = "OK", [], now - alert_h * 3600
    latest_vstate = {}
    for e in sorted(events, key=lambda x: x["ts"]):
        if "statechange" in e["cls"] and e.get("vstate"):
            latest_vstate[(e.get("pool"), e.get("vdev"))] = (e["vstate"].upper(), e["ts"])
    for (pool, vdev), (vs, ts) in latest_vstate.items():
        if ts < recent:
            continue                                   # the net-current state settled outside the window
        if vs in ("FAULTED", "UNAVAIL", "REMOVED"):
            sev = worst(sev, "CRIT"); reasons.append(f"{vdev or '?'} {vs} on {pool or '?'}")
        elif vs == "DEGRADED":
            sev = worst(sev, "WARN"); reasons.append(f"{vdev or '?'} DEGRADED on {pool or '?'}")
    for e in events:                                   # corruption / latency signals in the window
        if e["ts"] >= recent and e["cls"] in ("checksum", "io", "data", "deadman", "delay", "io_failure"):
            sev = worst(sev, "WARN")
            t = f"{e['cls']} on {e.get('pool') or '?'}" + (f" vdev={e['vdev']}" if e.get("vdev") else "")
            reasons.append(t + (f" err={e['err']}" if e.get("err") else ""))
        if e["ts"] >= recent and (e.get("pstate") or "").upper() in ("SUSPENDED", "FAULTED"):
            sev = worst(sev, "CRIT"); reasons.append(f"pool {e.get('pool') or '?'} {e['pstate']}")
    st["severity"] = sev
    if reasons:
        st["last_error"] = "; ".join(dict.fromkeys(reasons))[:300]
    def _fmt(e):
        when = time.strftime("%m-%d %H:%M", time.localtime(e["ts"])) if e["ts"] else "?"
        bits = [when, e["cls"]]
        if e.get("pool"):   bits.append(e["pool"])
        if e.get("vdev"):   bits.append(f"vdev={e['vdev']}")
        if e.get("vstate"): bits.append(e["vstate"])
        if e.get("err"):    bits.append(f"err={e['err']}")
        if e.get("delay"):  bits.append(f"delay={e['delay']}ms")
        return "  ".join(bits)
    timeline = [_fmt(e) for e in sorted(events, key=lambda x: x["ts"], reverse=True)][:40]
    st["detail_json"] = json.dumps({"label": "ZFS events (zed)", "log_label": "ZFS events",
                                    "summary": f"{len(events)} event(s) in {days}d", "journal": timeline})
    return [st]

def _sd_show(unit, props):
    rc, o, _ = run(["systemctl", "show", unit, "-p", ",".join(props)])
    d = {}
    for ln in o.splitlines():
        if "=" in ln:
            k, v = ln.split("=", 1)
            d[k] = v.strip()
    return d

def _sd_epoch(ts):
    """systemd prints timestamps like 'Mon 2026-09-07 00:00:04 MDT' - turn one into epoch secs."""
    if not ts or ts in ("n/a", "0"):
        return None
    rc, o, _ = run(["date", "-d", ts, "+%s"])
    return int(o.strip()) if rc == 0 and o.strip().lstrip("-").isdigit() else None

def _pretty_cal(c):
    if not c:
        return None
    c = c.strip()
    if c in ("weekly", "daily", "hourly", "monthly", "yearly"):
        return c
    m = re.fullmatch(r"\*:0?/(\d+)", c)
    if m:
        return f"every {m.group(1)} min"
    m = re.fullmatch(r"\*-\*-\* (\d\d):(\d\d)(?::\d\d)?", c)
    if m:
        return f"daily {m.group(1)}:{m.group(2)}"
    return c

def _timer_oncalendar(timer):
    rc, o, _ = run(["systemctl", "cat", timer])
    for ln in o.splitlines():
        s = ln.strip()
        if s.startswith("#"):
            continue
        m = re.match(r"OnCalendar=(.+)", s)
        if m:
            return m.group(1).strip()
    return None

def _syncoid_pairs():
    rc, o, _ = run(["systemctl", "cat", "syncoid.service"])
    pairs = []
    for ln in o.splitlines():
        m = re.search(r"ExecStart=-?\S*syncoid\s+(\S+)\s+(\S+)", ln)
        if m and not m.group(1).startswith("-"):
            pairs.append((m.group(1), m.group(2)))
    return pairs

def _journal_lines(args, n=200):
    rc, o, _ = run(["journalctl", "-o", "cat", "--no-pager", "-q", "-n", str(n)] + args)
    return o.splitlines() if rc == 0 else []

def _last_run_journal(service):
    """Just the most recent invocation of a service (via its systemd InvocationID), so we show
    THIS run's failure - not lines bleeding in from older runs. Falls back to a tail by unit."""
    inv = _sd_show(service, ["InvocationID"]).get("InvocationID")
    if inv:
        ls = _journal_lines([f"_SYSTEMD_INVOCATION_ID={inv}"], 400)
        if ls:
            return ls
    return _journal_lines(["-u", service], 80)

_ERRPAT = re.compile(r"\b(CRITICAL|ERROR|Error|Fatal|FATAL|FAILED|failed|cannot|warning|WARN|denied|refused)\b")
def _error_lines(lines):
    seen, out = set(), []
    for l in lines:
        s = l.strip()
        if s and _ERRPAT.search(s) and s not in seen:
            seen.add(s); out.append(s)
    return out

def adapter_schedules(t, defaults, now):
    """Surface the systemd-timer backup jobs (syncoid replication, sanoid snapshots) as
    scheduled-job cards: WHAT each backs up + its schedule + next/last run. All readable
    without root (systemctl show/cat). Add/adjust units via the target's `units:` list."""
    specs = t.get("units") or [
        {"kind": "syncoid", "timer": "syncoid.timer", "service": "syncoid.service", "label": "ZFS replication (syncoid)"},
        {"kind": "sanoid",  "timer": "sanoid.timer",  "service": "sanoid.service",  "label": "ZFS snapshots (sanoid)"},
    ]
    out = []
    for sp in specs:
        tp = _sd_show(sp["timer"], ["ActiveState", "UnitFileState", "NextElapseUSecRealtime",
                                    "LastTriggerUSec", "Result"])
        if not tp.get("UnitFileState") and not tp.get("ActiveState"):
            continue                                   # timer not installed on this host
        st = dict(severity="OK", name_suffix=sp["kind"], last_error=None)
        detail = {"label": sp["label"],
                  "schedule": _pretty_cal(_timer_oncalendar(sp["timer"])) or "(schedule unknown)",
                  "next_ts": _sd_epoch(tp.get("NextElapseUSecRealtime")),
                  "last_ts": _sd_epoch(tp.get("LastTriggerUSec"))}
        st["last_run_ts"] = detail["last_ts"]
        if sp["kind"] == "syncoid":
            pairs = _syncoid_pairs()
            detail["backs_up"] = ", ".join(f"{s} → {d}" for s, d in pairs) or "(no syncoid jobs configured)"
            sv = _sd_show(sp["service"], ["Result", "ExecMainStatus"])
            # ExecStart uses a '-' prefix so the timer stays 'success' even when syncoid itself errors -
            # surface a non-zero last exit as a warning, since it means a replication run had problems.
            if sv.get("ExecMainStatus") not in (None, "", "0"):
                st["severity"] = worst(st["severity"], "WARN")
                st["last_error"] = f"last run exited status {sv['ExecMainStatus']}"
        else:
            detail["backs_up"] = "ZFS snapshots per sanoid.conf"
        # pull the actual failure text from THIS run's journal (portable: journalctl, no custom log)
        if sp.get("service"):
            errs = _error_lines(_last_run_journal(sp["service"]))
            if errs:
                spec = [e for e in errs if re.search(r"CRITICAL|ERROR|Fatal|FATAL|FAILED|denied|refused", e)]
                warns = [e for e in errs if e not in spec]      # lead with real errors, then warnings
                keep = (spec + warns) if len(spec + warns) <= 20 else \
                    spec[:12] + warns[:6] + [f"… +{len(spec + warns) - 18} more line(s)"]
                detail["journal"] = keep
                if st["severity"] != "OK":                      # replace the vague exit code with the real reason
                    pick = (spec or errs)[:2]
                    st["last_error"] = "; ".join(x[:160] for x in pick)[:340]
        ufs = tp.get("UnitFileState")
        if ufs and ufs not in ("enabled", "enabled-runtime", "static"):
            st["severity"] = worst(st["severity"], "WARN")
            st["last_error"] = f"timer {ufs}"
        if tp.get("Result") not in (None, "", "success"):
            st["severity"] = worst(st["severity"], "WARN")
            st["last_error"] = f"timer result {tp.get('Result')}"
        st["detail_json"] = json.dumps(detail)
        out.append(st)
    if not out:
        return [dict(severity="UNKNOWN", last_error="no schedule timers found (syncoid/sanoid absent)")]
    return out

# Non-handler files that may appear beside real backupninja handlers (or in its error log): editor
# swap/backup files, package-manager leftovers, and this project's own *.bm-bak handler backups.
_BN_JUNK = re.compile(r"(\.bm-bak|\.bak|\.orig|\.tmp|\.disabled|\.save|\.swp|"
                      r"\.dpkg-(old|new|dist)|\.rpm(save|new|orig)|~)$", re.I)

def adapter_backupninja(t, defaults, now):
    """One status per handler, parsed from the log + reports dir (both adm-readable) so this
    works in user mode WITHOUT reading /etc/backup.d (root 0750, may hold DB passwords)."""
    cfgdir = Path(t["source"]); logf = Path(t.get("log", "/var/log/backupninja.log"))
    reportsdir = Path(t.get("reports", "/var/lib/backupninja/reports"))
    out = []
    logtxt = ""
    try:
        if logf.is_file():
            logtxt = logf.read_text(errors="replace")
    except PermissionError:
        pass
    # Enumerate handlers WITHOUT /etc/backup.d: prefer reports dir, else parse the log,
    # else fall back to /etc/backup.d if we happen to be able to read it (root mode).
    handlers = []
    try:
        if reportsdir.is_dir():
            handlers = sorted({p.name for p in reportsdir.iterdir() if p.is_file()})
    except PermissionError:
        pass
    if not handlers and logtxt:
        handlers = sorted({m.rstrip(".:") for m in re.findall(r"/etc/backup\.d/([\w.+-]+)", logtxt)})
    if not handlers:
        try:
            handlers = [p.name for p in sorted(cfgdir.iterdir())
                        if p.is_file() and not p.name.startswith(".") and not p.name.endswith(".disabled")]
        except (PermissionError, FileNotFoundError):
            return [dict(severity="UNKNOWN",
                         last_error="no handlers (log/reports unreadable; need adm group)")]
    # Drop non-handler files that can leak in via log-parsing: editor/package/backup junk (e.g. a
    # *.bm-bak that backupninja itself rejects). Real handlers are <NN>.<type>, never these suffixes.
    handlers = [h for h in handlers if not h.startswith(".")
                and not _BN_JUNK.search(h)]
    for h in handlers:
        htype = h.split(".")[-1]
        st = dict(severity="UNKNOWN", handler_type=htype, name_suffix=h, last_error=None)
        # backupninja logs lines like: "<ts> Info: Finished action /etc/backup.d/<h>."
        # and "Fatal:" / "Warning:" per handler. Grab last mention.
        mentions = [ln for ln in logtxt.splitlines() if h in ln]
        if mentions:
            last = mentions[-1]
            m = re.match(r"([A-Z][a-z]{2}\s+\d+\s+[\d:]+)", last) or re.match(r"(\d{4}-\d\d-\d\d[ T][\d:]+)", last)
            if m:
                rc, ep, _ = run(["date", "-d", m.group(1), "+%s"])
                if rc == 0:
                    st["last_run_ts"] = int(ep.strip())
            low = last.lower()
            if "fatal" in low:
                st["severity"], st["handler_result"] = "CRIT", "fatal"
            elif "warning" in low:
                st["severity"], st["handler_result"] = "WARN", "warning"
            elif "finished" in low or "info" in low:
                st["severity"], st["handler_result"] = "OK", "ok"
        detail = {}
        # schedule: backupninja logs "(because current time matches <when>)" on each handler's
        # "starting action" line - the effective schedule, without reading the root-only config.
        for ln in reversed(mentions):
            if "starting action" not in ln:
                continue
            ms = re.search(r"because current time matches ([^)]+)\)", ln)
            if ms:
                detail["schedule"] = ms.group(1).strip(); break
        jcfg = (t.get("jobs") or {}).get(h) or {}
        if jcfg.get("schedule"):
            detail["schedule"] = jcfg["schedule"]
        elif "schedule" not in detail and t.get("schedule"):
            detail["schedule"] = t["schedule"]
        # what it backs up: explicit config label wins; else scrape the repo path from the log if present
        if jcfg.get("backs_up"):
            detail["backs_up"] = jcfg["backs_up"]
        else:
            for ln in reversed(mentions):
                mr = re.search(r"[Rr]epository:\s*(\S+)", ln)
                if mr and "/" in mr.group(1):
                    detail["backs_up"] = mr.group(1); break
        # Surface the ACTUAL warning/error text from this handler's last run block, not just the
        # "finished ...: WARNING" bookkeeping line. (backupninja collapses a handler's multi-line
        # output onto single Warning:/Error: log lines, e.g. borg's "file changed while we backed
        # it up" for a live DB file.)
        if st.get("handler_result") in ("warning", "fatal"):
            lines = logtxt.splitlines()
            starts = [i for i, l in enumerate(lines) if "starting action" in l and h in l]
            if starts:
                s = starts[-1]
                ends = [i for i, l in enumerate(lines) if i > s and "finished action" in l and h in l]
                e = ends[0] if ends else len(lines) - 1
                msgs, seen = [], set()
                for l in lines[s:e + 1]:
                    ll = l.lower()
                    if "starting action" in ll or "finished action" in ll:
                        continue
                    m2 = re.search(r"\b(?:Warning|Error|Fatal):\s*(.+)", l)
                    if not m2:
                        continue
                    txt = re.split(r"\s-{3,}", m2.group(1).strip())[0].strip()[:200]  # trim borg's ---- summary
                    if txt and txt not in seen:
                        seen.add(txt); msgs.append(txt)
                specific = [m for m in msgs if "finished with warnings" not in m.lower()]
                use = (specific or msgs)[:4]   # prefer the specific message over the generic tail
                if use:
                    detail["reasons"] = use
                    detail["journal"] = use          # feed the collapsible "Job log" on the card
                    st["last_error"] = "; ".join(use)[:400]
        # freshness (daily schedule)
        if st.get("last_run_ts"):
            age = now - st["last_run_ts"]
            fw, fc = th(t, defaults, "fresh_warn_h") * 3600, th(t, defaults, "fresh_crit_h") * 3600
            if age >= fc:
                st["severity"] = worst(st["severity"], "CRIT")
            elif age >= fw:
                st["severity"] = worst(st["severity"], "WARN")
        # DB dumps are higher-consequence
        if htype in ("mysql", "pgsql") and st["severity"] in ("CRIT", "WARN"):
            detail["note"] = "DB dump - app-consistent backup at risk"
        if detail:
            st["detail_json"] = json.dumps(detail)
        out.append(st)
    if not out:
        out = [dict(severity="UNKNOWN", last_error="no handlers enumerated")]
    return out

def _smart_cache_path():
    d = os.environ.get("CAIRN_SMART_CACHE", os.path.expanduser("~/.cache/cairn"))
    return os.path.join(d, "smart-cache.json")

def _disk_byid(dev):
    """Stable per-drive identity from /dev/disk/by-id. A /dev/sdX letter is NOT stable - it shifts when
    disks are added/removed/reordered (that's what produced phantom smart:sdk/sdm rows after a reseat) -
    and it collides across hosts (every box has an sda). A by-id encodes model+serial: stable across
    reboots and globally unique. Prefer a readable model_serial 'ata-'/'nvme-' id; fall back to wwn,
    then scsi, then the bare device name if by-id is unavailable."""
    bydir = "/dev/disk/by-id"
    try:
        target = os.path.realpath(dev)
        cands = []
        for nm in os.listdir(bydir):
            if re.search(r"-part\d+$", nm):
                continue
            try:
                if os.path.realpath(os.path.join(bydir, nm)) == target:
                    cands.append(nm)
            except OSError:
                continue
    except OSError:
        return os.path.basename(dev)
    if not cands:
        return os.path.basename(dev)
    def rank(nm):
        if nm.startswith("nvme-eui."):                       return 5   # cryptic, last resort for nvme
        if nm.startswith(("ata-", "nvme-")):                 return 0   # model_serial, readable + stable
        if nm.startswith("wwn-"):                            return 3
        if nm.startswith(("scsi-SATA_", "scsi-1ATA_")):      return 2
        if nm.startswith("scsi-"):                           return 4
        return 6
    return sorted(cands, key=lambda nm: (rank(nm), len(nm)))[0]

def _smart_parse(dev, typ, o, err, now):
    """Normalize one smartctl -a JSON blob (ATA / NVMe / SCSI) into a status dict whose
    detail_json carries identity, key stats, and the full attribute table for the drive view."""
    st = dict(severity="UNKNOWN", name_suffix=_disk_byid(dev), last_error=None)
    try:
        d = json.loads(o)
    except ValueError:
        st["last_error"] = ((err or o).strip().splitlines()[-1] if (err or o) else "no json")[:120]
        return st
    if isinstance(d.get("error"), str):
        st["last_error"] = d["error"][:120]; return st
    proto = (d.get("device") or {}).get("protocol") or ""
    passed = (d.get("smart_status") or {}).get("passed")
    temp = (d.get("temperature") or {}).get("current")
    poh = (d.get("power_on_time") or {}).get("hours")
    cycles = d.get("power_cycle_count")
    cap = (d.get("user_capacity") or {}).get("bytes") or d.get("nvme_total_capacity")
    rot = d.get("rotation_rate")            # 0 => SSD
    realloc = pending = offline_unc = crc = pct_used = None
    attrs = []
    for a in (d.get("ata_smart_attributes") or {}).get("table", []):
        aid = a.get("id"); raw = a.get("raw") or {}
        rawv = raw.get("value"); raws = raw.get("string")
        attrs.append(dict(id=aid, name=a.get("name"), value=a.get("value"), worst=a.get("worst"),
                          thresh=a.get("thresh"), raw=(raws if raws is not None else rawv),
                          when_failed=a.get("when_failed")))
        if aid == 5:   realloc = rawv
        if aid == 197: pending = rawv
        if aid == 198: offline_unc = rawv
        if aid == 199: crc = rawv           # UDMA CRC = cable/link/backplane, not disk surface
        if aid in (231, 177, 202, 233) and pct_used is None and isinstance(a.get("value"), int):
            pct_used = max(0, 100 - a["value"])     # SSD wear/life-left → % used (best-effort)
    nl = d.get("nvme_smart_health_information_log") or {}
    if nl:
        pct_used = nl.get("percentage_used", pct_used)
        if temp is None:   temp = nl.get("temperature")
        if poh is None:    poh = nl.get("power_on_hours")
        if cycles is None: cycles = nl.get("power_cycles")
        for k in ("critical_warning", "available_spare", "available_spare_threshold",
                  "percentage_used", "media_errors", "num_err_log_entries", "unsafe_shutdowns",
                  "data_units_written", "data_units_read", "controller_busy_time",
                  "warning_temp_time", "critical_comp_time"):
            if k in nl:
                attrs.append(dict(id=None, name=k, value=None, worst=None, thresh=None,
                                  raw=nl[k], when_failed=None))
    if passed is True:
        st["severity"] = "OK"
    elif passed is False:
        st["severity"] = "CRIT"; st["last_error"] = "SMART health FAILED"
    else:
        st["last_error"] = "no smart_status (needs root/sudo - grant smartctl sudoers)"
    if realloc or pending or offline_unc:
        st["severity"] = worst(st["severity"], "WARN")
        st["last_error"] = f"reallocated={realloc} pending={pending} offline_uncorrectable={offline_unc}"
    if crc:
        st["severity"] = worst(st["severity"], "WARN")
        st["last_error"] = f"UDMA CRC errors={crc} (cable/backplane/HBA link - not disk surface)"
    if nl.get("critical_warning"):
        st["severity"] = worst(st["severity"], "WARN")
        st["last_error"] = f"NVMe critical_warning={nl['critical_warning']}"
    sp, spt = nl.get("available_spare"), nl.get("available_spare_threshold")
    if sp is not None and spt is not None and sp <= spt:
        st["severity"] = worst(st["severity"], "WARN")
        st["last_error"] = f"NVMe available spare {sp}% ≤ threshold {spt}%"
    if pct_used is not None and pct_used >= 90:
        st["severity"] = worst(st["severity"], "WARN")
        st["last_error"] = ((st["last_error"] + " · ") if st["last_error"] else "") + f"SSD life {pct_used}% used"
    st["detail_json"] = json.dumps(dict(
        passed=passed, proto=proto,
        model=(d.get("model_name") or d.get("model_family") or d.get("scsi_model_name")),
        serial=d.get("serial_number"), firmware=d.get("firmware_version"),
        capacity=cap, rotation=rot, is_ssd=(rot == 0) or proto.upper() == "NVME",
        temp=temp, power_on_hours=poh, power_cycles=cycles, pct_used=pct_used,
        realloc=realloc, pending=pending, offline_unc=offline_unc, crc=crc,
        dev=dev, typ=typ, attrs=attrs, probed_ts=now))
    return st

def _smart_bare(st):
    """True if a probe didn't decode the drive's full ATA identity + attribute table - so we should
    try another device type. UNKNOWN (JSON failed), or a parsed blob missing the model or the
    attribute table (what `-d scsi` yields for a SATA disk behind an HBA: at best a bare health bit,
    no model and no attributes)."""
    if st.get("severity") == "UNKNOWN":
        return True
    try:
        d = json.loads(st.get("detail_json") or "{}")
    except ValueError:
        return True
    return not d.get("model") or not d.get("attrs")

def _smart_probe_all(now):
    rc, out, _ = run(["smartctl", "--scan"])
    devs = []
    for ln in out.splitlines():
        m = re.match(r"(/dev/\S+)\s+-d\s+(\S+)", ln)
        if m:
            devs.append((m.group(1), m.group(2)))
    if not devs:
        return [dict(severity="UNKNOWN", last_error="smartctl --scan found no devices")]
    is_root = os.geteuid() == 0
    # Non-root reads go through a root-OWNED wrapper that sudoers pins by absolute path - never the
    # user-writable repo copy (sudo-ing an editable script would be an escalation hole). grant-access.sh
    # deploys it to /opt; override with CAIRN_SMART_WRAPPER if you installed elsewhere.
    wrapper = os.environ.get("CAIRN_SMART_WRAPPER", "/opt/cairn/phase1/smart-probe.sh")

    def _read(dev, typ):
        cmd = (["smartctl", "-j", "-a", "-d", typ, dev] if is_root
               else ["sudo", "-n", wrapper, dev, typ])
        rc, o, err = run(cmd, timeout=30)
        return _smart_parse(dev, typ, o, err, now)

    results = []
    for dev, typ in devs:
        st = _read(dev, typ)
        # SATA disks behind a SAS/HBA controller enumerate as `-d scsi`, which can't decode ATA SMART
        # (no model, no health, no attributes). Retry once through SAT translation, which does.
        if typ not in ("sat", "nvme") and _smart_bare(st):
            st2 = _read(dev, "sat")
            if not _smart_bare(st2):
                st = st2
        results.append(st)
    return results

def _smartd_alerts(window_h=72):
    """Real-time SMART alerts from smartd's journal - the PORTABLE source (systemd + smartmontools,
    no custom wrapper), and free: smartd already polls every drive ~every 30 min, so reading its log
    costs zero extra drive access. Returns {device_basename: {sev, msgs, ts}}."""
    rc, o, _ = run(["journalctl", "-u", "smartd", "--since", f"{window_h} hours ago",
                    "-o", "short-unix", "--no-pager", "-q"])
    if rc != 0 or not o.strip():
        rc, o, _ = run(["journalctl", "-t", "smartd", "--since", f"{window_h} hours ago",
                        "-o", "short-unix", "--no-pager", "-q"])
    alerts = {}
    for ln in o.splitlines():
        mt = re.match(r"(\d+)(?:\.\d+)?\s", ln)
        ts = int(mt.group(1)) if mt else 0
        m = re.search(r"Device:\s*(/dev/\S+?)(?:\s*\[[^\]]*\])?,\s*(.+?)\s*$", ln)
        if not m:
            continue
        dev, msg = m.group(1), m.group(2).strip()
        low = msg.lower()
        # Skip the non-fault chatter smartd emits: self-test SUCCESS notices ("completed without
        # error") and attribute trend TRACKING ("... changed from A to B", e.g. Seagate
        # Raw_Read_Error_Rate, which fluctuates normally). Alert only on genuine failures.
        if "without error" in low or "completed without" in low or "no error" in low:
            continue
        if "changed" in low:
            continue
        if "failed smart" in low or "back up data now" in low:
            sev = "CRIT"
        elif re.search(r"currently unreadable|pending sector|offline uncorrectable|uncorrectable sector|"
                       r"error count increased|below threshold|failing_now|failing now|read failure|"
                       r"self-test.*(failed|failure)", low):
            sev = "WARN"
        else:
            continue
        # smartd names disks by their config path (often /dev/disk/by-id/...); resolve to the same
        # /dev/sdX basename our cards use so the alert attaches to the right drive.
        try:
            key = os.path.basename(os.path.realpath(dev))
        except OSError:
            key = os.path.basename(dev)
        a = alerts.setdefault(key, {"sev": "OK", "msgs": [], "ts": 0})
        a["sev"] = worst(a["sev"], sev)
        if msg not in a["msgs"]:
            a["msgs"].append(msg)
        a["ts"] = max(a["ts"], ts)
    return alerts

def _merge_smartd(results, alerts):
    # alerts are keyed by /dev basename; match on the result's device (from detail_json), not its
    # name_suffix, which is now a stable by-id rather than the sdX basename.
    for r in results:
        try:
            dev = json.loads(r.get("detail_json") or "{}").get("dev") or ""
        except (ValueError, TypeError):
            dev = ""
        a = alerts.get(os.path.basename(dev)) if dev else None
        if not a:
            continue
        r["severity"] = worst(r.get("severity", "OK"), a["sev"])
        note = "smartd: " + "; ".join(a["msgs"][:3])
        r["last_error"] = note[:300] if not r.get("last_error") else (r["last_error"] + " · " + note)[:400]
        try:
            d = json.loads(r.get("detail_json") or "{}")
        except (ValueError, TypeError):
            d = {}
        d["smartd"] = a["msgs"][:10]
        r["detail_json"] = json.dumps(d)

def _smart_scan_only():
    """Sudoless DEFAULT: enumerate SMART devices via `smartctl --scan` (works unprivileged) with NO
    privileged probe. Health/alerts are folded in from smartd's journal by _merge_smartd. The rich
    attribute table is opt-in (CAIRN_SMART_DETAIL=1 + the scoped smartctl wrapper via grant-access.sh
    --smart-detail)."""
    rc, out, _ = run(["smartctl", "--scan"])
    results = []
    for ln in out.splitlines():
        m = re.match(r"(/dev/\S+)\s+-d\s+(\S+)", ln)
        if m:
            results.append(dict(severity="OK", name_suffix=_disk_byid(m.group(1)), last_error=None,
                                detail_json=json.dumps({"dev": m.group(1), "typ": m.group(2),
                                                        "detail_optin": True})))
    return results

def adapter_smart(t, defaults, now):
    """Per-disk health, sudoless by default:
      • ALERTS + status come from smartd's journal (real-time, portable, free - smartd already polls
        every drive ~30 min), folded onto a device list from unprivileged `smartctl --scan`.
      • The DETAIL snapshot (identity + full attribute table) needs a privileged `smartctl -a`, so it
        is OPT-IN: set CAIRN_SMART_DETAIL=1 (and install the scoped wrapper via grant-access.sh
        --smart-detail). It's ~static, so it's cached long (CAIRN_SMART_TTL, default 24h) and only re-read
        when the cache is stale/missing or smartd just flagged a change.
    Default install therefore elevates NOTHING at runtime; the attribute table is simply absent until
    opted in."""
    alerts = _smartd_alerts(int(t.get("smartd_window_h", 72)))
    detail_on = os.environ.get("CAIRN_SMART_DETAIL", "").lower() in ("1", "true", "yes", "on") \
        or os.geteuid() == 0
    if not detail_on:
        results = _smart_scan_only()
        _merge_smartd(results, alerts)
        return results or [dict(severity="UNKNOWN", last_error="smartctl --scan found no devices")]
    ttl = int(os.environ.get("CAIRN_SMART_TTL", str(24 * 3600)))
    newest_alert = max((a["ts"] for a in alerts.values()), default=0)
    cp = _smart_cache_path()
    cached = None
    try:
        if os.path.isfile(cp):
            cached = json.loads(Path(cp).read_text())
    except Exception:
        cached = None
    cache_fresh = bool(cached and cached.get("results") and (now - cached.get("ts", 0)) < ttl
                       and not (newest_alert and newest_alert > cached.get("ts", 0)))
    if cache_fresh:
        results = cached["results"]
    else:
        results = _smart_probe_all(now)                # re-read smartctl (stale / missing / smartd changed)
        if any(r.get("detail_json") for r in results):
            try:
                os.makedirs(os.path.dirname(cp), exist_ok=True)
                Path(cp).write_text(json.dumps({"ts": now, "results": results}))
            except Exception:
                pass
        elif cached and cached.get("results"):
            results = cached["results"]                # keep last-good detail if this probe couldn't read
    _merge_smartd(results, alerts)                     # fold real-time alerts onto whatever detail we have
    return results

# ---------- persistence ----------
STATUS_COLS = ["snap_age_src_s","snap_age_dst_s","repl_lag_s","pool_health","pool_cap_pct",
    "last_scrub_ts","usedbysnapshots","compressratio","key_status","archive_count","dedup_ratio",
    "logical_size","physical_size","last_check_ts","last_check_result","lock_state","handler_type",
    "handler_result","last_run_ts","detail_json","last_error"]

def ensure_schema(conn):
    conn.executescript((HERE / "schema.sql").read_text())

def upsert_target(conn, t):
    meta = json.dumps(t)
    cur = conn.execute("""INSERT INTO targets(name,type,source,dest,tier,transport,location,
        cadence,encrypted,meta_json,enabled) VALUES(?,?,?,?,?,?,?,?,?,?,1)
        ON CONFLICT(name) DO UPDATE SET type=excluded.type,source=excluded.source,dest=excluded.dest,
        tier=excluded.tier,location=excluded.location,encrypted=excluded.encrypted,meta_json=excluded.meta_json
        RETURNING id""",
        (t["name"], t["type"], t.get("source"), t.get("dest"), t.get("tier"),
         t.get("transport"), t.get("location"), t.get("cadence"),
         1 if t.get("encrypted") else 0, meta))
    return cur.fetchone()[0]

def write_status(conn, tid, st, now):
    cols = ["ts","target_id","severity"] + STATUS_COLS
    vals = [now, tid, st.get("severity", "UNKNOWN")] + [st.get(c) for c in STATUS_COLS]
    conn.execute(f"INSERT INTO status({','.join(cols)}) VALUES({','.join('?'*len(cols))})", vals)

def alert(st, tname):
    if not NOTIFY.exists() or st.get("severity") not in ("WARN", "CRIT"):
        return
    reasons = ""
    try:
        reasons = ", ".join(json.loads(st.get("detail_json") or "{}").get("reasons", []))
    except ValueError:
        pass
    body = f"target={tname} severity={st['severity']} {reasons} {st.get('last_error') or ''}".strip()
    run(["bash", str(NOTIFY), st["severity"], f"{tname}: {st['severity']}", body, f"bm1-{tname}"], timeout=30)

# ---------- shared collection + action-command building (used by main() and the agent) ----------
def collect_all(cfg, now=None):
    """Run every target's adapter. Returns [(target_dict_with_name, status_dict), ...].
    Sub-status targets (borg/backupninja/smart yield several) get 'name:suffix' names."""
    if now is None:
        now = int(time.time())
    defaults = {**DEFAULT_THRESHOLDS, **cfg.get("defaults", {})}; scrub_cad = cfg.get("scrub_cadence", {})
    pools = zpool_list()
    out = []
    for t in cfg["targets"]:
        typ = t["type"]
        try:
            if typ == "zfs-local":
                sts = adapter_zfs_local(t, defaults, scrub_cad, now, pools)
            elif typ == "zfs-repl":
                sts = adapter_zfs_repl(t, defaults, now, pools)
            elif typ == "borg-repo":
                sts = adapter_borg(t, defaults, now)
            elif typ == "restic":
                sts = adapter_restic(t, defaults, now)
            elif typ == "rclone":
                sts = adapter_rclone(t, defaults, now)
            elif typ == "removable":
                sts = adapter_removable(t, defaults, now)
            elif typ == "snapper":
                sts = adapter_snapper(t, defaults, now)
            elif typ == "smart":
                sts = adapter_smart(t, defaults, now)
            elif typ == "kernel-errors":
                sts = adapter_kernel_errors(t, defaults, now)
            elif typ == "backupninja-handler":
                sts = adapter_backupninja(t, defaults, now)
            elif typ == "schedules":
                sts = adapter_schedules(t, defaults, now)
            elif typ == "zfs-events":
                sts = adapter_zfs_events(t, defaults, now)
            else:
                sts = [dict(severity="UNKNOWN", last_error=f"unknown type {typ}")]
        except Exception as e:
            sts = [dict(severity="UNKNOWN", last_error=f"adapter error: {e}")]
        for i, st in enumerate(sts):
            # uniform passthrough: any target may advertise WHAT it backs up + its schedule; merge
            # into detail without overriding a value the adapter already derived (e.g. per-handler).
            extra = {k: t[k] for k in ("backs_up", "schedule") if t.get(k)}
            if extra:
                try:
                    d = json.loads(st.get("detail_json") or "{}")
                except (ValueError, TypeError):
                    d = {}
                for k, v in extra.items():
                    d.setdefault(k, v)
                st["detail_json"] = json.dumps(d)
            name = t["name"] if len(sts) == 1 else f"{t['name']}:{st.get('name_suffix', i)}"
            out.append((dict(t, name=name), st))
    return out

def build_command(action, t, opts=None):
    """Map (action, target) -> argv from the TRUSTED local target config. Never from the wire.
    Returns (argv|None, error|None). The action allowlist for the agent's executor."""
    opts = opts or {}
    typ = t.get("type"); src = t.get("source")
    if action == "snapshot":
        if not src:
            return None, "target has no source dataset"
        return ["zfs", "snapshot", f"{src}@cairn-manual-{time.strftime('%Y%m%dT%H%M%S')}"], None
    if action == "sync":
        if typ != "zfs-repl":
            return None, f"'sync' not allowed for type '{typ}'"
        dst = t.get("dest")
        if not src or not dst:
            return None, "target missing source/dest"
        cmd = ["syncoid", "--no-privilege-elevation", "--no-stream"]
        if t.get("encrypted"):
            # raw send (-w) for zero-knowledge replicas: the destination stays encrypted with its
            # key unavailable. A non-raw send would need the dest key loaded ("inherited key must be
            # loaded") and would defeat the zero-knowledge property.
            cmd.append("--sendoptions=w")
        if not opts.get("create_snapshot", True):
            cmd.append("--no-sync-snap")
        return cmd + [src, dst], None
    if action == "backup-now":
        # Incremental backup of a live source onto a removable 2nd-leg drive. rsync only for now
        # (borg/restic later). ADDITIVE by default (no --delete): a stale/diverged drive is never
        # auto-clobbered - set `mirror: true` on the target to opt into --delete. The agent's handler
        # guards presence/rw and stamps the drive on success; here we only build the argv.
        if typ != "removable":
            return None, f"'backup-now' not allowed for type '{typ}'"
        tool = t.get("tool", "rsync")
        if tool != "rsync":
            return None, f"backup tool '{tool}' not supported yet (rsync only)"
        dest = _removable_dest(t)
        if not src or not dest:
            return None, "removable target needs source + mount"
        dry = bool(opts.get("dryrun"))
        # mirror (--delete) is opt-in and dangerous. Per-click `opts.mirror` wins; else the target's
        # `mirror` default; else off. A stale/diverged drive is never clobbered unless explicitly asked.
        mirror = opts.get("mirror")
        if mirror is None:
            mirror = t.get("mirror")
        # -X carries xattrs (mcz's user.b3sig hash-at-rest) onto the drive, so future verification is a
        # free xattr compare; -H preserves the dataset's internal hardlinks (space saving carries over);
        # -h makes the --stats sizes human-readable in the result/log (this rsync's output isn't parsed,
        # unlike the census, so -h is safe here).
        cmd = ["rsync", "-aHXh", "--stats"]
        # Persistent, appended rsync log (real runs only - a dry run's "would transfer" lines would
        # pollute the record of actual backups; dry output still comes back in the intent result).
        if not dry:
            cmd += ["--log-file", _removable_log_path(t)]
        if dry:
            cmd.append("-n")
        exc = t.get("exclude") or []
        if mirror:
            cmd.append("--delete")
            if exc and opts.get("prune_excluded"):   # OPT-IN: also remove excluded folders from the
                cmd.append("--delete-excluded")       # drive (reclaim their space); default leaves them
        for ex in exc:
            cmd += ["--exclude", str(ex)]
        # trailing slashes: copy the CONTENTS of src into dest
        return cmd + ["--", src.rstrip("/") + "/", dest.rstrip("/") + "/"], None
    if action == "scrub":
        if typ != "zfs-local":
            return None, f"'scrub' not allowed for type '{typ}'"
        pool = (src or "").split("/")[0]
        if not pool:
            return None, "no pool for scrub"
        # `zpool scrub` needs root: ZFS delegation (`zfs allow`) covers dataset-level `zfs` verbs only,
        # never `zpool` sub-commands, so a bare `zpool scrub` fails "permission denied" for the user-mode
        # agent. Go through a root-owned, sudoers-pinned wrapper (same pattern as the SMART probe) that
        # hard-constrains to `zpool scrub <existing-pool>`. Provisioned by grant-access.sh --scrub.
        wrapper = os.environ.get("CAIRN_ZPOOL_WRAPPER", "/opt/cairn/phase1/zpool-scrub.sh")
        return (["sudo", "-n", wrapper, pool], None)
    if action == "pull":
        # Vault-side on-demand replication: pull THIS replica's set from home via the restricted key.
        # The set name is the target name (replication.conf SET names == the dataset targets), and the
        # runner only pulls a SET that exists in this host's own replication.conf - so the wire can't
        # make it pull anything unconfigured.
        name = t.get("name")
        if not name:
            return None, "pull needs a target name"
        runner = str(HERE.parent / "replication" / "vault-pull.sh")
        if not os.path.isfile(runner):
            return None, "no replication runner (this host isn't a pull vault)"
        return [runner, "--only", name], None

    # ---- Phase 4: recovery-point catalog (httm) + guarded restore ----
    # All read-only or copy-only; paths validated to stay within the target's dataset.
    if action in ("recover-points", "recover-search", "recover-deleted", "restore"):
        if not src:
            return None, "recovery requires a dataset-backed target"
        if action == "recover-points":
            # FAST: list recovery points (snapshots) - no snapshot automount.
            return ["zfs", "list", "-Hp", "-t", "snapshot", "-o", "name,creation", "-s", "creation",
                    "-d", "1", src], None
        mp, err = _mountpoint(src)
        if err:
            return None, err
        rel = (opts.get("path") or "").lstrip("/")
        target_path, err = _safe_join(mp, rel)
        if err:
            return None, err
        if action == "recover-search":   # versions of a file/dir across snapshots (SLOW: automount)
            return NICE + ["httm", "--json", "--recursive", target_path], None
        if action == "recover-deleted":  # files gone from live but present in snapshots
            return NICE + ["httm", "--deleted=only", "--recursive", "--json", target_path], None
        if action == "restore":
            # copy a chosen snapshot version to a staging dir; NEVER overwrite a live file.
            version = opts.get("version") or ""     # absolute path inside .zfs/snapshot/...
            rp, err = _validate_under(version, mp)
            if err:
                return None, f"bad version path: {err}"
            staging = opts.get("dest") or os.path.join(mp, ".cairn-restores")
            sp, err = _validate_under(staging, mp) if not opts.get("dest") else (staging, None)
            dest = os.path.join(sp if not err else staging, os.path.basename(rp) + f".restored-{time.strftime('%Y%m%dT%H%M%S')}")
            # -v so stdout carries "'<src>' -> '<dest>'": the UI parses that to show where it landed.
            return ["cp", "-av", "--no-clobber", "--", rp, dest], None
    return None, f"unknown action '{action}'"

def build_dryrun(action, t, opts=None):
    """A SAFE dry-run that shows the REAL projected result. Returns (argv, note):
      - argv set  -> run it; it uses a native dry-run flag (`zfs send -nvP` for replication) or a
        read-only probe (`zpool status` for scrub) - real output, zero side effects.
      - argv None -> no meaningful native dry-run; `note` explains what the real run would do.
    syncoid 2.2 has no --dryrun and `zfs snapshot`/`zpool scrub` have no -n, hence the split."""
    opts = opts or {}
    src = t.get("source")
    if action == "sync":
        dst = t.get("dest")
        if not src or not dst:
            return None, "target missing source/dest"
        ssnaps = zfs_snapshots(src)
        if not ssnaps:
            return None, "source has no snapshots to send"
        newest_src = ssnaps[-1][0]
        raw = ["-w"] if t.get("encrypted") else []                    # match the real (raw) send
        dsnaps = zfs_snapshots(dst)
        if not dsnaps:
            return ["zfs", "send", "-nvP"] + raw + [newest_src], None  # first sync = full send estimate
        dguids = {g for _, g, _ in dsnaps}
        common = [s for s in ssnaps if s[1] in dguids]
        if not common:
            return None, "no snapshot in common with the destination - diverged; needs a manual base"
        base = max(common, key=lambda x: x[2])[0]
        if base == newest_src:
            return None, "already up to date - 0 bytes pending to the destination"
        return ["zfs", "send", "-nvP"] + raw + ["-I", base, newest_src], None  # real incremental estimate
    if action == "scrub":
        pool = (src or "").split("/")[0]
        return (["zpool", "status", pool], None) if pool else (None, "no pool for scrub")
    if action == "snapshot":
        return None, f"'zfs snapshot' has no dry-run - would create {src}@cairn-manual-<timestamp>"
    if action == "pull":
        return None, f"would pull the '{t.get('name')}' replication set from home now (syncoid, resumable)"
    if action in ("recover-points", "recover-search", "recover-deleted"):
        return build_command(action, t, opts)                          # read-only anyway
    if action == "restore":
        return None, "would copy the chosen snapshot version into the staging dir (copy-only, never overwrites live)"
    return None, f"no dry-run for '{action}'"

def _nice_prefix():
    """CPU/IO politeness prefix for the heavy httm scans, so a walk yields to real work on the box.
    IMPORTANT: ionice's classes only affect the Linux CFQ/BFQ scheduler and are effectively a NO-OP on
    ZFS (ZFS uses its own ZIO scheduler), so on a ZFS pool the real disk-load control is cadence and
    off-peak scheduling (see the agent's walk window), NOT this. `nice` still helps the CPU-bound tree
    walk + JSON build, and ionice does help on any non-ZFS dataset, so include both when present."""
    pre = []
    if shutil.which("ionice"):
        pre += ["ionice", "-c3"]        # idle IO class (no-op on ZFS, helps ext4/btrfs/etc.)
    if shutil.which("nice"):
        pre += ["nice", "-n19"]         # lowest CPU priority
    return pre

NICE = _nice_prefix()

def build_recovery_walk(kind, t):
    """argv for a per-dataset recovery-manifest walk (read-only). 'deleted' = files gone from live but
    still in snapshots. --recursive to cover the tree, --one-filesystem so a parent dataset's walk does
    NOT descend into child datasets (each child dataset walks itself -> smaller, non-overlapping blobs),
    --no-live so only snapshot versions are returned."""
    if kind != "deleted":
        return None, f"unknown recovery-walk kind '{kind}'"
    src = t.get("source")
    if not src:
        return None, "recovery walk requires a dataset-backed target"
    mp, err = _mountpoint(src)
    if err:
        return None, err
    return NICE + ["httm", "--deleted=only", "--recursive", "--one-filesystem", "--no-live", "--json", mp], None

def reduce_deleted_manifest(raw_json, cap=2000):
    """Collapse httm's deleted-files output to ONE (newest) version per path, newest-modified first,
    capped to `cap` entries, so the stored manifest stays small (a dataset can have tens of thousands of
    deleted-in-snapshot files, e.g. after an rmlint pass).

    httm's RECURSIVE json is a STREAM of concatenated pretty-printed objects (one per directory), not a
    single object, so we raw_decode successively and merge. Each object is
    {"<path>": [ {"path":..., "metadata":{"size":..., "modify_time":...}}, ... ]}. This framing is
    UNDOCUMENTED (the README only shows a single-file --json giving one object), so we also accept a single
    object and a top-level array of such objects - if a future httm switches form, this still works.
    Returns (json_string, total_found): json holds up to `cap` newest entries as
    {"<path>": {"path","size","modify_time","versions"}}; total_found is the full count before the cap.
    Newest is by parsed modify_time (httm format "Tue Sep 08 08:35:48 2026"), -1 when it won't parse."""
    import datetime

    def _mt(v):
        s = ((v or {}).get("metadata") or {}).get("modify_time") or ""
        try:
            return datetime.datetime.strptime(s, "%a %b %d %H:%M:%S %Y").timestamp()
        except (ValueError, TypeError):
            return -1.0

    text = raw_json or ""
    dec = json.JSONDecoder()
    merged, i, n = {}, 0, len(text)
    while i < n:
        while i < n and text[i] in " \t\r\n":   # skip whitespace between concatenated objects
            i += 1
        if i >= n:
            break
        try:
            obj, i = dec.raw_decode(text, i)
        except ValueError:
            break   # partial/garbage tail - stop, keep what parsed
        # accept a per-directory object (today), or a future top-level array of such objects
        for chunk in (obj if isinstance(obj, list) else [obj]):
            if isinstance(chunk, dict):
                for path, vers in chunk.items():
                    if isinstance(vers, list) and vers:
                        merged.setdefault(path, []).extend(vers)

    rows = []
    for path, vers in merged.items():
        newest = max(vers, key=_mt)
        md = newest.get("metadata") or {}
        rows.append((_mt(newest), path, {"path": newest.get("path") or "", "size": md.get("size") or "",
                                         "modify_time": md.get("modify_time") or "", "versions": len(vers)}))
    rows.sort(key=lambda r: r[0], reverse=True)   # newest-modified first (most likely recovery targets)
    out = {path: rec for _, path, rec in rows[:cap]}
    return json.dumps(out), len(rows)

def _scan_files(base, cap):
    """DFS the live directory tree under `base`, staying on ONE filesystem (skip child-dataset mounts,
    like --one-filesystem) and NOT following symlinks. Returns (files, truncated, scanned). Skips .zfs and
    the .cairn-restores staging dir. Bounded to `cap` files. This replaces httm --recursive for versions,
    which panics outside interactive mode - we enumerate ourselves and hand explicit files to httm."""
    files, truncated, scanned = [], False, 0
    try:
        base_dev = os.stat(base).st_dev
    except OSError as e:
        return files, False, 0
    stack = [base]
    while stack and len(files) < cap:
        d = stack.pop()
        try:
            entries = list(os.scandir(d))
        except OSError:
            continue
        for e in entries:
            if e.name in (".zfs", ".cairn-restores", ".bm-restores"):
                continue
            try:
                if e.is_symlink():
                    continue
                if e.is_dir(follow_symlinks=False):
                    if e.stat(follow_symlinks=False).st_dev == base_dev:   # don't cross into child datasets
                        stack.append(e.path)
                elif e.is_file(follow_symlinks=False):
                    scanned += 1
                    files.append(e.path)
                    if len(files) >= cap:
                        truncated = True
                        break
            except OSError:
                continue
    return files, truncated, scanned

def build_dirtree(t, cap=20000):
    """CHEAP directory structure (folders only - no files, no httm) for navigation. os.scandir dirs on one
    filesystem, skipping .zfs and the restore staging dirs. Returns (result, err); result = {tree, count,
    truncated} where tree is a nested {dirname: subtree}. This is what seeds the Versions browser so you
    navigate real folders instead of guessing a path; version history is scanned per-folder on demand."""
    src = t.get("source")
    if not src:
        return None, "dirtree requires a dataset-backed target"
    mp, err = _mountpoint(src)
    if err:
        return None, err
    try:
        base_dev = os.stat(mp).st_dev
    except OSError as e:
        return None, str(e)
    root = {}
    stack = [(mp, root)]
    count, truncated = 0, False
    while stack and count < cap:
        d, node = stack.pop()
        try:
            entries = list(os.scandir(d))
        except OSError:
            continue
        for e in entries:
            if e.name in (".zfs", ".cairn-restores", ".bm-restores"):
                continue
            try:
                if e.is_symlink() or not e.is_dir(follow_symlinks=False):
                    continue
                if e.stat(follow_symlinks=False).st_dev != base_dev:   # don't cross into child datasets
                    continue
            except OSError:
                continue
            child = {}
            node[e.name] = child
            stack.append((e.path, child))
            count += 1
            if count >= cap:
                truncated = True
                break
    return {"tree": root, "count": count, "truncated": truncated}, None

def _reduce_versions(merged, mp, show_cap, ver_cap):
    """Pure: turn {abs_path: [version dicts]} (merged httm --json output) into the browsable result. Keep
    only files that have real HISTORY (at least one snapshot version, i.e. a version path != the live
    path); newest-first, capped. Returns (files_dict, total_with_history). files_dict is keyed by path
    relative to the mountpoint -> list of {path,size,modify_time,live}."""
    import datetime

    def _mt(v):
        s = ((v or {}).get("metadata") or {}).get("modify_time") or ""
        try:
            return datetime.datetime.strptime(s, "%a %b %d %H:%M:%S %Y").timestamp()
        except (ValueError, TypeError):
            return -1.0

    rows = []
    for p, vers in merged.items():
        if not isinstance(vers, list):
            continue
        if not any(isinstance(v, dict) and (v.get("path") or "") != p for v in vers):
            continue   # only a live version -> nothing to restore
        vs = sorted((v for v in vers if isinstance(v, dict)), key=_mt, reverse=True)[:ver_cap]
        entries = [{"path": v.get("path") or "", "size": (v.get("metadata") or {}).get("size") or "",
                    "modify_time": (v.get("metadata") or {}).get("modify_time") or "",
                    "live": (v.get("path") or "") == p} for v in vs]
        rel = os.path.relpath(p, mp) if mp else p
        rows.append((rel, entries))
    total = len(rows)
    rows.sort(key=lambda r: r[0].lower())
    return {rel: entries for rel, entries in rows[:show_cap]}, total

def scan_versions(t, rel, scan_cap=1500, show_cap=300, ver_cap=15, timeout=900, budget=None):
    """Folder-wide version history for a dataset-backed target, WITHOUT httm --recursive: enumerate the
    files under <mountpoint>/<rel> ourselves, then run `httm --json` on them in batches and merge. rel may
    also name a single file. `budget` (seconds) caps total wall-clock across batches so a whole-dataset
    nightly scan can't run away (it stops early and marks the result truncated). Returns (result_dict,
    err); result = {path, files, total, shown, truncated, scanned}."""
    src = t.get("source")
    if not src:
        return None, "versions requires a dataset-backed target"
    mp, err = _mountpoint(src)
    if err:
        return None, err
    base, err = _safe_join(mp, rel or "")
    if err:
        return None, err
    if os.path.isfile(base):
        files, truncated, scanned = [base], False, 1
    elif os.path.isdir(base):
        files, truncated, scanned = _scan_files(base, scan_cap)
    else:
        return None, f"no such file or folder under the dataset: {rel or '/'}"
    merged = {}
    deadline = (time.time() + budget) if budget else None
    budget_hit = False
    for i in range(0, len(files), 400):                     # batch: keep argv well under ARG_MAX
        if deadline and time.time() > deadline:             # wall-clock budget (nightly whole-dataset scan)
            budget_hit = True
            break
        # --omit-ditto drops snapshot versions identical to live (same size+mtime), so an unchanged file
        # collapses to just its live version and gets filtered out below - only genuinely-changed files
        # survive. (--omit-ditto is safe here; it only panics when paired with --recursive.)
        rc, out, _ = run(NICE + ["httm", "--json", "--omit-ditto"] + files[i:i + 400], timeout=timeout)
        if not out:
            continue
        try:
            o = json.loads(out)
        except ValueError:
            continue
        if isinstance(o, dict):
            for p, vers in o.items():
                if isinstance(vers, list):
                    merged.setdefault(p, []).extend(vers)
    # key files relative to the SCANNED folder (not the mountpoint) so the dashboard tree starts cleanly
    # at the scan root; for a single-file scan, relative to its parent so the filename shows.
    treebase = base if os.path.isdir(base) else os.path.dirname(base)
    fdict, total = _reduce_versions(merged, treebase, show_cap, ver_cap)
    return {"path": rel or "", "files": fdict, "total": total, "shown": len(fdict),
            "truncated": truncated or budget_hit or (total > len(fdict)), "scanned": scanned}, None

def _mountpoint(ds):
    rc, out, _ = run(["zfs", "get", "-H", "-o", "value", "mountpoint", ds])
    mp = out.strip()
    if rc != 0 or not mp or mp in ("none", "legacy", "-"):
        return None, f"dataset {ds} has no usable mountpoint ({mp or 'unknown'})"
    return mp, None

def _safe_join(mp, rel):
    """Join a user-supplied RELATIVE path onto a mountpoint, refusing any escape."""
    full = os.path.realpath(os.path.join(mp, rel))
    root = os.path.realpath(mp)
    if full != root and not full.startswith(root + os.sep):
        return None, f"path escapes dataset root {root}"
    return full, None

def _validate_under(path, mp):
    if not path:
        return None, "empty path"
    full = os.path.realpath(path)
    root = os.path.realpath(mp)
    if full != root and not full.startswith(root + os.sep):
        return None, f"path {full} not under {root}"
    return full, None

# ---------- main ----------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--db", default=None)
    ap.add_argument("--targets", default=None)
    ap.add_argument("--alert", action="store_true", help="send notify.sh alerts for WARN/CRIT")
    ap.add_argument("--print", dest="pr", action="store_true", help="print a summary table")
    a = ap.parse_args()
    load_env()
    db = a.db or os.environ.get("CAIRN_DB", "/var/lib/cairn/cairn.db")
    tf = a.targets or os.environ.get("CAIRN_TARGETS", str(HERE.parent / "targets.yaml"))
    cfg = yaml.safe_load(Path(tf).read_text())
    defaults = {**DEFAULT_THRESHOLDS, **cfg.get("defaults", {})}; scrub_cad = cfg.get("scrub_cadence", {})
    now = int(time.time())

    Path(db).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db); ensure_schema(conn)
    rows = []
    for sub, st in collect_all(cfg, now):
        tid = upsert_target(conn, sub)
        write_status(conn, tid, st, now)
        if a.alert:
            alert(st, sub["name"])
        rows.append((sub["name"], st.get("severity", "UNKNOWN"), st))
    conn.commit()
    # prune status older than 90 days
    conn.execute("DELETE FROM status WHERE ts < ?", (now - 90 * DAY,))
    conn.commit(); conn.close()

    if a.pr or not a.alert:
        order = {"CRIT": 0, "WARN": 1, "UNKNOWN": 2, "OK": 3}
        for name, sev, st in sorted(rows, key=lambda r: order.get(r[1], 9)):
            extra = ""
            if st.get("repl_lag_s") is not None: extra += f" lag={st['repl_lag_s']//3600}h"
            if st.get("pool_cap_pct") is not None: extra += f" cap={st['pool_cap_pct']}%"
            if st.get("last_error"): extra += f" err={st['last_error'][:60]}"
            print(f"  {sev:8} {name:28}{extra}")
    ncrit = sum(1 for _, s, _ in rows if s == "CRIT")
    nwarn = sum(1 for _, s, _ in rows if s == "WARN")
    print(f"[collector] {len(rows)} targets  CRIT={ncrit} WARN={nwarn}  db={db}")
    return 1 if ncrit else 0

if __name__ == "__main__":
    sys.exit(main())
