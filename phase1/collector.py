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
import argparse, json, os, re, sqlite3, subprocess, sys, time
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

def th(t, defaults, key):
    return t.get(key, defaults.get(key))

def adapter_zfs_local(t, defaults, scrub_cad, now, pools):
    ds = t["source"]; pool = ds.split("/")[0]
    st = dict(severity="OK", detail_json=None, last_error=None)
    reasons = []
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
    st["detail_json"] = json.dumps(dict(reasons=reasons, snap_count=len(snaps)))
    return [st]

def adapter_zfs_repl(t, defaults, now, pools):
    src, dst = t["source"], t["dest"]
    st = dict(severity="OK", last_error=None)
    ssnaps = zfs_snapshots(src); dsnaps = zfs_snapshots(dst)
    st["snap_age_src_s"] = newest_age(ssnaps, now)
    st["snap_age_dst_s"] = newest_age(dsnaps, now)
    reasons = []
    if not ssnaps or not dsnaps:
        st["severity"] = "UNKNOWN"; st["last_error"] = "missing snapshots on src or dst"
        st["detail_json"] = json.dumps(dict(reasons=["no snapshots"], src_n=len(ssnaps), dst_n=len(dsnaps)))
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

def _smart_parse(dev, typ, o, err, now):
    """Normalize one smartctl -a JSON blob (ATA / NVMe / SCSI) into a status dict whose
    detail_json carries identity, key stats, and the full attribute table for the drive view."""
    st = dict(severity="UNKNOWN", name_suffix=os.path.basename(dev), last_error=None)
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
    results = []
    for dev, typ in devs:
        cmd = (["smartctl", "-j", "-a", "-d", typ, dev] if is_root
               else ["sudo", "-n", wrapper, dev, typ])
        rc, o, err = run(cmd, timeout=30)
        results.append(_smart_parse(dev, typ, o, err, now))
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
    for r in results:
        a = alerts.get(r.get("name_suffix"))
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
            results.append(dict(severity="OK", name_suffix=os.path.basename(m.group(1)), last_error=None,
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
    defaults = cfg["defaults"]; scrub_cad = cfg.get("scrub_cadence", {})
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
    if action == "scrub":
        if typ != "zfs-local":
            return None, f"'scrub' not allowed for type '{typ}'"
        pool = (src or "").split("/")[0]
        return (["zpool", "scrub", pool], None) if pool else (None, "no pool for scrub")

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
            return ["httm", "--json", "--recursive", target_path], None
        if action == "recover-deleted":  # files gone from live but present in snapshots
            return ["httm", "--deleted=only", "--recursive", "--json", target_path], None
        if action == "restore":
            # copy a chosen snapshot version to a staging dir; NEVER overwrite a live file.
            version = opts.get("version") or ""     # absolute path inside .zfs/snapshot/...
            rp, err = _validate_under(version, mp)
            if err:
                return None, f"bad version path: {err}"
            staging = opts.get("dest") or os.path.join(mp, ".bm-restores")
            sp, err = _validate_under(staging, mp) if not opts.get("dest") else (staging, None)
            dest = os.path.join(sp if not err else staging, os.path.basename(rp) + f".restored-{time.strftime('%Y%m%dT%H%M%S')}")
            return ["cp", "-a", "--no-clobber", "--", rp, dest], None
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
    if action in ("recover-points", "recover-search", "recover-deleted"):
        return build_command(action, t, opts)                          # read-only anyway
    if action == "restore":
        return None, "would copy the chosen snapshot version into the staging dir (copy-only, never overwrites live)"
    return None, f"no dry-run for '{action}'"

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
    defaults = cfg["defaults"]; scrub_cad = cfg.get("scrub_cadence", {})
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
