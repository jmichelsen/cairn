#!/usr/bin/env python3
"""zfs-perms - work out, show and (optionally) grant the `zfs allow` delegations cairn needs here.

The agent runs as a normal user, so every ZFS action it takes (Snapshot, Replicate, a vault's
receive, the vault pulling from home) needs a ZFS delegation for that user. This reads THIS host's
targets.yaml, derives exactly which permissions each dataset needs and why, checks what the user
already holds, and with --apply grants only what's missing (one `sudo zfs allow` per dataset),
then checks again.

  phase1/zfs-perms.py                  # show the plan: needed / held / missing, per dataset
  phase1/zfs-perms.py --apply          # grant the REQUIRED ones that are missing (sudo), then verify
  phase1/zfs-perms.py --apply --all    # also the optional Snapshot-button grants
  phase1/zfs-perms.py --user alice     # check/grant for another user (e.g. when run as root)

Required = what replication needs (send side, receive side, a vault pulling from here); within it,
`hold`/`mountpoint` (and `snapshot` for a vault pull) are recommended extras that --apply grants too
but whose absence doesn't break anything, so the agent's dashboard check doesn't warn on them. Optional =
`snapshot` on a zfs-local target, which only enables its Snapshot button; some pools are kept out
of reach on purpose, so those are never granted without --all. Grants never include destroy,
rollback or anything that can delete data. Exit code: 0 when every REQUIRED permission is held
(after --apply, if given), 1 when one is still missing.
"""
import argparse, os, subprocess, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
# Debian keeps zfs/zpool in /usr/sbin, which a normal user's PATH lacks
os.environ["PATH"] = os.pathsep.join([os.environ.get("PATH", "")] + [d for d in ("/usr/local/sbin", "/usr/sbin", "/sbin")
                                                                     if d not in os.environ.get("PATH", "").split(os.pathsep)])
sys.path.insert(0, str(HERE))
import collector as C  # noqa: E402  (zfs_delegated, run)

def plan(targets, local_pools):
    """[(dataset, essential, extra, [reasons], required)] this host needs, merged per dataset and kind
    (a dataset can have a required row and a separate optional one). The per-target rules live in
    collector.zfs_perm_needs, shared with the agent's per-cycle check."""
    need = {}
    for t in targets or []:
        if not isinstance(t, dict):
            continue
        for ds, ess, extra, why, req in C.zfs_perm_needs(t, local_pools):
            cur = need.setdefault((ds, req), [[], [], []])
            for p in ess:
                if p not in cur[0]:
                    cur[0].append(p)
            for p in extra:
                if p not in cur[1] and p not in cur[0]:
                    cur[1].append(p)
            cur[2].append(why + ("" if req else " (optional)"))
    rows = []
    for (ds, req), (ess, extra, why) in sorted(need.items(), key=lambda kv: (kv[0][0], not kv[0][1])):
        extra = [p for p in extra if p not in ess]     # promoted to essential by another target
        rows.append((ds, tuple(ess), tuple(extra), why, req))
    return rows


def missing(ds, perms, user, groups):
    have = C.zfs_allowed(ds, user, groups)
    return [p for p in perms if p not in have]


def _groups(user):
    rc, out, _ = C.run(["id", "-Gn", user])
    return out.split() if rc == 0 else []


def _local_pools():
    rc, out, _ = C.run(["zpool", "list", "-H", "-o", "name"])
    return set(out.split()) if rc == 0 else set()


def _report(rows, user, groups):
    """Print the table; return (required datasets with essential gaps, optional datasets with gaps)."""
    gaps = opt = 0
    for ds, ess, extra, why, req in rows:
        miss, rec = missing(ds, ess, user, groups), missing(ds, extra, user, groups)
        if miss:
            gaps += req
            opt += not req
        if miss:
            state = ("MISSING " if req else "optional, not held: ") + ",".join(miss)
        elif rec:
            state = "OK (recommended: " + ",".join(rec) + ")"
        else:
            state = "OK"
        print(f"  {ds:<34} {','.join(ess + extra):<34} {state}")
        for w in why:
            print(f"      - {w}")
    return gaps, opt


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--targets", default=os.environ.get("CAIRN_TARGETS")
                    or str(HERE.parent / "config" / "targets.yaml"))
    ap.add_argument("--user", default=None, help="user to check/grant for (default: you)")
    ap.add_argument("--apply", action="store_true", help="grant missing REQUIRED permissions via sudo, then verify")
    ap.add_argument("--all", action="store_true", help="with --apply: also grant the optional Snapshot-button ones")
    a = ap.parse_args()

    user = a.user or os.environ.get("SUDO_USER") or C._whoami()[0]
    if user == "root":
        sys.exit("refusing to plan for root (root needs no delegation): pass --user <the agent's user>")
    try:
        import yaml
        cfg = yaml.safe_load(Path(a.targets).read_text()) or {}
    except Exception as e:
        sys.exit(f"cannot read {a.targets}: {e}")
    pools = _local_pools()
    if not pools:
        sys.exit("no ZFS pools found on this host (zpool list)")
    rows = plan(cfg.get("targets"), pools)
    if not rows:
        print(f"No ZFS targets in {a.targets} need delegation on this host.")
        return 0
    groups = _groups(user)
    print(f"ZFS delegations cairn needs for user '{user}' ({a.targets}):")
    gaps, opt = _report(rows, user, groups)
    if not gaps and not (a.all and opt):
        print("All required permissions are held." +
              (f" {opt} optional Snapshot-button grant(s) not held (--apply --all adds them)." if opt else ""))
        return 0
    if not a.apply:
        print(f"\n{gaps} dataset(s) need grants. Re-run with --apply to grant them (one sudo each)." +
              (f" {opt} optional (--apply --all)." if opt else ""))
        return 1
    sudo = [] if os.geteuid() == 0 else ["sudo"]
    print()
    for ds, ess, extra, _, req in rows:
        miss = missing(ds, ess + extra, user, groups)
        if miss and (req or a.all):
            cmd = sudo + ["zfs", "allow", "-u", user, ",".join(miss), ds]
            print("  $ " + " ".join(cmd))
            if subprocess.run(cmd).returncode != 0:
                print(f"    failed on {ds}")
    C._ZALLOW.clear()                                   # re-read, don't trust the pre-grant cache
    print("\nAfter granting:")
    gaps, _ = _report(rows, user, groups)
    print("All required permissions are held." if not gaps
          else f"{gaps} dataset(s) still missing required permissions (see above).")
    return 0 if not gaps else 1


if __name__ == "__main__":
    sys.exit(main())
