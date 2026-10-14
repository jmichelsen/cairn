#!/usr/bin/env python3
"""sanoid-setup - a wizard that writes sanoid.conf entries for the datasets cairn watches here.

Nothing snapshots a ZFS dataset on its own: sanoid does that on a schedule, from /etc/sanoid/sanoid.conf.
Replication only copies snapshots that exist, and a copy on a vault keeps every snapshot it receives
unless something prunes it. This finds the datasets this host's cairn targets touch that sanoid.conf
doesn't cover yet, asks what each should get, shows the entries, and (on a yes) appends them to
sanoid.conf with sudo, after saving a backup copy.

  ORIGINAL (data that lives here: a zfs-repl source, a zfs-local dataset):
      production  sanoid's example: hourly kept 36h, daily 30 days, monthly 3 months
      custom      the same, with your own counts
      ignore      no snapshots
  COPY (a dataset a pull writes into: the vault's replicas). Optional: a pull never deletes
  anything, so with no entry a copy keeps every snapshot it receives (the default, "skip"):
      backup      sanoid's example: prune-only, keeps 30 hourly / 90 daily / 12 monthly arrivals
      keepall     prune nothing (keep every snapshot that arrives; it grows forever)
      custom      backup with your own counts
      ignore      leave alone (cairn then stops checking the copy's freshness)
  A copy is never offered a policy that takes snapshots: a local snapshot there breaks the next pull.

  phase1/sanoid-setup.py              # ask per dataset, then write (sudo)
  phase1/sanoid-setup.py --yes        # the defaults without asking (production; copies left as they are)
  phase1/sanoid-setup.py --print      # only print the entries, change nothing
  phase1/sanoid-setup.py --dataset tank/x   # also offer a dataset no target names

Datasets sanoid.conf already covers (by name, or by a parent with recursive = yes) are left alone.
The templates are added as template_cairn_<policy> so they never clash with templates you edited.
"""
import argparse, os, shutil, subprocess, sys, tempfile, time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import sanoid_parser as SP  # noqa: E402

os.environ["PATH"] = os.pathsep.join([os.environ.get("PATH", ""), "/usr/local/sbin", "/usr/sbin", "/sbin"])
PULL_CONF = Path.home() / ".config" / "cairn" / "replication.conf"
CHOICES = {"original": ["production", "custom", "ignore", "skip"],
           "copy": ["skip", "backup", "keepall", "custom", "ignore"]}


def received_sets(path=PULL_CONF):
    """Dest datasets of this vault's pull SETs (replication.conf), if any."""
    out = []
    try:
        for ln in path.read_text().splitlines():
            f = ln.split()
            if len(f) >= 4 and f[0] == "SET":
                out.append(f[3])
    except OSError:
        pass
    return out


def local_pools():
    try:
        p = subprocess.run(["zpool", "list", "-H", "-o", "name"], capture_output=True, text=True, timeout=30)
        return set(p.stdout.split()) if p.returncode == 0 else set()
    except (OSError, subprocess.TimeoutExpired):
        return set()


def plan(targets, received, parsed, defaults, extra=(), pools=()):
    """[(dataset, kind, target name)] not yet covered by sanoid.conf, plus [(dataset, why)] covered."""
    todo, covered = [], []
    for ds, kind, name in SP.classify(targets, received, pools) + [(d, "original", None) for d in extra]:
        f = SP.freshness(ds, parsed, defaults)
        if f.get("governed"):
            covered.append((ds, f"sanoid: {f.get('type') or f.get('reason')}"))
        elif ds not in [d for d, _, _ in todo]:
            todo.append((ds, kind, name))
    return todo, covered


def _ask(prompt, default):
    try:
        with open("/dev/tty") as tty:
            sys.stdout.write(f"{prompt} [{default}]: "); sys.stdout.flush()
            ans = tty.readline().strip()
    except OSError:
        ans = input(f"{prompt} [{default}]: ").strip()
    return ans or default


def _custom(kind):
    base = dict(x.split(" = ") for x in SP.POLICIES["production" if kind == "original" else "backup"]["lines"])
    over = {}
    for k in ("hourly", "daily", "monthly"):
        v = _ask(f"      keep how many {k} snapshots", base[k])
        while not v.isdigit():
            v = _ask(f"      a number please: {k}", base[k])
        if v != base[k]:
            over[k] = v
    return over


def choose(todo, assume_yes):
    """{dataset: (policy, overrides)} from the user's answers (or the defaults with --yes)."""
    picks = {}
    for ds, kind, name in todo:
        opts = CHOICES[kind]
        if assume_yes:
            if opts[0] != "skip":
                picks[ds] = (opts[0], {})
            continue
        print(f"\n  {ds}" + (f"  (target '{name}')" if name else "") +
              ("  - a COPY that pulls write into" if kind == "copy" else "  - data that lives on this box"))
        for i, o in enumerate(opts, 1):
            label = {"custom": "the default policy with your own counts",
                     "skip": ("keep as now: nothing is written, every snapshot that arrives is kept"
                              if kind == "copy" else "decide later (nothing written)")}.get(o) or SP.POLICIES[o]["label"]
            print(f"    {i}) {o:<10} {label}")
        a = _ask("    choose", "1")
        while not (a.isdigit() and 1 <= int(a) <= len(opts)) and a not in opts:
            a = _ask("    choose a number from the list", "1")
        pol = opts[int(a) - 1] if a.isdigit() else a
        if pol == "skip":
            continue
        if pol == "custom":
            picks[ds] = ("production" if kind == "original" else "backup", _custom(kind))
        else:
            picks[ds] = (pol, {})
    return picks


def _sudo():
    return [] if os.geteuid() == 0 else ["sudo"]


def write(conf, text):
    """Append text to sanoid.conf via sudo, keeping a timestamped backup of the old file."""
    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".conf") as f:
        f.write(text if text.endswith("\n") else text + "\n")
        tmp = f.name
    try:
        if conf.exists():
            bak = f"{conf}.bak-{time.strftime('%Y%m%d-%H%M%S')}"
            subprocess.run(_sudo() + ["cp", "-a", str(conf), bak], check=True)
            print(f"  saved the old file as {bak}")
            subprocess.run(_sudo() + ["sh", "-c", 'cat "$1" >> "$2"', "sh", tmp, str(conf)], check=True)
        else:
            subprocess.run(_sudo() + ["install", "-D", "-m", "644", tmp, str(conf)], check=True)
        print(f"  wrote {conf}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"  could not write {conf}: {e}")
        return False
    finally:
        os.unlink(tmp)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--targets", default=os.environ.get("CAIRN_TARGETS") or str(HERE.parent / "config" / "targets.yaml"))
    ap.add_argument("--conf", default=os.environ.get("CAIRN_SANOID_CONF", "/etc/sanoid/sanoid.conf"))
    ap.add_argument("--yes", action="store_true", help="use the defaults without asking (still writes)")
    ap.add_argument("--print", dest="print_only", action="store_true", help="print the entries, change nothing")
    ap.add_argument("--dataset", action="append", default=[], help="also offer this dataset (an original)")
    a = ap.parse_args()

    targets = []
    try:
        import yaml
        targets = (yaml.safe_load(Path(a.targets).read_text()) or {}).get("targets") or []
    except FileNotFoundError:
        pass
    except Exception as e:
        sys.exit(f"cannot read {a.targets}: {e}")
    conf = Path(a.conf)
    try:
        parsed = SP.parse(conf.read_text())
    except OSError:
        parsed = {"templates": {}, "datasets": {}}
    defaults = SP.load_defaults(os.environ.get("CAIRN_SANOID_DEFAULTS") or SP.defaults_path())
    todo, covered = plan(targets, received_sets(), parsed, defaults, a.dataset, local_pools())

    print(f"sanoid setup ({conf})")
    for ds, why in covered:
        print(f"  already scheduled: {ds} ({why})")
    if not todo:
        print("  every dataset cairn watches here is already in sanoid.conf. Nothing to do.")
        return 0
    if not shutil.which("sanoid"):
        print("  sanoid isn't installed: sudo apt install sanoid (then re-run this)")
        if not a.print_only:
            return 1
    picks = choose(todo, a.yes or a.print_only)
    if not picks:
        print("\n  nothing chosen, nothing written.")
        return 0
    text = SP.render(picks, parsed, header=f"\n# --- added by cairn sanoid-setup {time.strftime('%Y-%m-%d')} ---")
    print("\n  These entries go at the end of " + str(conf) + ":\n")
    print("\n".join("    " + ln for ln in text.strip("\n").splitlines()))
    if a.print_only:
        return 0
    if not a.yes and _ask("\n  write them now (sudo)?", "y").lower() not in ("y", "yes"):
        print("  not written. Copy them in by hand, or re-run this.")
        return 0
    if not write(conf, text):
        return 1
    rc = subprocess.run(["systemctl", "is-enabled", "sanoid.timer"], capture_output=True, text=True).stdout.strip()
    if rc != "enabled":
        print("  sanoid.timer isn't enabled, so sanoid.conf would never run; enabling it")
        subprocess.run(_sudo() + ["systemctl", "enable", "--now", "sanoid.timer"])
    if any(SP.POLICIES[p]["kind"] == "original" for p, _ in picks.values()):
        if a.yes or _ask("  take the first snapshots now (replication needs one to start)?", "y").lower() in ("y", "yes"):
            subprocess.run(_sudo() + ["sanoid", "--take-snapshots", "--verbose"])
    print("  done. sanoid applies sanoid.conf every 15 minutes (sanoid.timer), and cairn's cards follow "
          "the new schedule on their next check.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
