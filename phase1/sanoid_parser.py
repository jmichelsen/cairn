#!/usr/bin/env python3
"""Parse /etc/sanoid/sanoid.conf and derive per-dataset snapshot-freshness thresholds, so cairn's
freshness verdict follows the machine's actual sanoid policy instead of a hardcoded 28/50h default.

Why: cairn tracks one "newest snapshot age" per dataset. What counts as stale depends entirely on how
often sanoid snapshots it - hourly datasets should be minutes-fresh, daily ones a day or two. Sanoid
already encodes that (templates + `<type>_warn`/`<type>_crit`), and it also declares which datasets it
does NOT monitor (`use_template = ignore` -> monitor=no, and `process_children_only = yes`). Reading
that gives correct thresholds for free and suppresses false freshness on unmonitored datasets.

This mirrors sanoid's own monitoring semantics (verified against sanoid 2.x + sanoid.defaults.conf):
- Effective config = template_default (from sanoid.defaults.conf) < each `use_template` in order <
  the stanza's own key overrides.
- A dataset is monitored only if `monitor` is truthy and `process_children_only` is not set.
- For each snapshot type with count > 0, sanoid warns/crits when the newest snapshot of that type is
  older than `<type>_warn`/`<type>_crit`. cairn uses the FINEST active type (the tightest bound) as the
  single freshness threshold for the dataset.
- Threshold units mirror sanoid's convertTimePeriod(): a suffix (y/w/d/h/m/s) is explicit (m = MINUTES,
  there is no "months" suffix); a bare number uses the type's default unit ("smallerperiod"):
  frequently=seconds, hourly=minutes, daily=hours, weekly=days, monthly=weeks, yearly=~months(31d).

Pure + dependency-free (stdlib only) so it unit-tests without a sanoid install.
"""
import os
import re

__all__ = ["parse", "load_defaults", "effective", "freshness", "annotate_target"]

# sanoid convertTimePeriod() suffix -> seconds (case-insensitive). m/M are MINUTES (no months).
_SUFFIX_SECONDS = {"y": 60 * 60 * 24 * 31 * 365, "w": 60 * 60 * 24 * 7, "d": 60 * 60 * 24,
                   "h": 60 * 60, "m": 60, "s": 1}
# per-type "smallerperiod": the unit (in seconds) a BARE number of that type is multiplied by.
_SMALLER = {"frequently": 1, "hourly": 60, "daily": 60 * 60, "weekly": 60 * 60 * 24,
            "monthly": 60 * 60 * 24 * 7, "yearly": 60 * 60 * 24 * 31}
# finest -> coarsest; cairn takes the finest ACTIVE type as the dataset's freshness bound.
_TYPES = ["frequently", "hourly", "daily", "weekly", "monthly", "yearly"]

# Fallback if sanoid.defaults.conf is unreadable - the stock template_default warn/crit + monitor flag.
_FALLBACK_DEFAULTS = {
    "monitor": "yes",
    "frequently_warn": "0", "frequently_crit": "0",
    "hourly_warn": "90m", "hourly_crit": "360m",
    "daily_warn": "28h", "daily_crit": "32h",
    "weekly_warn": "0", "weekly_crit": "0",
    "monthly_warn": "32d", "monthly_crit": "40d",
    "yearly_warn": "0", "yearly_crit": "0",
}


def parse(text):
    """Parse sanoid.conf text into {'templates': {name: {k: v}}, 'datasets': {path: {k: v}}}.
    Template names are stored WITHOUT the 'template_' prefix (so `use_template = archive` -> 'archive')."""
    templates, datasets = {}, {}
    curmap = None
    for raw in text.splitlines():
        s = raw.strip()
        if not s or s[0] in "#;":                 # blank or full-line comment
            continue
        if s.startswith("[") and s.endswith("]"):
            name = s[1:-1].strip()
            curmap = {}
            if name.startswith("template_"):
                templates[name[len("template_"):]] = curmap
            else:
                datasets[name] = curmap
            continue
        if curmap is None or "=" not in s:
            continue
        k, v = s.split("=", 1)
        curmap[k.strip()] = v.strip()
    return {"templates": templates, "datasets": datasets}


def load_defaults(path="/etc/sanoid/sanoid.defaults.conf"):
    """The stock [template_default] (monitor flag + per-type warn/crit), read from the defaults file
    when present, else a hardcoded copy. This is the base every dataset inherits from."""
    try:
        if path and os.path.exists(path):
            with open(path) as f:
                d = parse(f.read())["templates"].get("default")
            if d:
                return d
    except OSError:
        pass
    return dict(_FALLBACK_DEFAULTS)


def _truthy(v):
    return str(v).strip().lower() in ("yes", "true", "1", "on")


def _int(v, default=0):
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return default


def convert_time_period(value, smaller_period):
    """Mirror sanoid's convertTimePeriod: return the threshold in SECONDS. A trailing y/w/d/h/m/s is an
    explicit unit; a bare integer is multiplied by `smaller_period` (the type's default unit)."""
    v = str(value).strip()
    m = re.fullmatch(r"(\d+)([yYwWdDhHmMsS])", v)
    if m:
        return int(m.group(1)) * _SUFFIX_SECONDS[m.group(2).lower()]
    if re.fullmatch(r"\d+", v):
        return int(v) * smaller_period
    return 0                                        # invalid/empty -> no threshold (sanoid treats 0 as off)


def _stanza_for(dataset, datasets):
    """Return (stanza_dict, exact_bool) for a dataset: an exact match, else the nearest ancestor stanza
    marked recursive (which covers descendants). None if sanoid doesn't govern this dataset at all."""
    if dataset in datasets:
        return datasets[dataset], True
    parts = dataset.split("/")
    for i in range(len(parts) - 1, 0, -1):          # nearest ancestor first
        anc = "/".join(parts[:i])
        st = datasets.get(anc)
        if st and str(st.get("recursive", "")).strip().lower() in ("yes", "zfs"):
            return st, False
    return None, False


def effective(dataset, parsed, defaults):
    """Merge the effective config for a dataset: defaults < each use_template (in order) < stanza
    overrides. Returns (merged_dict, exact_bool) or (None, False) if not governed by sanoid."""
    stanza, exact = _stanza_for(dataset, parsed["datasets"])
    if stanza is None:
        return None, False
    merged = dict(defaults)
    for tmpl in [t.strip() for t in stanza.get("use_template", "").split(",") if t.strip()]:
        merged.update(parsed["templates"].get(tmpl, {}))
    for k, v in stanza.items():                     # the stanza's own keys win last
        if k != "use_template":
            merged[k] = v
    return merged, exact


def freshness(dataset, parsed, defaults):
    """Derive cairn's freshness verdict policy for a dataset from sanoid. Returns a dict:
      {'governed': False}                                   - not in sanoid; leave cairn's own default
      {'governed': True, 'suppress': True, 'reason': ...}   - sanoid does not monitor it
      {'governed': True, 'suppress': False, 'type': 'daily', 'warn_h': 48, 'crit_h': 60}
    """
    merged, exact = effective(dataset, parsed, defaults)
    if merged is None:
        return {"governed": False}
    if not _truthy(merged.get("monitor", "yes")):
        return {"governed": True, "suppress": True,
                "reason": "sanoid monitor=no (e.g. use_template=ignore)"}
    if exact and _truthy(merged.get("process_children_only", "")):
        return {"governed": True, "suppress": True,
                "reason": "sanoid process_children_only (children monitored, not this dataset)"}
    for typ in _TYPES:
        if _int(merged.get(typ, "0")) <= 0:
            continue
        warn_s = convert_time_period(merged.get(typ + "_warn", "0"), _SMALLER[typ])
        crit_s = convert_time_period(merged.get(typ + "_crit", "0"), _SMALLER[typ])
        if warn_s <= 0 and crit_s <= 0:
            continue                                # this type isn't alerted on; try the next coarser one
        warn_h = max(1, round(warn_s / 3600)) if warn_s > 0 else 0
        crit_h = max(1, round(crit_s / 3600)) if crit_s > 0 else 0
        if warn_h and crit_h:
            crit_h = max(crit_h, warn_h)            # crit must never be tighter than warn
        return {"governed": True, "suppress": False, "type": typ,
                "warn_h": warn_h or crit_h, "crit_h": crit_h or warn_h}
    return {"governed": True, "suppress": True,
            "reason": "sanoid takes no snapshots of this dataset (all types 0)"}


def annotate_target(t, parsed, defaults):
    """Annotate one cairn target dict IN PLACE from sanoid, keyed on its `source` dataset. A user-set
    fresh_warn_h/fresh_crit_h in targets.yaml always wins. Sets, when governed:
      fresh_suppress + fresh_reason   (sanoid doesn't monitor it), or
      fresh_warn_h/fresh_crit_h (unless user-set) + fresh_src='sanoid:<type>'.
    All-or-nothing user override: if the user set EITHER fresh_warn_h or fresh_crit_h in targets.yaml,
    sanoid leaves the target entirely alone (no thresholds changed, no suppression) - set both to take
    full manual control. Idempotent: a `fresh_src='sanoid:<type>'` marker tags values WE set (so a
    re-run may overwrite them when the policy changes) and, by its absence next to a fresh_* value,
    identifies a user override. Returns the freshness() dict for logging/tests."""
    if t.get("type") not in ("zfs-local", "zfs-repl") or not t.get("source"):
        return {"governed": False}
    ours = str(t.get("fresh_src", "")).startswith("sanoid:")
    if (("fresh_warn_h" in t) or ("fresh_crit_h" in t)) and not ours:
        return {"governed": False, "user_override": True}       # manual thresholds win; hands off
    f = freshness(t["source"], parsed, defaults)
    t.pop("fresh_suppress", None); t.pop("fresh_reason", None)   # clear prior sanoid state each pass
    if ours:                                        # drop values we set before, so a changed policy sticks
        t.pop("fresh_warn_h", None); t.pop("fresh_crit_h", None); t.pop("fresh_src", None)
    if not f.get("governed"):
        return f
    if f.get("suppress"):
        t["fresh_suppress"] = True
        t["fresh_reason"] = f["reason"]
        return f
    t["fresh_warn_h"] = f["warn_h"]
    t["fresh_crit_h"] = f["crit_h"]
    t["fresh_src"] = f"sanoid:{f['type']}"
    return f


_PARSE_CACHE = {}   # (conf_path, defaults_path) -> (conf_mtime, parsed, defaults); re-parse only on change


def load_and_annotate(targets, conf_path="/etc/sanoid/sanoid.conf",
                      defaults_path="/etc/sanoid/sanoid.defaults.conf"):
    """Read sanoid.conf (if present) and annotate every ZFS target. Parsing is cached by the conf's
    mtime, so a long-lived agent re-derives thresholds when sanoid.conf is edited but pays nothing when
    it isn't. Safe no-op when the file is missing/unreadable (targets keep cairn's built-in thresholds).
    Returns the number of targets sanoid governs."""
    try:
        mtime = os.path.getmtime(conf_path)
    except OSError:
        return 0
    key = (conf_path, defaults_path)
    cached = _PARSE_CACHE.get(key)
    if not cached or cached[0] != mtime:
        try:
            with open(conf_path) as f:
                parsed = parse(f.read())
        except OSError:
            return 0
        _PARSE_CACHE[key] = (mtime, parsed, load_defaults(defaults_path))
    _, parsed, defaults = _PARSE_CACHE[key]
    n = 0
    for t in targets:
        if annotate_target(t, parsed, defaults).get("governed"):
            n += 1
    return n
