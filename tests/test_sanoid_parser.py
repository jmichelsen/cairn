"""Unit tests for the sanoid.conf parser + freshness derivation. Config text is embedded (mirrors the
real templates incl. the stock bare-vs-suffix unit mix), so these run with no sanoid install."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "phase1"))
import sanoid_parser as sp  # noqa: E402

CONF = """
[mcz/mclife/Pics]
\tuse_template = archive
\trecursive = yes
[mcz/mclife/karly]
\tuse_template = archive
\trecursive = yes
\thourly = 0
[mcz/mclife/wyze_backups]
\tuse_template = production
\trecursive = yes
\tprocess_children_only = yes
\thourly = 0
[plex]
\tuse_template = production
\trecursive = yes
\tprocess_children_only = yes
[nvme]
\tuse_template = backup
\trecursive = yes
\tprocess_children_only = yes
\thourly = 0
\tdaily = 0
[iwolf/Pics]
\tuse_template = ignore
[mcz/mclife/Pics/2024]
\tuse_template = archive

[template_production]
\thourly = 36
\tdaily = 30
\tmonthly = 3
[template_archive]
\thourly = 12
\tdaily = 90
\tmonthly = 12
\tyearly = 2
\tdaily_warn = 48
\tdaily_crit = 60
[template_backup]
\thourly = 36
\tdaily = 90
\thourly_warn = 2880
\thourly_crit = 3600
\tdaily_warn = 48
\tdaily_crit = 60
[template_ignore]
\tautosnap = no
\tmonitor = no
"""

# stock template_default subset (what load_defaults() returns from sanoid.defaults.conf)
DEFAULTS = {"monitor": "yes", "hourly_warn": "90m", "hourly_crit": "360m",
            "daily_warn": "28h", "daily_crit": "32h", "monthly_warn": "32d", "monthly_crit": "40d"}


def _p():
    return sp.parse(CONF)


def test_parse_sections():
    p = _p()
    assert set(p["templates"]) >= {"archive", "production", "backup", "ignore"}
    assert "mcz/mclife/Pics" in p["datasets"]
    assert p["datasets"]["mcz/mclife/karly"]["hourly"] == "0"
    assert p["templates"]["archive"]["daily_warn"] == "48"


def test_convert_time_period_units():
    assert sp.convert_time_period("90m", 60) == 5400          # explicit minutes
    assert sp.convert_time_period("2880", 60) == 2880 * 60    # bare hourly -> minutes = 48h
    assert sp.convert_time_period("48", 3600) == 48 * 3600    # bare daily -> hours
    assert sp.convert_time_period("4h", 1) == 4 * 3600        # suffix wins over fallback
    assert sp.convert_time_period("2d", 1) == 2 * 86400
    assert sp.convert_time_period("0", 3600) == 0
    assert sp.convert_time_period("", 60) == 0                # invalid -> 0 (off)


def test_hourly_dataset_uses_default_hourly_thresholds():
    # Pics: archive has no hourly_warn -> inherits default 90m/360m; finest active type = hourly.
    f = sp.freshness("mcz/mclife/Pics", _p(), DEFAULTS)
    assert f == {"governed": True, "suppress": False, "type": "hourly", "warn_h": 2, "crit_h": 6}


def test_daily_only_dataset_uses_archive_daily_thresholds():
    # karly: hourly=0 -> finest active = daily; archive daily_warn=48h / daily_crit=60h.
    f = sp.freshness("mcz/mclife/karly", _p(), DEFAULTS)
    assert f["type"] == "daily" and f["warn_h"] == 48 and f["crit_h"] == 60


def test_process_children_only_suppresses():
    for ds in ("mcz/mclife/wyze_backups", "plex", "nvme"):
        f = sp.freshness(ds, _p(), DEFAULTS)
        assert f["governed"] and f["suppress"], ds
        assert "children" in f["reason"] or "0" in f["reason"]


def test_ignore_template_suppresses_via_monitor_no():
    f = sp.freshness("iwolf/Pics", _p(), DEFAULTS)
    assert f["suppress"] and "monitor=no" in f["reason"]


def test_exact_deeper_dataset_and_recursive_child():
    p = _p()
    # exact stanza for a deeper dataset
    assert sp.freshness("mcz/mclife/Pics/2024", p, DEFAULTS)["type"] == "hourly"
    # a child NOT explicitly listed resolves via the recursive ancestor (Pics, recursive=yes)
    f = sp.freshness("mcz/mclife/Pics/2024/sub", p, DEFAULTS)
    assert f["governed"] and not f["suppress"] and f["type"] == "hourly"


def test_ungoverned_dataset_left_alone():
    assert sp.freshness("mcz/mclife/other", _p(), DEFAULTS) == {"governed": False}


def test_annotate_sets_thresholds_and_respects_user_override():
    p = _p()
    t = {"type": "zfs-local", "source": "mcz/mclife/karly"}
    sp.annotate_target(t, p, DEFAULTS)
    assert t["fresh_warn_h"] == 48 and t["fresh_crit_h"] == 60 and t["fresh_src"] == "sanoid:daily"
    # user override wins and is never clobbered (even on a re-run)
    u = {"type": "zfs-local", "source": "mcz/mclife/karly", "fresh_warn_h": 10}
    sp.annotate_target(u, p, DEFAULTS)
    sp.annotate_target(u, p, DEFAULTS)
    assert u["fresh_warn_h"] == 10 and "fresh_src" not in u


def test_annotate_suppress_and_idempotent():
    p = _p()
    t = {"type": "zfs-local", "source": "plex"}
    sp.annotate_target(t, p, DEFAULTS)
    sp.annotate_target(t, p, DEFAULTS)          # idempotent
    assert t["fresh_suppress"] is True and "sanoid" in t["fresh_reason"]


def test_annotate_ignores_non_zfs_and_unsourced():
    t = {"type": "borg-repo", "source": "/mnt/borg"}
    assert sp.annotate_target(t, _p(), DEFAULTS) == {"governed": False}
    assert "fresh_warn_h" not in t


def test_load_defaults_fallback_when_missing():
    d = sp.load_defaults("/no/such/sanoid.defaults.conf")
    assert d["hourly_warn"] == "90m" and d["monitor"] == "yes"
