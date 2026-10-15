"""SMART: Backblaze failure predictors, live hwmon temperature + heat alerts, and the per-drive daily
history (smart_daily) behind the card's Trends panel."""
import json
import os
import sys
import tempfile

os.environ.setdefault("CAIRN_DB", os.path.join(tempfile.mkdtemp(), "cairn-test.db"))
os.environ.setdefault("CAIRN_ADMIN_TOKEN", "test-admin-token")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "phase1"))
import api  # noqa: E402
import collector  # noqa: E402


def _ata(attrs, passed=True, temp=30):
    return json.dumps({"device": {"protocol": "ATA"}, "smart_status": {"passed": passed},
                       "temperature": {"current": temp}, "model_name": "Disk", "serial_number": "SN1",
                       "rotation_rate": 5400,
                       "ata_smart_attributes": {"table": [
                           {"id": i, "name": f"a{i}", "value": 100, "worst": 100, "thresh": 0,
                            "raw": {"value": v, "string": s}} for i, v, s in attrs]}})


def _parse(o):
    st = collector._smart_parse("/dev/sdz", "sat", o, "", 1000)
    return st, json.loads(st["detail_json"])


def test_clean_drive_stays_ok():
    st, d = _parse(_ata([(5, 0, "0"), (187, 0, "0"), (188, 0, "0 0 0"), (10, 0, "0")]))
    assert st["severity"] == "OK" and d["cmd_timeout"] == 0 and d["rpt_unc"] == 0


def test_predictors_warn():
    st, d = _parse(_ata([(187, 3, "3")]))
    assert st["severity"] == "WARN" and "reported uncorrectable (187)=3" in st["last_error"]


def test_packed_seagate_188_counts_its_fields_not_the_packed_value():
    st, d = _parse(_ata([(188, 4295032833, "1 1 1")]))
    assert d["cmd_timeout"] == 3 and st["severity"] == "WARN"


def test_temperature_with_extra_text_is_not_summed():
    st, d = _parse(_ata([(10, 0, "0 (Min/Max 0/0)")]))
    assert d["spin_retry"] == 0 and st["severity"] == "OK"


def test_nvme_media_errors_warn():
    o = json.dumps({"device": {"protocol": "NVMe"}, "smart_status": {"passed": True}, "serial_number": "N1",
                    "nvme_smart_health_information_log": {"media_errors": 2, "temperature": 40,
                                                          "available_spare": 100, "available_spare_threshold": 10}})
    st, d = _parse(o)
    assert d["media_errors"] == 2 and st["severity"] == "WARN"


def _hwmon(root, n, name, temp, dev):
    d = root / f"hwmon{n}"
    d.mkdir()
    (d / "name").write_text(name + "\n")
    (d / "temp1_input").write_text(str(temp * 1000) + "\n")
    tgt = root / f"dev{n}"
    (tgt / dev if name == "nvme" else tgt / "block" / dev).mkdir(parents=True)
    os.symlink(tgt / dev if name == "nvme" else tgt, d / "device")


def test_hwmon_reads_nvme_and_drivetemp(tmp_path):
    _hwmon(tmp_path, 0, "nvme", 41, "nvme0")
    _hwmon(tmp_path, 1, "drivetemp", 33, "sdb")
    _hwmon(tmp_path, 2, "k10temp", 60, "cpu")
    assert collector._hwmon_temps(str(tmp_path)) == {"nvme0": 41.0, "sdb": 33.0}


def _res(dev, ssd=False, temp=None):
    return {"severity": "OK", "last_error": None,
            "detail_json": json.dumps({"dev": dev, "is_ssd": ssd, "temp": temp})}


def test_heat_limits_by_drive_kind_and_override():
    hdd, ssd, hot = _res("/dev/sda"), _res("/dev/nvme0", ssd=True), _res("/dev/sdb")
    collector._apply_temp([hdd, ssd, hot], {}, {"sda": 52, "nvme0": 65, "sdb": 61})
    assert hdd["severity"] == "WARN" and "52°C" in hdd["last_error"]
    assert ssd["severity"] == "OK"
    assert hot["severity"] == "CRIT"
    r = _res("/dev/sda")
    collector._apply_temp([r], {"temp_warn": 55}, {"sda": 52})
    assert r["severity"] == "OK" and json.loads(r["detail_json"])["temp_live"] is True


def test_daily_rollup_keeps_range_and_highest_counter():
    with api.db() as conn:
        for ts, temp, crc in ((86400 * 10, 30, 0), (86400 * 10 + 60, 41, 2), (86400 * 10 + 120, 35, 1)):
            api._record_smart_day(conn, ts, {"serial": "TREND1", "model": "M", "temp": temp, "crc": crc,
                                             "available_spare": 100 - crc})
        api._record_smart_day(conn, 86400 * 11, {"serial": "TREND1", "temp": 33, "crc": 2})
        api._record_smart_day(conn, 86400 * 11, {"model": "no serial", "temp": 99})
        conn.commit()
    j = api.smart_history("TREND1")
    d0, d1 = j["days"]
    assert (d0["temp_min"], d0["temp_max"], d0["crc"], d0["available_spare"]) == (30, 41, 2, 98)
    assert d1["day"] == "1970-01-12" and j["model"] == "M"


def test_trends_panel_shows_only_nonzero_counters():
    with api.db() as conn:
        for day, rpt in ((1, 0), (2, 0), (3, 4)):
            api._record_smart_day(conn, 86400 * day, {"serial": "TREND2", "temp": 30 + day, "rpt_unc": rpt,
                                                      "realloc": 0})
        conn.commit()
    html = api._smart_trends("TREND2", warn=50)
    assert "reported uncorrectable (187): now 4, first non-zero 1970-01-04" in html
    assert "zero on every day: reallocated" in html and html.count("<svg") == 2
    assert "no history yet" in api._smart_trends("NOPE")
