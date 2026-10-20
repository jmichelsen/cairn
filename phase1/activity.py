"""cairn's debug log: applog's rules for this app (see applog/ and ~/private/applog/docs/RULES.md).

Self-hosted mode: the log lives in cairn's own SQLite and belongs to whoever runs this cairn; nothing is sent
anywhere else. Admins read it at /log (page) or GET /api/v1/backup/log (JSON).

Every column of every table is declared here, either shown or secret; tests/test_activity.py fails on a column
nobody declared, so a new one can't be logged (or leak) by accident.
"""
import applog

COLUMNS = {
    "acks": {"target", "sig", "ts", "note"},
    "agents": {"name", "can_execute", "last_report_ts", "report_interval", "agent_version", "update_requested",
               "hostname", "host_conflict", "host_conflict_ts"},
    "auth_tokens": {"role", "kind", "label", "parent", "expires_ts", "created_ts", "last_used_ts", "active"},
    "ci_status": {"name", "status", "ref", "url", "updated_ts"},
    "intents": {"id", "target_id", "action", "opts", "state", "requested_by", "created_ts", "claimed_ts",
                "claimed_by", "result", "result_ts", "notified", "progress", "progress_ts"},
    "reconcile_dismissed": {"pair", "ts"},
    "recovery_manifests": {"target_id", "kind", "entry_count", "raw_bytes", "walked_ts"},
    "removable_links": {"id", "agent", "removable", "dataset", "dest_subpath", "confirmed", "score",
                        "last_backup_ts", "meta_json", "verify_method", "verify_ts", "excludes", "mirror",
                        "updated_ts"},
    "smart_daily": {"serial", "day", "model", "temp_min", "temp_max", "realloc", "pending", "offline_unc", "crc",
                    "rpt_unc", "cmd_timeout", "spin_retry", "media_errors", "pct_used", "available_spare",
                    "power_on_hours", "source"},
    "status": {"id", "ts", "target_id", "severity", "snap_age_src_s", "snap_age_dst_s", "repl_lag_s",
               "pool_health", "pool_cap_pct", "last_scrub_ts", "usedbysnapshots", "compressratio", "key_status",
               "archive_count", "dedup_ratio", "logical_size", "physical_size", "last_check_ts",
               "last_check_result", "lock_state", "handler_type", "handler_result", "last_run_ts", "detail_json",
               "last_error"},
    "target_retired": {"agent", "name", "ts"},
    "targets": {"id", "name", "type", "source", "dest", "tier", "transport", "location", "cadence", "encrypted",
                "agent", "meta_json", "enabled"},
    "users": {"username", "role", "created_ts", "active"},
    "vault_reports": {"id", "ts", "agent"},
}

SECRET_COLUMNS = {
    "auth_tokens": {"hash"},            # a token's hash is as good as a key for anyone holding a guess list
    "users": {"pass_hash"},
    "recovery_manifests": {"gz"},       # a compressed file list: bulky, and the files' names are the owner's
    "vault_reports": {"payload_json"},  # the vault agent's whole report: bulky; its rows are in status
}


def setup(db_path):
    applog.configure(
        db_path=db_path,
        app="cairn",                    # the Android app sends X-Cairn-App: <version>
        columns=COLUMNS,
        secret_columns=SECRET_COLUMNS,
        reads="slow",                   # dashboards, widgets and agents poll: only slow or failed reads are rows
        # No row and no stdout line: the container healthcheck and LAN discovery probes hit these all day.
        quiet={"/api/v1/identify", "/favicon.ico"},
        skip_kinds={"POST /api/v1/backup/events", "GET /api/v1/backup/log"},
    )
