# Target reference

This is the full reference for `config/targets.yaml`: every target type the collector supports,
every key it reads, its thresholds, what each severity means, which dashboard actions apply, and
what the agent needs to run it. The [README](../README.md) has the quick tour;
[`config/targets.example.yaml`](../config/targets.example.yaml) is a working starting point.

Severities, worst first: **CRIT**, **WARN**, **UNKNOWN** (cairn could not read the thing it checks),
**OK**. A type that yields several statuses (one per disk, handler or timer) reports each as
`<name>:<suffix>`.

## File layout

```yaml
defaults:        # optional: global thresholds (built-in values below apply when absent)
  fresh_warn_h: 28
scrub_cadence:   # optional: per-pool scrub-age thresholds (days)
  tank: { warn_d: 40, crit_d: 70 }
targets:         # required: one entry per thing to monitor
  - { name: tank, type: zfs-local, source: tank }
```

### `defaults:`

Overrides the built-in thresholds key by key. A target can override most of them for itself by
setting the same key on the target (see each type).

| Key | Built-in | Unit | Used by | Per-target override |
| --- | --- | --- | --- | --- |
| `repl_warn_h` / `repl_crit_h` | 28 / 50 | hours | `zfs-repl` lag | yes |
| `cap_warn_pct` / `cap_crit_pct` | 85 / 92 | percent | `zfs-local` pool capacity | yes |
| `scrub_warn_d` / `scrub_crit_d` | 40 / 70 | days | `zfs-local` scrub age (when the pool has no `scrub_cadence` entry) | **no** |
| `resilver_warn_h` | 48 | hours | `zfs-local` recent resilver | yes |
| `fresh_warn_h` / `fresh_crit_h` | 28 / 50 | hours | snapshot / archive / run freshness (`zfs-local`, paired `zfs-repl`, `borg-repo`, `restic`, `rclone`, `snapper`, `removable`, `backupninja-handler`) | yes |
| `removable_detach_warn_d` | 45 | days | `removable` plug-me-in nudge | yes, as `detach_warn_d` |

### `scrub_cadence:`

Scrub-age thresholds per pool, keyed by pool name:

```yaml
scrub_cadence:
  tank: { warn_d: 40, crit_d: 70 }   # monthly scrub
  fast: { warn_d: 10, crit_d: 24 }   # weekly scrub
```

Give both `warn_d` and `crit_d` for every pool you list (a partial entry does not fall back to
`defaults`). A pool with no entry uses `defaults.scrub_warn_d` / `scrub_crit_d`. Scrub age is only
read from here and from `defaults`: a `scrub_warn_d` / `scrub_crit_d` set on a target is ignored.

## Keys common to all types

| Key | Required | Meaning |
| --- | --- | --- |
| `name` | yes | Unique per agent. The dashboard card name, the intent target, and the join key for pairing, removable links and the vault pull (see below). |
| `type` | yes | One of the types below. An unknown type reports UNKNOWN "unknown type". |
| `tier` | no | A label. Only `tier: A` on a `zfs-repl` target does anything: it puts that dataset in the 3-2-1 scorecard. Other values are a badge. |
| `location` | no | `offsite` on a `zfs-repl` counts that copy as off-site in the scorecard. `removable` is the default shown on removable cards. Otherwise a label. |
| `encrypted` | no | `true` on `zfs-repl`: raw sends and the dest key check. On any dataset target: refuses (by target name) linking it to a removable drive, and shows the "enc" badge. |
| `backs_up` | no | Free text "what this protects", shown on the card. Never overrides a value the adapter derived itself. |
| `schedule` | no | Free text schedule, shown on the card (same passthrough rule). |
| `source_agent` | no | Documentation on a receiving `zfs-local`: the agent that sends this data. Shown on the card; it does not drive pairing. |
| `note` | no | Free text. On `zfs-local`, a note containing `not in sanoid` makes a pool root with no snapshots show "no snapshots". |
| `cadence`, `transport` | no | Stored with the target, not used by any check. |
| `pre_cmd`, `post_cmd`, `hook_actions`, `hook_timeout_s` | no | Wrap cairn's own `snapshot`, `sync` and `backup-now` actions. See [README: Pre/post hooks](../README.md#prepost-hooks-eg-consistent-vm-snapshots). |

The agent sends only `type`, `source`, `dest`, `tier`, `location`, `encrypted` and `cadence` to the
API as target metadata. Everything else stays on the agent and reaches the dashboard only through
the status it computes.

## Sanoid-derived freshness

For `zfs-local` and `zfs-repl` targets, the agent reads `/etc/sanoid/sanoid.conf` (plus
`sanoid.defaults.conf`) and sets snapshot-freshness thresholds per dataset, keyed on `source`:

- The finest snapshot type sanoid takes and alerts on (frequently, hourly, daily, ...) sets
  `fresh_warn_h` / `fresh_crit_h` from that type's `_warn` / `_crit`. The card notes `sanoid:<type>`.
- A dataset sanoid does not monitor (`use_template = ignore` / `monitor = no`, or the exact stanza
  has `process_children_only = yes`, or every snapshot count is 0) gets its freshness verdict
  suppressed: the card says why and freshness never alerts.
- A dataset sanoid does not govern at all keeps cairn's `defaults`.
- **Setting either `fresh_warn_h` or `fresh_crit_h` on a target opts that target out of derivation
  entirely** (no derived values, no suppression). The key you did not set falls back to `defaults`.
- `CAIRN_SANOID_DERIVE=0` turns derivation off; `CAIRN_SANOID_CONF` / `CAIRN_SANOID_DEFAULTS` move
  the files. A missing or unreadable `sanoid.conf` is a silent no-op.

## Container image limits

The Docker image (`Dockerfile`) installs only `zfsutils-linux borgbackup msmtp smartmontools sqlite3
curl`, runs as root, and its agent is report-only by default (`CAIRN_CAN_EXECUTE=0`). There is no
`journalctl`, `systemctl`, `ssh`, `sudo`, `rsync`, `syncoid`, `httm`, `restic`, `rclone` or `snapper`
in it. Per type:

| Works in the container | Does not |
| --- | --- |
| `zfs-local`, `zfs-repl` (reads; needs `/dev/zfs`), `borg-repo` (mount the repo), `smart` (as root it reads `smartctl -a` directly; needs device access; no smartd journal alerts), `kernel-errors` (only via a mounted plain-text log), `backupninja-handler` (mount log + reports) | `restic`, `rclone`, `snapper` (UNKNOWN "not installed"), `schedules` and `zfs-events` (UNKNOWN, no systemd/journal), `aide` (UNKNOWN, no sudo), `reachability` (**CRIT**, no ssh client: do not configure it there), `removable` backups (no rsync) |

Run the host agent (`./install.sh`) for anything in the right column.

## Types

### `zfs-local`

A local pool or dataset: pool health and capacity, resilver, vdev errors, scrub age, data errors,
and snapshot freshness.

| Key | Req | Default | Meaning |
| --- | --- | --- | --- |
| `source` | yes | | Pool (`tank`) or dataset (`tank/photos`), as `zfs list` prints it. |
| `cap_warn_pct`, `cap_crit_pct` | no | defaults | Pool capacity thresholds. |
| `resilver_warn_h` | no | defaults | WARN window after a completed resilver. |
| `fresh_warn_h`, `fresh_crit_h` | no | sanoid / defaults | Newest-snapshot age. Setting either opts out of sanoid derivation. |

Pool-level checks run **only when `source` is a pool root** (no `/`) and that pool is imported on
this host. A child dataset gets dataset properties and snapshot freshness only.

| Severity | When |
| --- | --- |
| CRIT | Pool health not ONLINE; capacity >= `cap_crit_pct`; resilver in progress; a vdev not ONLINE; vdev read/write/checksum errors; `zpool status` reports data errors; last scrub found errors; scrub age >= `crit_d`; newest snapshot >= `fresh_crit_h`. |
| WARN | Capacity >= `cap_warn_pct`; a resilver finished within `resilver_warn_h`; never scrubbed; scrub age >= `warn_d`; newest snapshot >= `fresh_warn_h`. |
| UNKNOWN | Only if the adapter itself errors (e.g. a malformed `scrub_cadence` entry). |
| OK | None of the above. A dataset with **no snapshots at all** stays OK with a "no snapshots" note. |

Dashboard actions (execute-capable agent, admin):

- **Snapshot** (`zfs snapshot <source>@cairn-manual-<ts>`): shown only when the agent's user holds
  `snapshot` via `zfs allow` on the dataset (user, one of its groups, or everyone). Hookable.
- **Scrub**: pool roots only, and only when `sudo -n -l` allows the scrub wrapper
  (`CAIRN_ZPOOL_WRAPPER`, default `/opt/cairn/phase1/zpool-scrub.sh`, installed by
  `grant-access.sh --scrub`). Dry-run shows `zpool status`.
- **Snapshots / Deleted / Versions / Restore** (recovery): Snapshots always; Deleted and Versions
  need a real mountpoint and `httm`. Restore copies a chosen version into
  `<mountpoint>/.cairn-restores`, never over a live file.
- **Replicate now** (pull): appears on a pair card when this `zfs-local` is the receiving half and
  its agent can execute. See [Vault pull](#vault-replicate-now-pull).

### `zfs-repl`

Watches a replication you already run (it schedules nothing): the lag of the newest snapshot common
to `source` and `dest`.

| Key | Req | Default | Meaning |
| --- | --- | --- | --- |
| `source` | yes | | Sending dataset (`tank/photos`). |
| `dest` | yes | | Receiving dataset name (`backup/photos`), never a mountpoint or `user@host:`. |
| `repl_warn_h`, `repl_crit_h` | no | defaults | Lag thresholds. |
| `encrypted` | no | false | Raw sends (`--sendoptions=w`) and the dest key check. |
| `vault_keystatus_expected` | no | `unavailable` | Expected dest `keystatus` when `encrypted`. |
| `dest_agent` | no | | The dest lives on another agent (a vault). Changes only how this half reports, see below. |
| `fresh_warn_h`, `fresh_crit_h` | no | sanoid / defaults | Used only in the `dest_agent` mode (source freshness). |

| Severity | When (both sides local) |
| --- | --- |
| CRIT | No common snapshot (never replicated, or diverged); lag >= `repl_crit_h`; `encrypted` and the dest `keystatus` differs from `vault_keystatus_expected`. |
| WARN | Lag >= `repl_warn_h`. |
| UNKNOWN | Dest pool not on this host and no `dest_agent`; dest has no snapshots ("replication never ran?"); source has no snapshots. |

**`dest_agent` mode.** When the dest pool is not imported here and `dest_agent` is set, this half
reports its own **source** snapshot freshness instead of UNKNOWN: CRIT >= `fresh_crit_h`, WARN >=
`fresh_warn_h`, WARN if the source has no snapshots, OK if sanoid suppresses the source. The card
shows "paired -> <dest_agent>". The keystatus check does not run in this mode (the receiver
checks its own copy).

Dashboard actions: **Replicate** (`syncoid --no-privilege-elevation --no-stream <source> <dest>`,
raw when `encrypted`; dry-run is a real `zfs send -nvP` estimate), **no-snap** (same with
`--no-sync-snap`), **Snapshot** of the source, and the recovery buttons on the source. `sync` and
`snapshot` are hookable. Requires `syncoid` and `zfs allow` delegation (send/snapshot/hold on the
source, receive on the dest).

### Replication pairs and the 3-2-1 scorecard

**Pair merge.** The API merges two targets into one pair card when a `zfs-repl` `dest` **exactly
equals** the `source` of a `zfs-local` reported by a **different** agent. `dest_agent` is not part
of that match; it only changes how the home half reports. Other `zfs-repl` targets of the same
source on the same agent fold into the card as "local 2nd copy" legs.

**Pair severity.** The receiver's severity when the home half is UNKNOWN (no `dest_agent`);
otherwise the worse of the two (with `dest_agent` the home half has a real severity, so a stale
source shows even if the vault copy is still fresh). Legs then fold in with the worse-of rule.

**3-2-1.** Only `tier: A` `zfs-repl` targets count, grouped by `source`:

- copies and media: distinct pool names across source and every dest in the group, plus one each
  for a confirmed removable link whose name matches one of the group's target names and that was
  backed up or content-verified within `CAIRN_REMOVABLE_STALE_D` days (default 90);
- off-site: any target in the group with `location: offsite`, **or** a guaranteed pair as above.
  `dest_agent` itself is not read by the scorecard.

A dataset passes with >= 3 copies, >= 2 media and >= 1 off-site.

### Vault "Replicate now" (pull)

The pair card's **Replicate now** queues a `pull` on the receiving agent, which runs
`replication/vault-pull.sh --only <vault zfs-local target name>`. The runner only pulls a `SET` of
that name from its own `replication.conf`, and `./install.sh home --replication` names each set
after the home `zfs-repl` target. So keep one name for all three: the home `zfs-repl`, the vault
`zfs-local`, and the `SET`. The vault host needs `replication/vault-pull.sh` (a pull vault install).

```yaml
# home
- { name: photos_offsite, type: zfs-repl, source: tank/photos, dest: vault/photos, tier: A, dest_agent: vault }
# vault
- { name: photos_offsite, type: zfs-local, source: vault/photos, source_agent: home }
```

### `borg-repo`

A local borg repository: newest archive age, archive count, size and dedup ratio.

| Key | Req | Default | Meaning |
| --- | --- | --- | --- |
| `source` | yes | | Repo **directory** on this host (it must exist as a path; `ssh://` repos are not supported). |
| `passphrase_env` | no | | Name of an env var in the agent's environment holding `BORG_PASSPHRASE`. |
| `fresh_warn_h`, `fresh_crit_h` | no | defaults | Newest-archive age. |

| Severity | When |
| --- | --- |
| CRIT | Newest archive >= `fresh_crit_h`. |
| WARN | Newest archive >= `fresh_warn_h`; no archives (or unreadable time); a `lock.exclusive` present (stale lock, or a backup running right now). |
| UNKNOWN | Repo path missing; `borg info` fails (permission denied, needs passphrase, not a repo). |

No actions. Requires `borg` and read access to the repo segments (`grant-access.sh` adds
`--umask 0027` for root-run borg). Runs with `--bypass-lock`; cache under `BORG_BASE_DIR` /
`BORG_CACHE_DIR` (default `/tmp/borg-base`, `/tmp/borg-cache`). Works in the container with the
repo mounted.

### `restic`

| Key | Req | Default | Meaning |
| --- | --- | --- | --- |
| `source` | yes | | Repo: path or `rest:` / `s3:` / `b2:` / `sftp:` URL. |
| `passphrase_env` | no | `RESTIC_PASSWORD` | Env var to read the password from. With no `passphrase_env`, the agent's own `RESTIC_PASSWORD` is used. |
| `password_file` | no | | Passed as `RESTIC_PASSWORD_FILE`. |
| `fresh_warn_h`, `fresh_crit_h` | no | defaults | Newest-snapshot age. |

CRIT / WARN on newest snapshot age; WARN if there are no snapshots; UNKNOWN when `restic` is not
installed or `restic snapshots --no-lock` fails (bad password, unreachable, locked). Backend
credentials (`AWS_*`, `B2_*`, ...) must be in the agent's environment. No actions.

### `rclone`

| Key | Req | Default | Meaning |
| --- | --- | --- | --- |
| `source` | yes | | Remote, e.g. `gdrive:backups`. |
| `marker` | no | | A local file your sync job touches on success; its mtime is the "last sync". |
| `fresh_warn_h`, `fresh_crit_h` | no | defaults | Marker age. |

CRIT when `rclone lsjson --max-depth 0` fails (remote unreachable or not configured for the agent
user). With `marker`: CRIT / WARN on marker age, WARN if the marker file is missing. Without
`marker`: OK once reachable (rclone keeps no backup time). UNKNOWN when `rclone` is not installed.
No actions.

### `snapper`

| Key | Req | Default | Meaning |
| --- | --- | --- | --- |
| `source` | yes | | snapper config name (`root`, `home`). |
| `fresh_warn_h`, `fresh_crit_h` | no | defaults | Newest-snapshot age. |

CRIT / WARN on newest snapshot age, WARN if none. UNKNOWN when `snapper` is missing (needs 0.10+
for `--jsonout`) or the agent user lacks access (add it to `ALLOW_USERS` in
`/etc/snapper/configs/<name>`). No actions.

### `removable`

An external drive as the 3-2-1 "2nd media" leg. Monitoring reads only `/dev/disk/by-*` and the
mount table (no privilege); backups run on demand.

| Key | Req | Default | Meaning |
| --- | --- | --- | --- |
| `uuid` or `by_id` | yes (one) | | Stable drive identity: filesystem UUID (`/dev/disk/by-uuid`) or a `/dev/disk/by-id` name. Never `/dev/sdX`. |
| `mount` | yes | | Where it is mounted when present (fstab with `nofail`). |
| `source` | single-source mode | | Live tree to copy. Ignored once the drive has confirmed links. |
| `dest_subpath` | no | drive root | Folder under `mount` for single-source mode. |
| `tool` | no | `rsync` | Only `rsync` is supported. |
| `exclude` | no | `[]` | rsync `--exclude` patterns (single-source mode). |
| `mirror` | no | false | `rsync --delete`. Default is additive (never deletes on the drive). |
| `detach_warn_d` | no | `defaults.removable_detach_warn_d` (45) | Days since the last sync before the plug-me-in nudge. |
| `remind_every_d` | no | 7 | Re-nudge cadence while overdue. |
| `fresh_warn_h`, `fresh_crit_h` | no | defaults | Age of the last backup while attached, **capped at WARN**. The defaults (28/50h) suit a daily job; raise them for a drive you sync monthly. |

| Severity | When |
| --- | --- |
| WARN | Attached but not mounted; mounted read-only; attached with last backup >= `fresh_warn_h` (capped, never CRIT) or no last backup found; detached and over `detach_warn_d` since the last backup. Overdue nudges push to Gotify and repeat every `remind_every_d`. |
| OK | Detached within the grace, detached and never backed up, or attached and fresh. A removable is never CRIT. |

"Last backup" is the newest `.cairn-lastbackup` stamp on the mounted drive (in `dest_subpath`, or
under `cairn/<host>/<slug>/`). A full drive never raises severity; the used % is display only.

**Link-driven mode.** From the card an admin runs **Detect matching datasets** (finds monitored dataset trees already
on the drive, with a dry-run rsync census), then confirms links, or adds one by hand. A confirmed
link maps one dataset target (by name) to a folder on the drive; a hand-added link defaults to
`cairn/<host>/<slug>` (slug = the dataset's `source` with `/` and other unsafe characters turned into `_`). Folders must not be
the drive root or nest. Each link has its own excludes and mirror flag. Once links exist, **Back up
now** copies every linked dataset (the target's own `source` / `dest_subpath` are ignored), stamps
each on success, and credits that dataset in the 3-2-1 scorecard.

Encryption guard: linking a dataset whose target has `encrypted: true` (on any agent) is refused
unless the link request passes `allow_plaintext`, and at backup time the agent skips any linked
dataset whose ZFS `encryption` property is not `off` (a file copy would be plaintext).

Dashboard actions: **Back up now** and **Mirror** (`--delete`, extra confirm) only while attached
and mounted read-write; **Detect matching datasets**, **Verify content** (census, xattr or full-hash
check; a clean content verify counts as fresh), **Move under cairn/** (move an existing tree into `cairn/<host>/<slug>`
on the same drive). Backups run detached and survive an agent restart. Requires `rsync` and
`findmnt` on the host agent; `pre_cmd` / `post_cmd` wrap the whole run once.

### `smart`

Per-disk SMART health, one status per disk named `smart:<by-id>`. USB / removable disks are skipped
(their removable card covers them).

| Key | Req | Default | Meaning |
| --- | --- | --- | --- |
| `smartd_window_h` | no | 72 | How far back to read smartd's journal for alerts. |

**Default (sudoless):** disks come from `smartctl --scan`; health comes from smartd's journal
(`journalctl -u smartd`, then `-t smartd`). Each disk is OK unless smartd logged, in the window:

- CRIT: "failed SMART" / "back up data now";
- WARN: pending or uncorrectable sectors, error count increased, below threshold, failing now,
  read failure, failed self-test.

**Opt-in detail:** `CAIRN_SMART_DETAIL=1` plus `grant-access.sh --smart-detail` (installs the
scoped wrapper, `CAIRN_SMART_WRAPPER`, default `/opt/cairn/phase1/smart-probe.sh`) reads the full
`smartctl -a` attribute table, cached for `CAIRN_SMART_TTL` seconds (default 24h, re-read early when
smartd flags a change). A root agent always uses detail. Detail adds: CRIT on SMART health FAILED;
WARN on reallocated / pending / offline-uncorrectable sectors, UDMA CRC errors (cable/link), NVMe
critical warning, NVMe spare at or below threshold, SSD wear >= 90%; UNKNOWN when no
`smart_status` could be read. smartd alerts are merged on top.

No actions. Needs `smartctl` and journal read access (`adm` / `systemd-journal`) for alerts.

### `kernel-errors`

Counts disk I/O, link-reset and HBA errors in the kernel log: the only trace of a transient fault
that ZFS self-healed.

| Key | Req | Default | Meaning |
| --- | --- | --- | --- |
| `window_h` | no | 24 | Look-back for `journalctl -k`. |
| `crit_count` | no | 10 | Error lines for CRIT. |
| `rescan_storm` | no | 20 | SCSI rescans for a WARN "rescan storm". |
| `log_file` | no | | Plain-text log to read when `journalctl -k` is unavailable. |

Source order: `journalctl -k --since -<window_h>h`; else `log_file`, `/var/log/kern.log`,
`/var/log/syslog` (first readable; last 20000 lines of the current file, so `window_h` does not
apply). CRIT at >= `crit_count` errors, WARN on any error or a rescan storm, UNKNOWN when no source
is readable. No actions.

### `backupninja-handler`

One status per backupninja handler (`<name>:<handler>`), parsed from the log and reports dir, so
the agent does not need to read the root-only `/etc/backup.d`.

| Key | Req | Default | Meaning |
| --- | --- | --- | --- |
| `source` | yes | | Handler dir, e.g. `/etc/backup.d` (last-resort handler list). |
| `log` | no | `/var/log/backupninja.log` | Log to parse. |
| `reports` | no | `/var/lib/backupninja/reports` | Preferred handler list. |
| `jobs` | no | | `{ "<handler>": { backs_up: "...", schedule: "..." } }` labels per handler. |
| `schedule` | no | | Fallback schedule label when the log does not show one. |
| `fresh_warn_h`, `fresh_crit_h` | no | defaults | Last-run age (one value for every handler). |

Last log line for the handler: Fatal -> CRIT, Warning -> WARN, finished/Info -> OK, no mention ->
UNKNOWN. Then last-run age raises to WARN / CRIT. UNKNOWN for the whole target when no handlers can
be listed (needs the `adm` group for the log). No actions.

### `schedules`

systemd timers for scheduled backup jobs, one status per timer (`<name>:<kind>`): schedule, next
and last run, recent journal errors.

| Key | Req | Default | Meaning |
| --- | --- | --- | --- |
| `units` | no | syncoid + sanoid | List of `{ kind, timer, label, service }`. `kind`, `timer`, `label` are required per unit; `service` enables journal errors. |

Default units: `syncoid.timer` / `syncoid.service` and `sanoid.timer` / `sanoid.service`. A timer
not installed is skipped; a disabled or masked timer is OK ("intentionally off"). WARN when the
timer's last Result is not success, or (kind `syncoid`) the service's last exit status was non-zero.
Journal error lines are shown but do not raise severity. UNKNOWN when no listed timer exists.
`kind: syncoid` also lists the source -> dest pairs from `syncoid.service`'s ExecStart; any other
kind is described as "ZFS snapshots per sanoid.conf". Reads `systemctl` and the journal, no root.
No actions.

### `zfs-events`

A ZFS event timeline from zed's journal (the stock `all-syslog.sh` zedlet).

| Key | Req | Default | Meaning |
| --- | --- | --- | --- |
| `window_h` | no | 168 | Timeline span. |
| `alert_h` | no | 48 | Only events this recent drive severity. |

Within `alert_h`: CRIT when a vdev's latest state is FAULTED / UNAVAIL / REMOVED or a pool is
SUSPENDED / FAULTED; WARN when a vdev is DEGRADED or on checksum / io / data / deadman / delay /
io_failure events. A vdev that flapped but ended ONLINE, or a vdev name that is no longer in an
ONLINE pool (a renamed device), does not alert. UNKNOWN when the journal cannot be read. Needs
`journalctl -t zed` access. No actions.

### `reachability`

SSH-probes a host, typically from an off-site agent to prove it can still reach home. The agent
reports over the public control plane, so a VPN outage between the two still arrives as an alert.

| Key | Req | Default | Meaning |
| --- | --- | --- | --- |
| `host` (or `ssh`) | yes | | `user@host` or `host`. |
| `port` | no | 22 | SSH port. |
| `key` | no | | Identity file. |
| `probe` | no | `true` | Remote command; `true` passes the pull key's forced command, testing the exact pull path. |
| `tries` | no | 3 | Attempts. |
| `retry_wait_s` | no | 5 | Pause between attempts. |
| `connect_timeout_s` | no | 10 | SSH `ConnectTimeout`. |

OK on the first success, CRIT only when every try fails, UNKNOWN with no `host`. Uses
`ssh -o BatchMode=yes`. Needs an ssh client (absent from the container, where it reads as CRIT).
No actions.

### `aide`

AIDE file-integrity changes nobody has reviewed yet, each with an Accept button.

| Key | Req | Default | Meaning |
| --- | --- | --- | --- |
| `check_cmd` | no | `/usr/local/sbin/aide-check.sh` | Root-owned checker supporting `--list` and `--accept [path]`. |
| `severity` | no | `WARN` | Severity while anything is pending (e.g. `CRIT`). |
| `label` | no | `File integrity (AIDE)` | Card label. |

OK with nothing pending, `severity` with one or more, UNKNOWN when `sudo -n <check_cmd> --list`
fails. Actions: **Accept** (one path) and **Accept all**. Needs a NOPASSWD sudoers rule for exactly
`check_cmd`; see [README: File integrity (AIDE)](../README.md#file-integrity-aide).
