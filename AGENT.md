# The agent

`agent.py` is the **one** program that runs on every host - the local machine and any remote
vault - and talks to the API over HTTP. There is no separate local vs remote design and no
file-based path.

Two capabilities:
- **report** (always): collect this host's backup status every `CAIRN_INTERVAL` seconds and POST
  it to the API.
- **execute** (opt-in, `CAIRN_CAN_EXECUTE=1`): poll the API for intents assigned to this agent, run
  them, POST results. Commands are built from **this agent's trusted local `targets.yaml`**,
  never from the wire.

Intent routing is self-organizing: whatever an agent reports, it owns, and the API routes that
target's action intents back to it. A target removed from an agent's `targets.yaml` disappears from
the dashboard at that agent's next report.

The full list of target types and keys is in [docs/targets.md](docs/targets.md).

## Auth (zero-trust)

Every API request needs a credential except a few public routes (`/login`, `/api/v1/identify`,
`/badge/*`, and `/enroll` / `/api/v1/ci/status`, which check their own secret). Agents send
`X-Backup-Token`; browsers use a session cookie from `/login`. Roles:

- **agent** (`CAIRN_API_TOKEN` or an enrollment secret on the agent): report, poll and claim
  intents, post results and live progress, and use the agent-side helper routes (removable links,
  recovery manifests). It **cannot** read the dashboard or queue actions.
- **viewer**: read-only dashboard and views (share links, read-only phones).
- **admin** (`CAIRN_ADMIN_TOKEN`, password accounts with role admin): everything, including
  queueing actions and managing tokens.

**Current limitation:** agent tokens are not bound to an agent name. The API trusts the `agent`
name a report declares, and any agent token can claim another agent's queued intents. Those
intents still only run if the claiming agent's own `targets.yaml` has a target by that name, but
treat every agent token as able to speak for every agent, and revoke a leaked one promptly.

Everything is **hash-at-rest** (the API stores only `sha256(secret)`) and **per-credential** (one
per box, individually revocable). Two ways an agent authenticates:

**A. Enrollment (recommended, supports rotation).** Each agent holds a long-lived **enrollment
secret** and trades it for a **short-lived access token** via `/enroll`; it re-enrolls
automatically on any `401`. `install.sh vault` sets this up for you. Mint one by hand:
```
# admin API (from anywhere with the admin token):
curl -X POST -H "X-Backup-Token: $ADMIN" -H 'Content-Type: application/json' \
     -d '{"role":"agent","label":"vault"}' https://backups.example.com/api/v1/backup/tokens
# or on the API host:
docker compose exec api python3 /app/phase1/cairn-token.py mint --role agent --label vault
```
Put the secret in the agent's **`CAIRN_ENROLL_SECRET`**. The access token lives only in memory and
expires (`CAIRN_ACCESS_TTL`, default 24h); the agent refreshes it silently.

**B. Static token (simplest).** Put a fixed token in `CAIRN_API_TOKEN` and list it in the API's
`CAIRN_AGENT_TOKENS`. No rotation. `install.sh home` uses this for the local agent.

### Managing tokens

| Operation | Command | Effect |
| --- | --- | --- |
| **Scheduled rotation** | (automatic) | access tokens expire; the agent re-enrolls. Nothing to do. |
| **Forced rotation** (a token *leaked*, box is fine) | `POST /api/v1/backup/tokens/<label>/rotate` | kills the current access token now; the box re-enrolls with its (non-leaked) enrollment secret and resumes. |
| **Revoke** (box *compromised* / decommissioned) | `DELETE /api/v1/backup/tokens/<label>` or `cairn-token.py revoke --label <label>` | kills the secret **and** its access tokens - terminal; provision a new credential out-of-band. |
| **List** | `GET /api/v1/backup/tokens` or `cairn-token.py list` | labels, roles, kind, last used (never the secret) |

`cairn-token.py mint --role admin|agent|viewer --label <name>` mints any role (a viewer token never
expires and can be shared as `/login?token=<token>`). A lockout guard refuses to revoke the last
active admin. Password accounts are managed with `cairn-user.py`, see the
[README](README.md#accounts-and-sharing).

## Settings (env)

The host agent's unit (`~/.config/systemd/user/cairn-agent.service`) sets its main settings with
`Environment=` lines, and the agent also reads `config/cairn.env` (path from `CAIRN_ENV`) for its
token and anything else. A value set in the unit **wins** over the same name in `cairn.env`. After
editing the unit: `systemctl --user daemon-reload && systemctl --user restart cairn-agent`.

| Variable | Default | Meaning |
| --- | --- | --- |
| `CAIRN_API_URL` | `http://localhost:8929` | base URL of the API, e.g. `https://backups.example.com` |
| `CAIRN_API_TOKEN` | | static agent token (option B) |
| `CAIRN_ENROLL_SECRET` | | enrollment secret (option A) |
| `CAIRN_AGENT_NAME` | `local` | unique per agent: the key everything it reports is filed under. `./install.sh home` writes the box's short hostname for a fresh install (older installs and an unset value: `local`); the vault defaults to `vault`. To change it later without losing history, use `phase1/cairn-agent-rename.py` (below) |
| `CAIRN_TARGETS` | `targets.yaml` beside `agent.py` | the targets this agent manages (the unit points at `config/targets.yaml`) |
| `CAIRN_CAN_EXECUTE` | `0` | `1` = run actions, `0` = report-only |
| `CAIRN_INTERVAL` | `900` | seconds between cycles (the shipped home unit uses 120, a vault 300) |
| `CAIRN_DRYRUN` | `0` | `1` = every action becomes a dry-run (see below) |
| `CAIRN_ACTION_TIMEOUT` | `7200` | seconds before a running action is killed |
| `CAIRN_ENV` | `/etc/cairn/cairn.env` | env file to load (the unit points at `config/cairn.env`) |
| `CAIRN_STATE_DIR` | `~/.local/state/cairn` | detached-job registry and removable rsync logs |
| `CAIRN_HTTM` | `1` | `0` turns off everything that needs httm (see Recovery) |
| `CAIRN_HTTM_SCOPE` | `1` | `0` runs httm without its own systemd scope |
| `CAIRN_RECOVER_WALK_HOURS` | `1-6` | local hours the nightly recovery scan may run (`22-6` wraps) |
| `CAIRN_RECOVER_WALK_MAX` | `1` | datasets scanned per cycle (`0` = no nightly scan) |
| `CAIRN_RECOVER_WALK_TIMEOUT` | `900` | seconds per httm scan |
| `CAIRN_DIRTREE_CAP` | `20000` | folders kept in a dataset's browse tree |
| `CAIRN_VERS_SCAN_CAP` / `_SHOW_CAP` / `_BUDGET` | `6000` / `1200` / `300` | files scanned, files shown, seconds per Versions scan |
| `CAIRN_SNAP_CACHE_TTL` | `1800` | seconds a dataset's snapshot list is cached |
| `CAIRN_SMART_DETAIL` | off (on as root) | `1` = read SMART attribute tables through the sudo wrapper |
| `CAIRN_SMART_WRAPPER` | `/opt/cairn/phase1/smart-probe.sh` | root-owned smartctl wrapper |
| `CAIRN_SMART_TTL` / `CAIRN_SMART_CACHE` | `86400` / `~/.cache/cairn` | SMART detail cache |
| `CAIRN_ZPOOL_WRAPPER` | `/opt/cairn/phase1/zpool-scrub.sh` | root-owned scrub wrapper |
| `CAIRN_SANOID_DERIVE` | `1` | `0` = don't derive freshness from sanoid.conf |
| `CAIRN_SANOID_CONF` / `_DEFAULTS` | `/etc/sanoid/sanoid.conf` / `sanoid.defaults.conf` | where to read sanoid policy |
| `CAIRN_MDNS` | `0` | `1` = advertise `_cairn._tcp` for the phone app (only on the agent next to the API; needs `python3-zeroconf`) |
| `CAIRN_MDNS_ADDR` / `_PORT` | auto / `8929` | address and port to advertise |
| `CAIRN_USER_AGENT` | `cairn-agent/1.0` | HTTP User-Agent (some proxies block Python's default) |
| `BORG_BASE_DIR` / `BORG_CACHE_DIR` | `/tmp/borg-base` / `/tmp/borg-cache` | borg's state while reading repos |

## Local agent (main host)

`./install.sh home` installs and starts the host agent as a systemd **user** service
(`cairn-agent.service`, with linger so it runs at boot), execute-capable, with the API at
`http://localhost:8929`. That is the recommended setup.

Privilege comes from grants, not root:
- **ZFS actions** use `zfs allow` delegation. `phase1/zfs-perms.py` works out exactly which
  grants this host's targets need and grants the missing ones with `--apply`; the installer runs
  it for you (see the [README](README.md#zfs-permissions)). In short: `snapshot,send,hold` on
  replication sources, `create,mount,receive,mountpoint` on destination pools, and optionally
  `snapshot` on datasets whose Snapshot button you want.
- **Scrub** isn't delegatable, so it needs `sudo phase1/grant-access.sh --scrub`, which installs a
  root-owned wrapper (`/opt/cairn/phase1/zpool-scrub.sh`) and a sudoers rule for exactly that. The
  Scrub button only appears on a pool's root dataset once `sudo -n` can run the wrapper.
- **Reads** (borg repos, backupninja logs, the kernel log) come from `grant-access.sh`, which the
  installer runs once. SMART health needs no sudo; the attribute table is opt-in with
  `--smart-detail`.

## Upgrading past read-only (container to host agent)

If you started with the report-only container agent (`docker compose --profile container-agent
up`), replace it with the host agent to unlock actions, SMART alerts, the zed timeline and the
recovery browser. **Stop the container agent first:** both report as `local`, so running both
makes the agent flip between report-only and execute-capable, and clicks intermittently fail with
"report-only".

The simplest switch is `docker compose --profile container-agent rm -sf agent`, then
`./install.sh home`. To do it by hand:

```
cd ~/cairn
docker compose --profile container-agent rm -sf agent   # 1. drop the container agent (api stays up)
./run-local-agent.sh report             # 2. report once, report-only - proves clean takeover
./run-local-agent.sh dry                # 3. execute + dry-run: buttons appear, clicks only dry-run
                                        #    (click one in the UI, read the [DRY-RUN] result, Ctrl-C)
install -Dm644 cairn-agent.service ~/.config/systemd/user/cairn-agent.service   # assumes ~/cairn
systemctl --user daemon-reload          # 4. install the persistent unit
systemctl --user enable --now cairn-agent.service
loginctl enable-linger "$USER"          #    keep it running across logout/reboot (may need root once)
```

Then click a **safe real action** (e.g. Snapshot on one dataset) and watch it reach `done`.
`systemctl --user status cairn-agent` / `journalctl --user -u cairn-agent -f` for logs.

**Rolling back:** `systemctl --user disable --now cairn-agent.service`, then
`docker compose --profile container-agent up -d agent`.

## Remote agent (the off-site vault)

Same `agent.py` on the vault box, pointed at the API's public URL. On home, `./install.sh home
--add-vault` (or the "add a remote vault?" prompt) mints an enrollment secret and writes a
`vault-install.conf` bundle; on the vault, `./install.sh vault --config vault-install.conf`
installs the agent as a user service with its own `config/targets.yaml` (default interval 300 s),
and an execute-capable vault also gets the scrub wrapper. Replication itself is set up from home,
see [replication/README.md](replication/README.md).

- Only **outbound HTTPS** from the vault, nothing inbound at the remote site.
- The vault agent carries **no SMTP/Gotify creds**; the API does all alerting centrally.
- Its `targets.yaml` defines what it manages (its local pool, its replicas) and the fixed
  commands it will run. A compromised API can only enqueue menu actions; it can't inject commands.
- Encrypted zero-knowledge replicas stay ciphertext: the agent reports snapshot timestamps and pool
  health without the key; it never needs to unlock anything.

## Actions

Dashboard buttons `POST /api/v1/backup/actions`. The API queues an intent for the target's owning
agent; that agent picks it up on its next poll, runs it, and posts the result (a failure alerts as
CRIT, success is an INFO notice). Before you confirm, the dashboard shows the exact command the
click will run.

| Action | Button | What the agent runs | Targets |
| --- | --- | --- | --- |
| `snapshot` | Snapshot | `zfs snapshot <src>@cairn-manual-<ts>` | any with a dataset `source` |
| `sync` | Replicate / no-snap | `syncoid --no-privilege-elevation --no-stream [--sendoptions=w] [--no-sync-snap] <src> <dst>` | `zfs-repl` |
| `pull` | Replicate now (vault) | `replication/vault-pull.sh --only <target name>` | vault `zfs-local` |
| `scrub` | Scrub | `sudo -n /opt/cairn/phase1/zpool-scrub.sh <pool>` | `zfs-local` on a pool root |
| `backup-now` | Back up now | detached incremental `rsync -aHXh` per confirmed dataset link | `removable` |
| `removable-scan` | Detect matching datasets | read-only match + `rsync -n` census, pushed as suggestions | `removable` |
| `removable-verify` | Verify content | read-only census / xattr / hash / content comparison | `removable` |
| `removable-relocate` | Move under cairn/ | renames a tree on the drive into `cairn/<host>/<dataset>` | `removable` |
| `recover-points` | Points | `zfs list -Hp -t snapshot -o name,creation -s creation -d 1 <src>` | dataset targets |
| `recover-search` / `recover-deleted` | Versions / Deleted | `httm ...` (see Recovery) | dataset targets |
| `recover-versions` / `recover-dirtree` / `recover-walk` | Scan here / browse / Refresh | httm scans and folder-tree builds stored on the API | dataset targets |
| `restore` | Restore | copy a snapshot version into `.cairn-restores/` (see Recovery) | dataset targets |
| `aide-accept` | Accept / Accept all | `sudo -n <check_cmd> --accept [path]` | `aide` |

Snapshot, sync and backup-now can be wrapped in [pre/post hooks](README.md#prepost-hooks-eg-consistent-vm-snapshots).

**Detached jobs.** Back up now can take hours, so it runs as one script in a transient
`systemd-run --user` unit (`cairn-job-*`, `setsid` if there's no user bus). It survives agent
restarts and updates; the agent streams rsync progress to the Activity pane and posts the result
when the job finishes (or gives up on it after 12 h with no result).

**Self-update.** The **Update** button on an agent tile tells that agent, at its next report, to
run `install.sh --update` in its own transient unit: pull the code, keep `config/`, restart.

## Dry-run

Two switches, same effect: the **Dry-run** box in the dashboard's top bar (per click), or
`CAIRN_DRYRUN=1` (every action on that agent). For the host agent set it in the unit file
(`Environment=CAIRN_DRYRUN=1`, then `daemon-reload` and restart): the unit's own
`CAIRN_DRYRUN=0` line wins over `cairn.env`. `./run-local-agent.sh dry` runs a dry-run agent by
hand.

A dry-run never runs the mutating command. The result starts with
`[DRY-RUN] would run: <command>`, followed by a real read-only probe where one exists:

- `sync`: `zfs send -nvP` estimate of exactly what would be sent (or "already up to date" /
  "diverged").
- `scrub`: `zpool status <pool>`.
- `backup-now`: `rsync -n` per dataset link.
- `snapshot`, `pull`, `restore`, `aide-accept`, `removable-relocate`: a note describing what would
  happen.
- Recovery listings, removable scan and verify are read-only, so they run normally.

Pre/post hooks are listed, not run. Self-update ignores dry-run.

## Recovery (httm)

Recovery is exposed as agent actions (same intent/allowlist path, so it inherits auth + routing).
Buttons per dataset target: **Points / Deleted / Versions**, plus **Restore**.

| Action | Command the agent runs | Notes |
| --- | --- | --- |
| `recover-points` | `zfs list -Hp -t snapshot -o name,creation -s creation -d 1 <src>` | **fast**, no snapshot automount |
| `recover-search {path}` | `httm --json --recursive <mp>/<path>` | versions of a file/dir across snapshots |
| `recover-deleted {path?}` | `httm --deleted=only --recursive --json <mp>/<path>` | files gone from live but present in snapshots |
| `recover-versions {path}` | enumerates files itself, then `httm --json --omit-ditto` in batches of 400 | the Versions browser; merged into a stored manifest |
| `restore {version}` | `mkdir -p <mp>/.cairn-restores` then `cp -av --no-clobber <version> <mp>/.cairn-restores/<name>.restored-<ts>` | **copy-only**, never overwrites a live file |

httm and the folder walks run under `ionice -c3 nice -n19` when available.

Guardrails: user-supplied paths (the browse path, the version, an API-supplied restore `dest`) are
resolved and **rejected if they leave the dataset's mountpoint**.

**Nightly scan.** Between `CAIRN_RECOVER_WALK_HOURS` (default 1-6 local time), the agent refreshes
each dataset whose scan is older than the API's `CAIRN_RECOVER_WALK_INTERVAL` (default daily),
`CAIRN_RECOVER_WALK_MAX` per cycle: a deleted-files list (`httm --deleted=only --recursive
--one-filesystem --no-live --json <mp>`, newest 2000 kept) and a folder tree for browsing. The
dashboard reads those, so **Deleted** opens instantly; **Refresh** rescans now, and **Scan here**
fills in Versions on demand. The API also caches listing results for `CAIRN_RECOVER_CACHE_TTL`
(600 s) and merges duplicate clicks.

**Perf caveat:** httm browses `.zfs/snapshot`, which **auto-mounts every snapshot**: slow on
datasets with many snapshots (tens of seconds to minutes the first time). Use **Points** for the
common "when can I recover from" question. The vault contributes recovery-point *timestamps* only
(ciphertext at rest; file-level recovery from it means pulling a snapshot home).

**httm is optional.** Without it (not installed, or `CAIRN_HTTM=0`) everything else works:
monitoring, actions, **Points**, restore and the folder tree. Only **Deleted** / **Versions** /
version search need it; they report "httm is disabled/not installed" instead of running, and the
nightly deleted-files scan records that and moves on. To opt out on the host agent, add
`CAIRN_HTTM=0` to `config/cairn.env` (or `Environment=CAIRN_HTTM=0` in the unit), then restart the
agent.

**Stuck httm.** If a `.zfs/snapshot` automount wedges in the kernel, httm can't be killed (not even
SIGKILL) until a reboot. The agent runs each httm in its own transient `systemd-run --user --scope`
(`cairn-httm-*.scope`), so a stuck one doesn't delay agent restarts, and while one is stuck the
agent skips new httm runs and says so instead of piling up more. Find them with
`ps -o pid,stat,etime,wchan:32,args -C httm` (state `D` = stuck in the kernel); the kernel log
usually shows a "blocked for more than 120 seconds" trace naming the ZFS call.

## Testing an action safely

1. Turn on **Dry-run** in the top bar and click a dataset's **Replicate**. The result shows
   the exact command and a `zfs send -nvP` estimate of what it would send.
2. Turn Dry-run off and click again: syncoid takes a fresh snapshot, sends it, and the lag resets.

(A common cause of "lag" is a dataset that replicates fine but stopped being snapshotted, i.e. it
isn't in `sanoid.conf`, so the real fix is to add it there.)

## Renaming an agent

An agent's history (targets, status, retired targets, removable links, past actions) is filed under
its `CAIRN_AGENT_NAME`, so changing only that setting starts its cards over and leaves the old name
behind as a silent agent that alerts. To rename the main box's agent, run on that box (the one with
the dashboard):

```bash
./install.sh --rename-agent homebox
```

It finds the current name (the unit's `Environment=` line, else `cairn.env`, else `local`), shows
what will move, and on a yes: stops the agent, renames it in the API's database (a backup is taken
first; one transaction), switches the name where this box sets it, and starts the agent again. If
the rename fails, the agent comes back under its old name and nothing changes. With
`CAIRN_VAULT_SSH` set, it then offers to change `source_agent: <old>` on the vault and restart the
vault's agent; otherwise do that by hand.

**Renaming an agent on another box** (e.g. a vault): the database lives with the API, so run the tool
in the API container, with that agent stopped, then set its new `CAIRN_AGENT_NAME` and start it:

```bash
systemctl --user stop cairn-agent                                                   # on the vault
docker compose exec api python3 /app/phase1/cairn-agent-rename.py vault offsite --dry-run   # API host
docker compose exec api python3 /app/phase1/cairn-agent-rename.py vault offsite --force
# on the vault: CAIRN_AGENT_NAME=offsite in its cairn.env (or unit), then start the agent;
# on the main box: dest_agent: vault -> offsite in its targets.yaml, restart its agent
```

(`podman compose exec ...` with Podman.) The tool refuses a name already in use. It also refuses
while the old agent reported recently, since a running agent would re-create the old name; it can't
tell a just-stopped agent from a running one, hence `--force` once you've stopped it. Start the
agent under the new name only after the rename succeeded, or the new name appears as a separate
empty agent. The dashboard's configuration banner lists any `dest_agent` / `source_agent` still
naming the old agent.

## Troubleshooting

**Start with the doctor.** `phase1/doctor.py` on the affected box checks the service, settings, API
access, `targets.yaml`, ZFS datasets and delegations, the vault pull and what the agent would report
now, and prints a fix for each problem; the dashboard's "configuration problems" banner covers what
spans agents. See [README: Checking a setup](README.md#checking-a-setup-doctor). The entries below
explain the common ones in more depth.

**Borg repos show UNKNOWN / "Restore points: 0".** The nightly borg runs as **root**; with root's
default umask it writes new repo segment files mode `0600`, unreadable by the non-root agent, so
every borg repo degrades to UNKNOWN and the restore-point count drops to 0 (the card's reason says
so). **Fix: re-run `sudo phase1/grant-access.sh`.** It makes the existing files group-readable
(`backup` group, setgid dirs) and adds `--umask 0027` to each backupninja borg handler's create,
prune and compact options so future segments stay readable. (Running the agent as root avoids
this but gives up least privilege.)

**Borg still UNKNOWN after grant-access.sh, yet `borg info` works in your shell.** The
`systemd --user` agent isn't carrying the `backup` group: a user manager started *before* you joined
the group can't gain it, and a user unit can't add a group its manager lacks. The shipped unit works
around this by wrapping the agent in `sg backup` (re-reads the group list at exec). The clean
alternative is to restart the user manager so it re-reads membership - `sudo systemctl restart
user@$(id -u).service` (or reboot) - after which the `sg` wrapper is redundant.

**Agent restarts take minutes.** Something in the agent's group won't exit, almost always a stuck
httm on an agent older than 0.34.4 (see *Stuck httm*). Update the agent; a reboot clears the stuck
process.

**`cannot create snapshots : permission denied` (or send/receive denied).** The agent's user lacks
a ZFS delegation. Run `phase1/zfs-perms.py` as that user: it shows what's missing and why, and
`--apply` grants it. The agent also checks this every cycle and puts a "ZFS permission missing"
WARN on the affected card. A grant made from a root shell (`sudo -i`) with `$USER` went to root, not you.

**Replicate warns `cannot destroy snapshots: permission denied`.** The replication still succeeds;
syncoid just can't prune its old sync-snapshots on the source because the agent user lacks `destroy`
on that pool (e.g. you deliberately keep the source pool read-only). Either use **no-snap**
(sends existing snapshots, creates none to prune), or delegate `destroy` *scoped to the
replicated datasets only* (`zfs allow -u <user> destroy pool/dataset`), never pool-wide.

**SMART cards show no attribute table.** Default SMART health comes from `smartctl --scan` and
smartd's journal, without sudo. The per-drive attribute table needs the opt-in wrapper:
`sudo phase1/grant-access.sh --smart-detail` (or `./install.sh --smart-detail`), and
`CAIRN_SMART_DETAIL=1` on the agent. The agent calls the root-owned
`/opt/cairn/phase1/smart-probe.sh`, not the user-writable repo copy; set `CAIRN_SMART_WRAPPER` if
you deployed it elsewhere.

**A card I don't want, or a renamed target lingering.** Remove it from that agent's
`targets.yaml` and it disappears at the next report. To keep a reported target off the board, use
the card's **Hide** (unhide from the Hidden pane).

**Encrypted replica fails: "cannot receive incremental stream: inherited key must be loaded".** The
destination is a zero-knowledge copy (its key is deliberately unavailable). Flag the target
`encrypted: true` so the agent sends **raw** (`--sendoptions=w`); a non-raw send needs the dest key
loaded and would defeat the zero-knowledge property.

**Action buttons missing or "report-only".** The target is owned by a report-only agent
(`CAIRN_CAN_EXECUTE=0`). Run an execute-capable agent on the owning host (see *Upgrading past
read-only*). No **Scrub** button: install the scrub wrapper with `grant-access.sh --scrub`; it only
appears on a pool's root dataset.
