# Getting started from zero

This is for someone new to ZFS, sanoid and cairn. By the end, the data you care about is snapshotted on
a schedule on your main box, copied every night to a second box somewhere else (the **vault**), and
cairn watches both and tells you when anything stops working. Each step says what to run and how to
check that it worked.

## The pieces

| Piece | What it is | Who sets it up |
| --- | --- | --- |
| **ZFS pool** | A set of disks ZFS manages as one (e.g. `rpool`, `tank`). `zpool list` shows them. | You, once per box (outside this guide) |
| **Dataset** | A folder-like filesystem inside a pool (`rpool/apps/wiki`), mounted somewhere (`zfs get mountpoint rpool/apps/wiki`). Snapshots and replication work **per dataset**. | You (step 1) |
| **Snapshot** | A frozen, read-only point in time of one dataset (`rpool/apps/wiki@autosnap_2026-10-14_00:00:01_daily`). Cheap, instant, and the unit everything else copies. | sanoid (step 4) |
| **sanoid** | Takes snapshots on a schedule and deletes old ones, from `/etc/sanoid/sanoid.conf`. Runs every 15 minutes from `sanoid.timer`. **Nothing snapshots a dataset unless sanoid.conf says so.** | `phase1/sanoid-setup.py` (step 4) |
| **syncoid** | Copies a dataset's snapshots to another pool or box, sending only what changed since the last copy. Comes in the `sanoid` package. | cairn's vault pull (step 5) |
| **The vault** | A second box, ideally in another building, that **pulls** a copy of your datasets every night. The vault starts every copy, and nothing on the main box can delete what it holds, so a compromised main box can't wipe the backups. [Why pull, and its limits](architecture.md#why-the-vault-pulls-instead-of-home-pushing) | `./install.sh` (step 5) |
| **cairn** | A dashboard (the **API**, a container on the main box) plus an **agent** on every box that reports what it sees and runs the buttons you press. | `./install.sh` (step 2) |

The flow: your data lives in datasets on the main box → sanoid snapshots them → each night the vault
pulls the newest snapshot of each → cairn checks every step and alerts you when one goes stale.

## 1. Put each thing you care about in its own dataset

Check what you have:

```bash
zpool list          # your pools
zfs list            # your datasets and where they're mounted
```

Creating a pool means choosing disks and a layout; follow the
[OpenZFS docs](https://openzfs.github.io/openzfs-docs/Getting%20Started/index.html) for your distro
(on Debian, `zfsutils-linux` from `contrib`). This guide starts once you have a pool.

Give each app or collection its own dataset, so each can have its own schedule and be copied on its own:

```bash
sudo zfs create -p rpool/apps/wiki                 # -p also creates rpool/apps if needed
zfs get -H -o value mountpoint rpool/apps/wiki      # where it lives, e.g. /rpool/apps/wiki
```

To move existing data in: stop the app, copy it (`sudo rsync -aHAX /old/path/ /rpool/apps/wiki/`),
point the app at the new path, start it, and check it before deleting the old copy.

## 2. Install cairn on the main box

Run as your normal user (not root); it asks for sudo once:

```bash
git clone https://github.com/jmichelsen/cairn && cd cairn
./install.sh            # role: home
```

It installs what's missing (docker or podman, python3-yaml, sanoid, ...), starts the dashboard at
`http://<main box>:8929/` and starts the agent. It may ask to add a vault right away; you can say no
and do step 5 later.

## 3. Tell cairn what to watch: `config/targets.yaml`

Each entry is a **target**. The two you need for this setup:

```yaml
targets:
  - name: rpool                 # the pool itself: health, capacity, scrubs
    type: zfs-local
    source: rpool

  - name: wiki_offsite         # one per dataset copied to the vault
    type: zfs-repl
    tier: A                     # irreplaceable: counts in the 3-2-1 scorecard
    source: rpool/apps/wiki     # the dataset here
    dest: tank/homebox/apps/wiki   # the dataset name it will have ON THE VAULT
    dest_agent: vault           # the vault agent's name (you pick it in step 5)
```

`dest` is just a name on the vault: don't create it there, the first pull does. A common layout is
`<vault pool>/<this box's name>/<same path>`. Every other target type (borg, restic, SMART, removable
drives...) is in [targets.md](targets.md). After editing, restart the agent:

```bash
systemctl --user restart cairn-agent
```

## 4. Snapshot on a schedule (sanoid)

```bash
phase1/sanoid-setup.py
```

It lists the datasets your targets use that sanoid.conf doesn't cover yet and asks what each should
get. For data that lives here, **production** (sanoid's own example) keeps hourly snapshots for 36
hours, dailies for 30 days and monthlies for 3 months; **custom** lets you change those counts. It
shows the entries, appends them to `/etc/sanoid/sanoid.conf` (saving a backup copy first), enables
`sanoid.timer` and offers to take the first snapshots now. Check:

```bash
zfs list -t snapshot rpool/apps/wiki      # you should see autosnap_..._hourly / _daily
```

cairn reads sanoid.conf too: each card's "too old" alarm follows that dataset's own schedule.

## 5. Add the vault

The vault needs ZFS with a pool (e.g. `tank`), SSH, and a user you can log in as. From the main box:

```bash
./install.sh home --add-vault                                  # installs cairn's agent on the vault
./install.sh home --replication --vault-ssh you@vault:2222     # the nightly pull (port optional)
```

`--add-vault` asks for the vault's name (use the `dest_agent` from step 3) and for the vault target
`user@host` or `user@host:port`, can copy your SSH key there, then installs the agent over SSH.

`--replication` sets up the pull and asks for the address and SSH port the **vault** uses to reach
the **main box** (a port forward if the vault is elsewhere). It installs a dedicated pull key that
can only run `zfs send`, gives both sides their ZFS permissions (one sudo each, never destroy),
teaches the vault the main box's SSH host key, installs the nightly timer, offers to run sanoid-setup
on both boxes, and offers the first pull. On the vault the sanoid step is **optional**: a pull never
deletes anything, so by default the vault keeps every snapshot it receives; choose **backup** to
prune old ones (sanoid's example: 30 hourly, 90 daily, 12 monthly). The first pull copies the whole
dataset; later ones send only changes.

Then tell the vault's cairn about the copy, in the **vault's** `~/cairn/config/targets.yaml`, using
the same name as the main box's target, and restart its agent:

```yaml
  - name: wiki_offsite
    type: zfs-local
    source: tank/homebox/apps/wiki
    source_agent: homebox        # the main box agent's name (its hostname on a fresh install;
                                 # older installs: "local"). It's CAIRN_AGENT_NAME in its cairn.env
```

## 6. Check everything

```bash
phase1/doctor.py --vault you@vault:2222
```

On the main box this checks the agent, settings, targets, ZFS permissions, sanoid, then logs in to
the vault, compares the two configs and runs the vault's own checks (including its SSH test back to
the main box). Each problem comes with a `fix:` line. On the dashboard, the dataset should show as one
**pair card** (main box + vault), the vault side with a **Replicate now** button, and the 3-2-1
scorecard should count it.

## When something's wrong

Run `phase1/doctor.py` first. The common ones:

| You see | It means | Fix |
| --- | --- | --- |
| `cannot create snapshots: permission denied` (or send/receive) | Your user lacks a ZFS delegation | `phase1/zfs-perms.py --apply` on that box |
| Pull: `Host key verification failed` (exit 4) | The vault doesn't know the main box's SSH key | Re-run `./install.sh home --replication` |
| Pull: `cannot reach ... Connection timed out` (exit 3) | The vault can't reach the main box on that address/port | Check the port forward / VPN; the `PORT` line in the vault's `~/.config/cairn/replication.conf` |
| Pull: `target exists but has no snapshots matching` | Someone created the dest dataset on the vault by hand | The pull prints the commands: check it's empty, `sudo zfs destroy` it, pull again |
| The copy stops moving, source shows old snapshots | Nothing snapshots the source | `phase1/sanoid-setup.py` on the main box |
| Two separate cards instead of one pair | `dest` on the main box ≠ `source` on the vault, or the names differ | The dashboard's "configuration problems" banner names the mismatch |
| No **Replicate now** on the vault's card | Its target has no `source_agent` | Add it, restart the vault's agent |
| A change to `targets.yaml` doesn't show | The agent reads it at start | `systemctl --user restart cairn-agent` |

More: [README](../README.md) (dashboard, alerts, accounts), [AGENT.md](../AGENT.md) (the agent and its
troubleshooting), [replication/README.md](../replication/README.md) (how the pull is locked down).
