# cairn replication (vault pull)

The 3-2-1 off-site leg: a remote **vault** pulls ZFS datasets from **home** on a nightly timer, over a
dedicated, strictly-restricted SSH key. Pull (not push) so the vault - typically behind a NAT at a
friend's house - only makes outbound connections; home never needs an inbound path to the vault.

## Pieces

| File | Runs on | What it is |
|------|---------|------------|
| `pull-command.sh` | **home** (send side) | forced-command wrapper for the pull key. Deny-by-default; permits only read-only `zfs`/`zpool` verbs + syncoid's harmless probes; runs validated commands via a shell so quoted dataset names parse, safe because every chaining/redirect/substitution metacharacter is rejected first. |
| `vault-pull.sh` | **vault** | config-driven `syncoid` runner (see below). |
| `cairn-pull.service` / `.timer` | **vault** | systemd `--user` oneshot + nightly timer (02:15, up to 10 min jitter). |
| `replication.conf.example` | **vault** | copy to `~/.config/cairn/replication.conf`. |

## vault-pull.sh

```
vault-pull.sh [CONF] [--conf CONF] [--only NAME]
```

- `--conf CONF` (or a bare `CONF` argument): the config file. Default
  `~/.config/cairn/replication.conf`.
- `--only NAME`: pull just the one SET named `NAME`. Exit 2 if no SET has that name. Without it,
  every SET is pulled (the nightly timer).

Each SET runs `syncoid --no-privilege-elevation --no-sync-snap --no-stream --sshkey KEY
HOME_SSH:source dest`, plus `--sendoptions=w` for a `raw` SET. `--no-sync-snap` means it replicates
home's existing snapshots (e.g. sanoid's) and creates none of its own.

**Reachability probe.** Before any syncoid run it SSHes to home with the pull key and runs `true`
(permitted by the forced command), so it tests the whole path: route, sshd, key auth, forced command.
It retries `PULL_PROBE_TRIES` times (default 4), `PULL_PROBE_WAIT` seconds apart (default 5), to
absorb a cold VPN tunnel that drops the first packet. If every try fails it exits **3** (home
unreachable), distinct from exit 1 (a set failed) and exit 2 (config or usage error).

## Dashboard pull ("Replicate now")

The vault's agent can pull one dataset on demand. "Replicate now" on the vault's `zfs-local` replica
card queues a `pull` action, and the vault agent runs `vault-pull.sh --only <target name>` with the
default config. So **each SET name must equal the vault's `zfs-local` target name** for that
replica. `./install.sh home --replication` names each SET after home's `zfs-repl` target, so give
the vault's `zfs-local` target that same name. The vault agent must be execute-capable.

## How the security holds

- **Key restriction:** the vault's key is in home's `authorized_keys` as
  `restrict,command="…/pull-command.sh"` - no pty, no forwarding, no shell; it can *only* trigger the
  wrapper, which allows only read-only zfs/zpool + probes. This forced command is the real limit on
  what the key can do.
- **Delegation:** the installer gives home's login user `zfs allow send,snapshot,hold` on each
  source pool, only if `send` isn't delegated already. That user is your normal login, so
  delegation is not a hard backstop; the forced command is. The vault user gets
  `create,mount,receive,mountpoint` on each dest pool. No sudo at run time.
- **Pipeline, not plain send:** the wrapper is pipeline-aware - it permits syncoid's normal
  `zfs send | lzop | mbuffer` pipeline (so compression + buffering + resume work, which matters over a
  remote link) by validating EVERY stage: read-only zfs/zpool, or a stream filter with no file access
  (`-o`/`-i`/path tokens rejected, so the filters can't read or write files). Only `|` is allowed as a
  control char; every other metacharacter is rejected, so eval can run a zfs-send pipeline and nothing
  else.

## Setup: `./install.sh home --replication [--vault-ssh user@host[:port]] [--home-port N]`

Run it on **home**. `./install.sh vault` does not set up the pull; it is offered at the end of
`./install.sh home --add-vault`, or run `--replication` on its own any time (idempotent, re-run to
re-sync). It needs key-based SSH from home to the vault. It:

1. detects home's `zfs-repl` targets from `config/targets.yaml` (one SET each, named after the
   target, `raw` when the target is `encrypted`);
2. asks the address the vault uses to reach home, defaulting to home's LAN address (a VPN address or
   hostname also works), and the SSH port it should use, defaulting to the `Port` in home's
   `sshd_config` (22 if none);
3. **home:** `zfs allow send,snapshot,hold` on each source pool, where any of them is missing;
4. **vault:** generates the dedicated `~/.ssh/cairn-pull` key;
5. **home:** authorizes it as `restrict,command="…/pull-command.sh" <pubkey>`;
6. **vault:** `zfs allow create,mount,receive,mountpoint` on each dest pool, where any of them is
   missing;
7. **vault:** pushes `vault-pull.sh` + the units, writes `~/.config/cairn/replication.conf`, enables
   the nightly timer;
8. optionally runs the first pull.

**Non-standard SSH ports.** Both directions are covered. Home reaches the vault on the port in the
vault target (`--vault-ssh user@host:2222`, `--vault-port 2222`, or `user@host:2222` at the
prompt). The vault reaches home on the port you give at the "SSH port" prompt (or `--home-port`),
which is written to `replication.conf` as `PORT` and used for both the reachability probe and
syncoid (`--sshport`). An alias in `~/.ssh/config` with a `Port` line works too.

For the per-dataset permissions both sides need, `phase1/zfs-perms.py` on each host shows and
grants them (see the main README's *ZFS permissions*).

It does NOT: import the vault's data pool, `apt install sanoid` on the vault (the installer's optional
toolchain step offers that), or add the replica datasets to the **vault's** `targets.yaml` as
`zfs-local`. Add them, named the same as their SETs, so the dashboard shows whether the off-site copy
is current and can pull it on demand.
