# cairn replication (vault pull)

The 3-2-1 off-site leg: a remote **vault** pulls ZFS datasets from **home** on a nightly timer, over a
dedicated, strictly-restricted SSH key. Pull (not push) so the vault - typically behind a NAT at a
friend's house - only makes outbound connections; home never needs an inbound path to the vault.

## Pieces

| File | Runs on | What it is |
|------|---------|------------|
| `pull-command.sh` | **home** (send side) | forced-command wrapper for the pull key. Deny-by-default; permits only read-only `zfs`/`zpool` verbs + syncoid's harmless probes; runs validated commands via a shell so quoted dataset names parse, safe because every chaining/redirect/substitution metacharacter is rejected first. |
| `vault-pull.sh` | **vault** | config-driven `syncoid` runner; pulls each `SET` with `--no-sync-snap --no-stream --compress=none`. |
| `cairn-pull.service` / `.timer` | **vault** | systemd `--user` oneshot + nightly timer (02:15). |
| `replication.conf.example` | **vault** | copy to `~/.config/cairn/replication.conf`. |

## How the security holds

- **Key restriction:** the vault's key is in home's `authorized_keys` as
  `restrict,command="…/pull-command.sh"` - no pty, no forwarding, no shell; it can *only* trigger the
  wrapper, which allows only read-only zfs/zpool + probes.
- **Delegation is the backstop:** the SSH user on home has only `zfs allow send,snapshot,hold` on the
  sources (no destroy/receive), and the vault has `receive` on its pool. No sudo at run time.
- **Pipeline, not plain send:** the wrapper is pipeline-aware - it permits syncoid's normal
  `zfs send | lzop | mbuffer` pipeline (so compression + buffering + resume work, which matters over a
  remote link) by validating EVERY stage: read-only zfs/zpool, or a stream filter with no file access
  (`-o`/`-i`/path tokens rejected, so the filters can't read or write files). Only `|` is allowed as a
  control char; every other metacharacter is rejected, so eval can run a zfs-send pipeline and nothing
  else. No `--compress=none` needed.

## Setup: `./install.sh home --replication`

The installer automates it (also offered at the end of vault provisioning), and is idempotent - re-run
any time to re-sync. It: (1) detects home's `zfs-repl` sets from `config/targets.yaml`; (2) **home:**
`zfs allow send,snapshot,hold` on each source pool, only where missing; (3) **vault:** generates the
dedicated `~/.ssh/cairn-pull` key; (4) **home:** authorizes it as
`restrict,command="…/pull-command.sh" <pubkey>`; (5) **vault:** `zfs allow create,mount,receive` on the
dest pool, only where missing; (6) **vault:** pushes `vault-pull.sh` + the units, writes
`~/.config/cairn/replication.conf`, enables the nightly timer; (7) optionally runs the first pull.

It does NOT: import the vault's data pool, `apt install sanoid` on the vault (the installer's optional
toolchain step offers that), or add the replica datasets to the **vault's** `targets.yaml` as
`zfs-local` (do that so their freshness - is the off-site copy current? - shows on the dashboard).
