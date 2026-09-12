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
- **No pipe:** the wrapper reports stream helpers (mbuffer/lzop/pv) as absent, so syncoid falls back to
  a plain `zfs send` - the wrapper never has to permit a pipeline. `--compress=none` reinforces this.

## Setup (manual, until folded into install.sh)

1. **Home:** `zfs allow <user> send,snapshot,hold <each source>` (skip if already delegated).
2. **Vault:** `zfs allow <user> create,mount,receive <pool>` (skip if already delegated); import the
   data pool; `apt install sanoid`.
3. **Vault:** `ssh-keygen -t ed25519 -f ~/.ssh/cairn-pull -N ""`; copy the `.pub` to home.
4. **Home:** add it to `authorized_keys` as `restrict,command="/home/<user>/cairn/replication/pull-command.sh" <pubkey>`.
5. **Vault:** drop `vault-pull.sh` + the systemd units, write `~/.config/cairn/replication.conf`,
   `systemctl --user enable --now cairn-pull.timer`.
6. **Monitoring:** add the replica datasets to the vault's `targets.yaml` as `zfs-local` so their
   snapshot freshness (is the off-site copy current?) shows on the dashboard.

## TODO: fold into install.sh

A `--replication` / vault-provisioning step should automate 1-6: detect home's `zfs-repl` sets from
its targets.yaml, run the `zfs allow` on both sides (the delegation is NOT set up by the installer
today), exchange the key, and write the runner/timer/conf. Tracked as the next replication feature.
