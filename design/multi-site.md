# Design: multiple sites, multiple vaults, standalone control plane

Status: **proposal, not built.** Written so the work can start when a real deployment needs it.

Cairn today assumes one home and one off-site vault, with the control plane running on the home
host. The agent protocol already allows more: every agent, home or vault, uses the same code path
and talks to the control plane over outbound HTTP(S). This doc covers what changes for the
deployments that are likely to come up next.

## Scenarios

| # | Shape | Example |
|---|---|---|
| S1 | One home, several vaults | home replicates `Pics` to a friend's vault AND to a cloud box |
| S2 | Several sites, each with its own vault(s), one owner | a main house and a cabin, each with its own off-site copy, one dashboard |
| S3 | One vault holding copies for several homes | a single off-site box that pulls from two houses |
| S4 | Control plane on its own host | a small VPS or mesh-only VM; no agent runs there |

Out of scope: **multiple owners in one control plane** (one person's dashboard showing another
person's data). Separate owners run separate cairn instances. Nothing below tries to isolate
tenants from each other.

## What already works

- Agents only make outbound calls (report, poll intents, post results). No inbound ports.
- The control plane reads nothing from its host: no ZFS, no disks. Its only side effect is the
  alert script (email, Gotify, Kuma push). It can run anywhere (S4) today.
- Targets are stored per agent: `targets` is `UNIQUE(agent, name)`, so two agents can both have a
  target called `Pics`.
- A vault declares where each copy came from (`source_agent`), and a home declares where it sends
  (`dest_agent`). Both halves already exist in config.
- Agent self-update pulls code from the public repo, not from the control plane, so a compromised
  control plane cannot push code to agents.

## Gaps found in the current code

1. **Some lookups use the target name alone.** Acknowledgements (`acks.target`), the ack lookup
   (`{x["name"]: x for x in latest_status(...)}`), the action endpoint's fallback when no agent is
   given, and the dashboard's `data-t` card ids all key on the target name. With two homes that
   both have `Pics`, acking one acks the other, and an action can land on the wrong agent.
2. **Pairing ignores `dest_agent`.** `_pair_rows` joins a home's `zfs-repl` to a vault's
   `zfs-local` on `r.dest = l.source` across different agents. If two vaults store the copy under
   the same path (common: same pool layout on both), each home target matches every vault copy.
3. **One off-site leg per card.** A pair view holds one off-site half plus optional local legs.
   S1 needs N off-site legs on one card.
4. **The agent name comes from the request, not the token.** `/report` takes `payload["agent"]`
   and `/intents?agent=` takes a query parameter. Any valid agent token can report as, or claim
   intents for, any agent. Fine for one trusted household; weak once there are more agents, more
   sites, or a public control plane.
5. **No grouping above the agent.** The dashboard is one flat list of cards plus an agents table.

## Design

### 1. Identity: (agent, name) everywhere

The stable key for a target becomes `(agent, name)` in every table and every API.

- `acks`: add `agent`, unique on `(agent, target)`. Migrate existing rows by resolving the name
  against the current targets (unambiguous today because names were globally unique before).
- API: actions, acks, hides and history take `agent` as well as `target`. Drop the name-only
  fallback in `/actions` once the UI always sends the agent.
- Dashboard: card ids and `data-t` become `agent/name`.

### 2. Token-bound agents

Each agent token is bound to one agent name at enrollment (the `auth_tokens` row gets an `agent`
column; enrollment already issues one token per agent).

- `/report`, `/intents`, intent results and progress use the agent bound to the token. A payload
  or query `agent` that disagrees is rejected (403). Log it, it means a copied token or a bug.
- Existing unbound tokens keep working for one release with a warning card ("token not bound to an
  agent, re-enroll"), then become report-only.

### 3. Pairing by declared destination

A pair is `(home agent, zfs-repl target) -> (dest_agent, zfs-local target whose source = dest)`.

- Match on `r.dest = l.source AND r.dest_agent = l.agent`. The old path-only match stays only as
  a fallback when `dest_agent` is unset AND exactly one candidate exists; otherwise the doctor
  raises "ambiguous pairing, set dest_agent".
- A vault's `source_agent` is checked against the home agent the same way, so S3 (one vault, two
  homes, possibly overlapping dataset names) pairs correctly.

### 4. One card, many legs (S1)

A replicated dataset renders as one card owned by the source agent, with a row per leg: each
off-site copy and each local 2nd copy, each showing its own freshness and severity.

- Card severity = worst of the legs, except legs marked `optional: true` in the home's
  `targets.yaml` (a best-effort cloud copy that shouldn't page anyone). Optional legs still show.
- Coverage summary counts copies: "3 copies (1 local, 2 off-site)". The 3-2-1 check passes when
  at least one required off-site leg is fresh.

### 5. Sites (S2, S3)

A **site** is a label grouping agents, set per agent with `CAIRN_SITE` (default: a single
implicit site, so existing installs change nothing).

- Dashboard: one section per site (summary, heatmap, cards). With one site, no site headers are
  drawn, so the current layout is unchanged.
- A vault serving several homes (S3) belongs to its own site (or none). Its legs appear on each
  home's cards, so the vault's data is shown where it matters, under the home it protects.
- Alerts: titles carry the site when there is more than one (`[cabin] Pics CRIT`). Per-site
  routing (different recipients per site) is a later option, not part of the first cut.
- Doctor's cross-agent checks run per site.

### 6. Standalone control plane (S4)

Packaging, not new code:

- A documented standalone compose in this repo: the cairn container, a TLS reverse proxy, a
  persistent volume for `cairn.db`.
- **Database backup** becomes the operator's job: the nightly `VACUUM INTO` copy (already planned)
  plus pulling it off the host.
- **Email:** use an authenticated SMTP provider (`SMTP_HOST/PORT/USER/PASS`, `SMTP_TLS=on`). Some
  VPS providers block outbound mail ports by default.
- **Liveness:** keep the Kuma (or other heartbeat) monitor off the control-plane host, so its
  silence alerts when the host dies.
- **LAN discovery** (`/identify`, mDNS) does not apply; clients pair by URL or QR code.

**Exposure.** A public control plane holds every site's backup status, folder and file names from
version listings, and the ability to queue snapshots, scrubs and copy-only restores on
execute-capable agents. In order of preference:

1. Don't publish it: put the control plane on a private mesh (WireGuard-based VPN) and let agents
   and browsers reach it there.
2. If it must be public: token-bound agents (section 2), an IP allowlist or auth proxy in front of
   the UI, and `CAIRN_CAN_EXECUTE=0` on agents that only need to report.

## Order of work

| Phase | Delivers | Unblocks | Size |
|---|---|---|---|
| 1 | (agent, name) identity everywhere + migration | S2, S3 safely | medium |
| 2 | Token-bound agents | S4 public, any multi-agent setup | small-medium |
| 3 | Pairing on `dest_agent` + multi-leg cards + `optional` legs | S1, S3 | medium |
| 4 | Sites: `CAIRN_SITE`, grouped dashboard, alert prefix | S2 | medium |
| 5 | Standalone compose + docs | S4 | small |

Phases 1 and 2 are worth doing even for single-home installs: they remove ways a mistake or a
leaked token can affect the wrong target.

## Tests to add

- Two homes with identically named targets: ack, hide, history and actions hit only the intended
  agent.
- A token used with a mismatched `agent` is rejected on report and intent poll.
- Home with two vaults using the same dataset path: exactly two pairs, one card, two legs.
- One vault pulling from two homes with overlapping dataset names: each copy pairs with its own
  home.
- Optional leg stale: card stays OK, leg shows WARN.
- Single-site install renders exactly as today (snapshot test of the dashboard HTML).

## Open questions

- Should a site have its own read-only viewer tokens (show one site only), or is one dashboard for
  everything enough for a single owner?
- Should severity thresholds be settable per site (a cabin checked weekly vs a main house daily)?
- Does a vault that serves several homes need its own card group, or is "legs on the home cards"
  plus the agents table enough?
