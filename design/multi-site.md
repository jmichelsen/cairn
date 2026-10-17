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

Multiple owners in one control plane are **in scope via sites** (section 5): each site is managed
independently with its own dashboard, settings and users, the way a UniFi controller hosts several
sites. Isolation is logical (one database, every query scoped to a site), which is right for people
who trust whoever runs the server, but not for hostile tenants. Whoever administers the control
plane can see every site.

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

### 5. Sites as independent tenants (S2, S3, shared servers)

Modeled on UniFi's multi-site controller: a **site** is a first-class object, and everything an
operator sees or changes happens inside one site. A single-site install never sees any of this.

**Data model**
- `sites(id, slug, name, settings_json, created_ts)`. Migration creates one `default` site and
  assigns every existing agent, target, ack, intent and link to it.
- Every agent belongs to **exactly one site** (`agents.site_id`). Targets, status, acks, hides,
  intents, removable links, manifests and SMART history inherit the site through their agent.
- Agent names are unique within a site, not globally. Internally rows key on `(site_id, agent)`.

**Enrollment.** An enrollment token is issued *for a site*. The agent it creates is bound to that
site and to its own name (section 2), so an agent can never report into another site.

**Users and tokens.** Each admin/viewer user or token has a site scope: one site, a list, or all
sites. "All sites" is the server owner (UniFi's super admin). The middleware resolves the scope
once per request, and every query goes through one scoping helper so a missed filter is a test
failure, not a leak.

**Dashboard**
- Each site has its own dashboard at `/s/<slug>/`: summary, heatmap, cards, agents, history, the
  same page as today, only showing that site.
- A site switcher in the header, shown only when the user can see more than one site.
- An **All sites** overview for multi-site users: one tile per site with worst severity, copy
  coverage, stale agents and last alert, linking into the site (UniFi's site list).
- With one site, `/` renders that site's dashboard directly and no switcher or overview is shown.

**Per-site settings** (in `settings_json`, editable by that site's admins): alert recipients,
Gotify target, Kuma push URL (one heartbeat per site), digest schedule, severity thresholds, ack
TTL. The mail transport (SMTP host and credentials) stays server-wide.

**A vault serving several sites (S3).** Because an agent belongs to one site, a shared off-site
box runs **one agent per site**: separate agent names, tokens and `targets.yaml` files, each
listing only that site's copies. Isolation stays clean, and each site's dashboard shows its own
off-site legs. (The pull jobs themselves are per-site too; nothing on the vault is shared between
sites except the pool.) A box serving datasets for two sites of the SAME owner can do the same.

**Cross-site pairing is not allowed.** `dest_agent` and `source_agent` resolve within the site.
Pairing across sites would leak one site's dataset names into another.

**What a site admin cannot do:** see other sites, enroll agents into them, change server-wide
settings (mail transport, TLS, update channel), or create sites. Those belong to all-sites admins.

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
| 1 | (agent, name) identity everywhere + migration (becomes (site, agent, name) in phase 4) | S2, S3 safely | medium |
| 2 | Token-bound agents | S4 public, any multi-agent setup | small-medium |
| 3 | Pairing on `dest_agent` + multi-leg cards + `optional` legs | S1, S3 | medium |
| 4 | Sites: `sites` table + migration, site-bound enrollment, scoped users/tokens, per-site dashboards + switcher + All-sites overview, per-site alert settings | S2, S3, shared servers | large |
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
- Every endpoint, called with a token scoped to site A, cannot read or change site B (a parametrized
  test over the full route table, so a new endpoint without scoping fails CI).
- An agent enrolled into site A that reports with site B's agent name is rejected.
- `dest_agent` naming an agent in another site does not pair and the doctor flags it.
- Per-site alert settings: a CRIT in site A goes only to site A's recipients.

## Open questions

- Should a site admin be able to invite users to their own site, or do only all-sites admins
  manage users?
- One database with site scoping (proposed), or a database file per site for stronger isolation
  and easy export of one site? Per-file costs cross-site overview queries.
- Should a site be exportable/movable to another cairn server (e.g. a friend's site that later
  self-hosts)? Cheap to design for now: site-scoped export of config + history.
