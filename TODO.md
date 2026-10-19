# TODO — cairn (server)

## Next

- [ ] **Adopt applog** (standing rule since 2026-10-18; standard in `~/private/applog/docs/RULES.md`, steps in
      `docs/ADOPTING.md`, cairn's row in `docs/fleet.md`). Mode: **self-hosted** (the log belongs to whoever
      runs cairn; nothing goes to Jesse).
      - `tools/sync.sh --python phase1` (vendored; never edit the copy).
      - Declarations module: columns shown vs secret (`auth_tokens.hash`, `users.pass_hash`, enroll/CI
        secrets), `secret(token)` where tokens are minted (`/tokens`, `/pair`, `/enroll`, sessions),
        `signed_in()` at password login.
      - `app.add_middleware(applog.asgi.Middleware, who=..., rollback=...)`; `uvicorn --no-access-log` in
        `entrypoint.sh` (then the 0.46.1 `_RedactTokens` filter can go); `POST /events` + operator `GET /log`.
      - Background loops (`_reap_agents`, kuma heartbeat, digest, nightly DB snapshot) in `applog.job`.
      - Tests with `applog.testkit`: planted tokens (incl. legacy `/login?token=`) never appear; all columns declared.
      - Deploy side (cairn-deploy compose): log rotation (journald today, or json-file max-size).
- Done 2026-10-18 (0.46.1): share-link tokens moved to `/login#token=`; legacy `?token=` redacted in the access
  log (applog BUGS.md row 1). Still to decide (Jesse): revoke `share-ro` and `share-ro-2026-10-08`, which were
  written to the journal and NPM logs before the fix.
