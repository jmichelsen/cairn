# TODO — cairn (server)

## Next

- [x] **applog adopted** 2026-10-19 (0.47.0, live; demo too): `phase1/activity.py` declarations, ASGI middleware,
      `--no-access-log`, `/log` page + `GET /api/v1/backup/log` (admin), `POST /api/v1/backup/events` (any role),
      jobs for heartbeat/digest/db-backup/seed-tokens, json-file log rotation in cairn-deploy/cairn-demo.
      Token `last_used_ts` is stamped on an untraced connection (else every poll is a "change").
- Done 2026-10-18 (0.46.1): share-link tokens moved to `/login#token=`; legacy `?token=` redacted in the access
  log (applog BUGS.md row 1). `share-ro` and `share-ro-2026-10-08` (written to the journal and NPM logs
  before the fix) were revoked 2026-10-19; mint a fresh share token for anyone who used them.
