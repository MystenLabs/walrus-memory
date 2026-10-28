# Walrus Memory Status

Standalone status service for Walrus Memory.

The browser app calls this service at `/api/status`. The Node server then probes
`STATUS_RELAYER_URL/health` server-side, so the relayer does not need to allow
the status page origin through CORS.

## Local development

Start the local Postgres history database:

```sh
docker compose -f apps/status/docker-compose.yml up -d postgres
```

Then run the status service with `DATABASE_URL` set:

```sh
export DATABASE_URL=postgres://memwal_status:memwal_status_secret@127.0.0.1:5433/memwal_status
pnpm --filter @memwal/status dev
```

This builds the client and runs the same Node server used in production. For
client-only Vite work without the probe API, use:

```sh
pnpm --filter @memwal/status dev:client
```

## Runtime env

- `STATUS_RELAYER_PRODUCTION_URL`: production relayer base URL, default `https://relayer.memory.walrus.xyz`
- `STATUS_RELAYER_STAGING_URL`: staging relayer base URL, default `https://relayer.dev.memwal.ai`
- `STATUS_RELAYER_URL`: backward-compatible fallback for production if `STATUS_RELAYER_PRODUCTION_URL` is unset
- `STATUS_HEALTH_PATH`: health path, default `/health`
- `STATUS_REQUEST_TIMEOUT_MS`: probe timeout, default `8000`
- `DATABASE_URL`: optional Postgres URL used to store uptime checks
- `STATUS_POLL_INTERVAL_MS`: background probe interval, default `60000`
- `STATUS_HISTORY_DAYS`: number of daily uptime buckets to return, default `90`

When `DATABASE_URL` is set, the service creates the `status_checks` table on
startup, polls both relayer health endpoints in the background, and stores each
check. `/api/status` returns the latest checks plus daily uptime buckets for each
component.
status page. If Postgres is unavailable, the service falls back to live checks so
Railway health checks can still pass.
