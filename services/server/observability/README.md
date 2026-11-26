# MemWal observability PoC — OpenObserve (WALM-81)

Self-hosted observability stack: **OpenObserve** + an **OpenTelemetry Collector**
that scrapes the relayer Prometheus `/metrics` and receives OTLP logs/traces
from the relayer. Follows the same OpenTelemetry/OpenObserve convention used by
MailGate: applications export OTLP; metrics scraping/export stays in the
collector.

> Status: **PoC**. Verified locally end-to-end (collector → OpenObserve ingest
> + query). Designed to be pointed at a staging/self-hosted environment; the
> production rollout notes and known gaps are at the bottom.

## Contents

| File | Purpose |
|------|---------|
| `docker-compose.observability.yml` | OpenObserve + OTel Collector services |
| `otel-collector-config.yaml` | metrics scrape + OTLP in → OpenObserve |

## Run

```bash
cd services/server/observability

# Credentials for the OpenObserve root user (change these).
export O2_ROOT_EMAIL=root@memwal.local
export O2_ROOT_PASSWORD='Complexpass#123'

# OTLP/HTTP Basic auth header value = base64("email:password").
export O2_AUTH=$(printf '%s' "$O2_ROOT_EMAIL:$O2_ROOT_PASSWORD" | base64)

# Where the relayer exposes /metrics (defaults to host.docker.internal:8000).
# Point this at your relayer or the main compose stack's published port.
export RELAYER_METRICS_TARGET=host.docker.internal:8000

docker compose -f docker-compose.observability.yml up -d
```

OpenObserve UI: <http://localhost:5080> (log in with `O2_ROOT_EMAIL` / `O2_ROOT_PASSWORD`).

Tear down: `docker compose -f docker-compose.observability.yml down` (add `-v` to wipe data).

## Relayer OTLP config

Set these on the relayer when OpenObserve is available:

```bash
export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:5080/api/default
export OTEL_EXPORTER_OTLP_HEADERS="Authorization=Basic $O2_AUTH"
export OTEL_SERVICE_NAME=memwal-relayer
```

For Railway dev, use the private service URL:

```bash
OTEL_EXPORTER_OTLP_ENDPOINT=http://openobserve.railway.internal:5080/api/default
OTEL_EXPORTER_OTLP_HEADERS="Authorization=Basic <base64(email:password)>"
OTEL_SERVICE_NAME=memwal-relayer-dev
```

The relayer appends `/v1/traces` and `/v1/logs` automatically. If a backend
requires signal-specific URLs, override with `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`
or `OTEL_EXPORTER_OTLP_LOGS_ENDPOINT`.

## Ingestion

| Signal | Source | Path |
|--------|--------|------|
| **Metrics** | relayer Prometheus `/metrics` (`memwal_*`) | collector `prometheus` receiver → OTLP → OpenObserve |
| **Logs** | relayer `tracing` events | relayer OTLP HTTP `/v1/logs` → OpenObserve |
| **Traces** | relayer request spans | relayer OTLP HTTP `/v1/traces` → OpenObserve |

The collector still accepts OTLP on ports `4317`/`4318` and can tail Docker
json-file logs for local debugging, but the production path is direct OTLP from
the relayer. The app does **not** implement Prometheus `remote_write`; keep
metrics on `/metrics` and let collector/Prometheus scrape them.

### Quick ingestion smoke test (no relayer needed)

```bash
curl -X POST http://localhost:4318/v1/logs -H 'Content-Type: application/json' -d '{
  "resourceLogs":[{"scopeLogs":[{"logRecords":[{
    "timeUnixNano":"'$(date +%s)'000000000","severityText":"INFO",
    "body":{"stringValue":"poc test"}}]}]}]}'
# then query it back:
curl -u "$O2_ROOT_EMAIL:$O2_ROOT_PASSWORD" -X POST \
  "http://localhost:5080/api/default/_search" -H 'Content-Type: application/json' \
  -d '{"query":{"sql":"SELECT * FROM \"default\" ORDER BY _timestamp DESC","start_time":'$(( ($(date +%s)-600)*1000000 ))',"end_time":'$(( ($(date +%s)+60)*1000000 ))',"size":5}}'
```

## Dashboard — API health

OpenObserve runs PromQL over ingested Prometheus metrics. Create a dashboard
(Dashboards → New) with these panels. Metric labels are
`{method, route, status}` for HTTP metrics.

| Panel | PromQL |
|-------|--------|
| Request rate (req/s) | `sum(rate(memwal_http_requests_total[5m]))` |
| Request rate by route | `sum by (route) (rate(memwal_http_requests_total[5m]))` |
| Error rate (5xx %) | `sum(rate(memwal_http_requests_total{status=~"5.."}[5m])) / sum(rate(memwal_http_requests_total[5m]))` |
| p95 latency (s) | `histogram_quantile(0.95, sum by (le) (rate(memwal_http_request_duration_seconds_bucket[5m])))` |
| In-flight requests | `memwal_http_requests_in_flight` |
| Dependency failures | `sum by (service) (rate(memwal_external_request_duration_seconds_count{status!="200"}[5m]))` |
| Sidecar failures | `sum by (operation, reason) (rate(memwal_sidecar_failures_total[5m]))` |
| DB query p95 (s) | `histogram_quantile(0.95, sum by (le, operation) (rate(memwal_db_query_duration_seconds_bucket[5m])))` |
| DB pool by state | `memwal_db_pool_connections` |

## Alerts

Create under Alerts. Suggested PoC thresholds (tune per environment):

| Alert | Condition |
|-------|-----------|
| 5xx error-rate spike | `sum(rate(memwal_http_requests_total{status=~"5.."}[5m])) / sum(rate(memwal_http_requests_total[5m])) > 0.05` for 5m |
| p95 latency breach | `histogram_quantile(0.95, sum by (le) (rate(memwal_http_request_duration_seconds_bucket[5m]))) > 2` for 10m |
| Sidecar / Walrus failure | `sum(rate(memwal_sidecar_failures_total[5m])) > 0` |
| Verification email failure | `sum(rate(memwal_email_sends_total{outcome=~"failed_.*|rate_limited"}[5m])) > 0` |
| No telemetry received | `absent(memwal_http_requests_total)` for 5m |

## Production / staging rollout notes

- **Logs/traces**: set `OTEL_EXPORTER_OTLP_ENDPOINT` and
  `OTEL_EXPORTER_OTLP_HEADERS` on the relayer. OpenObserve expects the endpoint
  base to include `/api/<org>`, for example `/api/default`.
- **Metrics**: keep the relayer `/metrics` endpoint reachable by the collector
  (private network). Set `RELAYER_METRICS_TARGET` to the staging relayer.
- **Sidecar logs**: the TypeScript sidecar still writes to stdout. If sidecar
  logs need OpenObserve coverage on Railway, forward them with a Railway log
  drain or add sidecar OTLP instrumentation separately.
- `LOG_FORMAT=json` remains useful for local stdout parsing, but OTLP logs do
  not require Docker log tailing.
- Replace the root credentials and pin image tags (this PoC uses `:latest`).
- The collector exposes a `health_check` liveness endpoint on `:13133`
  (`curl localhost:13133`) — wire it into orchestrator probes when deploying.
  A `memory_limiter` processor runs first in every pipeline; the compose
  `mem_limit` values are the ceiling it sizes against, so tune them together.

## Deploy the collector on Railway

On Railway each component is its own service — there is no docker-compose. The
relayer already pushes **logs + traces** straight to OpenObserve over OTLP, so
the only thing missing is **metrics**: nobody scrapes the relayer's Prometheus
`/metrics`. Deploy this collector as a service to close that gap (it scrapes the
relayer over the private network and forwards to OpenObserve).

`Dockerfile` + `railway.json` in this directory make it deployable: the config
is baked into the image (Railway can't bind-mount it).

1. **New service** → *Deploy from GitHub repo* → select the repo.
2. **Settings → Root Directory**: `services/server/observability`
   (Railway reads `railway.json` here and builds the `Dockerfile`).
3. **Variables** (Settings → Variables):

   | Variable | Value (dev) |
   |----------|-------------|
   | `O2_ORG` | `default` |
   | `O2_AUTH` | base64(`email:password`) of the OpenObserve root user |
   | `OPENOBSERVE_HOST` | `openobserve.railway.internal` |
   | `RELAYER_METRICS_TARGET` | `${{relayer.RAILWAY_PRIVATE_DOMAIN}}:3001` |

   > **Use the relayer's private domain, not its display name.** Railway's
   > `*.railway.internal` host is a *generated* name fixed at service creation
   > (e.g. the "relayer" service resolves as `lucky-strength.railway.internal`,
   > **not** `relayer.railway.internal`). The reference
   > `${{relayer.RAILWAY_PRIVATE_DOMAIN}}` resolves to it automatically; or copy
   > the literal value from the relayer service's `RAILWAY_PRIVATE_DOMAIN`. The
   > `:3001` is the relayer's **internal** `PORT`, not a public URL.
   >
   > Railway's private network is **IPv6-only**, so the relayer must bind `[::]`
   > (done in `services/server/src/main.rs`) — a service bound to `0.0.0.0` is
   > unreachable over `*.railway.internal`.
4. **Deploy.** No public domain is needed — the collector only makes outbound
   connections (scrape + export). Optionally expose `:13133` for health checks.

The collector's OTLP receivers and Docker `file_log` tailing stay idle on
Railway (nothing connects to them there); only the metrics pipeline is active.
Logs/traces continue to flow relayer → OpenObserve directly.

## Known gaps (follow-up)

1. **Job-queue health**: there is no apalis/job-queue metric exposed today, so a
   queue-depth/in-flight dashboard isn't possible without adding one.
2. **External dependency status labels**: dependency failures are derived from
   `memwal_external_request_duration_seconds{status}` and
   `memwal_sidecar_failures_total`; per-dependency (Walrus vs OpenAI vs Sui)
   breakdown depends on the `service` label values the relayer emits.
