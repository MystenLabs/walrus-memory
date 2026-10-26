# ============================================================
# Researcher App (Next.js) — Dockerfile
#
# BUILD FROM MONOREPO ROOT:
#     docker build -f apps/researcher/Dockerfile -t researcher .
#
# Root Directory on Railway must be "/" (repo root) so build context includes
# packages/sdk for workspace:* resolution.
# ============================================================

# ── Stage 1: Install Dependencies ──────────────────────────
FROM node:22.23.4-alpine@sha256:fe4f6d74e20370acb04ad889077d14d0f64a9c8ea6a42bc60cddf1e844699914 AS deps

RUN corepack enable && corepack prepare pnpm@9.12.3 --activate

WORKDIR /app

# Copy workspace manifests for layer caching
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY packages/sdk/package.json ./packages/sdk/
COPY apps/researcher/package.json ./apps/researcher/

# Install all workspace deps (resolves workspace:* for @mysten-incubation/memwal)
RUN pnpm install --frozen-lockfile

# ── Stage 2: Build SDK ─────────────────────────────────────
FROM deps AS sdk-builder

COPY packages/sdk/ ./packages/sdk/
RUN pnpm --filter @mysten-incubation/memwal build

# ── Stage 3: Build Next.js App ─────────────────────────────
FROM sdk-builder AS builder

COPY apps/researcher/ ./apps/researcher/

WORKDIR /app/apps/researcher

# Next.js collects telemetry by default — disable it
ENV NEXT_TELEMETRY_DISABLED=1

# Server-only env vars — dummies for build, real values at runtime
ENV POSTGRES_URL="postgresql://dummy:dummy@localhost:5432/dummy"
ENV AUTH_SECRET="build-time-placeholder"

# NEXT_PUBLIC_* vars are inlined into the client bundle at build time.
# Railway passes env vars as Docker build args automatically.
ARG NEXT_PUBLIC_ENOKI_API_KEY
ARG NEXT_PUBLIC_GOOGLE_CLIENT_ID
ARG NEXT_PUBLIC_SUI_NETWORK
ARG NEXT_PUBLIC_MEMWAL_PACKAGE_ID
ARG NEXT_PUBLIC_MEMWAL_REGISTRY_ID
ARG NEXT_PUBLIC_MEMWAL_SERVER_URL

ENV NEXT_PUBLIC_ENOKI_API_KEY=$NEXT_PUBLIC_ENOKI_API_KEY
ENV NEXT_PUBLIC_GOOGLE_CLIENT_ID=$NEXT_PUBLIC_GOOGLE_CLIENT_ID
ENV NEXT_PUBLIC_SUI_NETWORK=$NEXT_PUBLIC_SUI_NETWORK
ENV NEXT_PUBLIC_MEMWAL_PACKAGE_ID=$NEXT_PUBLIC_MEMWAL_PACKAGE_ID
ENV NEXT_PUBLIC_MEMWAL_REGISTRY_ID=$NEXT_PUBLIC_MEMWAL_REGISTRY_ID
ENV NEXT_PUBLIC_MEMWAL_SERVER_URL=$NEXT_PUBLIC_MEMWAL_SERVER_URL

# Build Next.js (skip DB migration — runs at container start)
RUN pnpm next build

# Compile migrate.ts → migrate.mjs so runtime needs no tsx/esbuild
RUN node_modules/.bin/esbuild lib/db/migrate.ts \
    --bundle --platform=node --format=esm \
    --external:postgres --external:drizzle-orm --external:dotenv \
    --outfile=migrate.mjs

# ── Stage 4: Runtime ───────────────────────────────────────
FROM node:22.23.4-alpine@sha256:fe4f6d74e20370acb04ad889077d14d0f64a9c8ea6a42bc60cddf1e844699914 AS runtime

RUN corepack enable && corepack prepare pnpm@9.12.3 --activate

WORKDIR /app

# Copy Next.js standalone output
COPY --from=builder /app/apps/researcher/.next/standalone ./
COPY --from=builder /app/apps/researcher/.next/static ./apps/researcher/.next/static
COPY --from=builder /app/apps/researcher/public ./apps/researcher/public

# Copy Drizzle migration SQL files + runtime deps (not in standalone bundle)
COPY --from=builder /app/apps/researcher/migrate.mjs ./migrate.mjs
COPY --from=builder /app/apps/researcher/lib/db/migrations/ ./lib/db/migrations/
COPY --from=builder /app/apps/researcher/node_modules/drizzle-orm ./node_modules/drizzle-orm
COPY --from=builder /app/apps/researcher/node_modules/postgres ./node_modules/postgres
COPY --from=builder /app/apps/researcher/node_modules/dotenv ./node_modules/dotenv

ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
ENV PORT=3000
ENV HOSTNAME=0.0.0.0
EXPOSE 3000

# Run DB migration (best-effort) then start Next.js server.
CMD ["sh", "-c", "node migrate.mjs || echo '[WARN] Migration failed, starting server anyway...' ; node apps/researcher/server.js"]
