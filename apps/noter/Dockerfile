# ============================================================
# Walrus Memory Noter — Dockerfile (v2 — Enoki build args)
#
# ⚠️  BUILD FROM MONOREPO ROOT:
#     docker build -f apps/noter/Dockerfile -t memwal-noter .
#
# Root Directory on Railway must be "/" (repo root)
# so build context includes packages/sdk for workspace:* resolution.
# ============================================================

# ── Stage 1: Dependencies ──────────────────────────────────
FROM node:22.23.4-alpine@sha256:fe4f6d74e20370acb04ad889077d14d0f64a9c8ea6a42bc60cddf1e844699914 AS deps

RUN corepack enable && corepack prepare pnpm@9.12.3 --activate

WORKDIR /app

# Copy workspace manifests for layer caching
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml ./
COPY packages/sdk/package.json ./packages/sdk/
COPY apps/noter/package.json   ./apps/noter/

# Install all workspace deps (resolves workspace:* for @mysten-incubation/memwal)
RUN pnpm install --frozen-lockfile

# Build SDK first (@mysten-incubation/memwal is the package name — matches sdk/package.json)
COPY packages/sdk/ ./packages/sdk/
RUN pnpm --filter @mysten-incubation/memwal build

# ── Stage 2: Build Next.js App ─────────────────────────────
FROM deps AS builder

COPY apps/noter/ ./apps/noter/

WORKDIR /app/apps/noter

# Next.js collects telemetry by default — disable it
ENV NEXT_TELEMETRY_DISABLED=1

# Server-only env vars — dummies for build, real values at runtime
ENV DATABASE_URL="postgresql://dummy:dummy@localhost:5432/dummy"

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

RUN npx next build

# Compile migrate.ts → migrate.mjs so runtime needs no tsx/esbuild
RUN node_modules/.bin/esbuild package/shared/lib/db/migrate.ts \
    --bundle --platform=node --format=esm \
    --external:postgres --external:drizzle-orm --external:dotenv \
    --outfile=migrate.mjs

# ── Stage 3: Runtime ───────────────────────────────────────
FROM node:22.23.4-alpine@sha256:fe4f6d74e20370acb04ad889077d14d0f64a9c8ea6a42bc60cddf1e844699914 AS runtime

WORKDIR /app

# Copy Next.js standalone output
COPY --from=builder /app/apps/noter/.next/standalone ./
COPY --from=builder /app/apps/noter/.next/static     ./apps/noter/.next/static
COPY --from=builder /app/apps/noter/public           ./apps/noter/public

# Copy DB migration files + runtime deps (not in standalone bundle)
COPY --from=builder /app/apps/noter/migrate.mjs              ./migrate.mjs
COPY --from=builder /app/apps/noter/package/shared/db/       ./package/shared/db/
COPY --from=builder /app/apps/noter/node_modules/drizzle-orm ./node_modules/drizzle-orm
COPY --from=builder /app/apps/noter/node_modules/postgres     ./node_modules/postgres
COPY --from=builder /app/apps/noter/node_modules/dotenv       ./node_modules/dotenv

ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
ENV PORT=3000
ENV HOSTNAME=0.0.0.0
EXPOSE 3000

# Run DB migration then start Next.js server
CMD ["sh", "-c", "node migrate.mjs && node apps/noter/server.js"]
