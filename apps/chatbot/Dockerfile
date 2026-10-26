# ============================================================
# Walrus Memory Chatbot (Next.js) — Dockerfile
#
# ⚠️  BUILD FROM MONOREPO ROOT:
#     docker build -f apps/chatbot/Dockerfile -t memwal-chatbot .
#
# Root Directory on Railway must be "/" (repo root)
# so build context includes packages/sdk for workspace:* resolution.
# ============================================================

# ── Stage 1: Install Dependencies ──────────────────────────
FROM node:22.23.4-alpine@sha256:fe4f6d74e20370acb04ad889077d14d0f64a9c8ea6a42bc60cddf1e844699914 AS deps

RUN corepack enable && corepack prepare pnpm@9.12.3 --activate

WORKDIR /app

# Copy workspace manifests for layer caching
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml ./
COPY packages/sdk/package.json ./packages/sdk/
COPY apps/chatbot/package.json ./apps/chatbot/

# Install all workspace deps (resolves workspace:* for @mysten-incubation/memwal)
RUN pnpm install --frozen-lockfile

# ── Stage 2: Build SDK ─────────────────────────────────────
FROM deps AS sdk-builder

COPY packages/sdk/ ./packages/sdk/
RUN pnpm --filter @mysten-incubation/memwal build

# ── Stage 3: Build Next.js App ─────────────────────────────
FROM sdk-builder AS builder

COPY apps/chatbot/ ./apps/chatbot/

WORKDIR /app/apps/chatbot

# Next.js collects telemetry by default — disable it
ENV NEXT_TELEMETRY_DISABLED=1

# Dummy env vars required for `next build` (real values injected at runtime)
ENV POSTGRES_URL="postgresql://dummy:dummy@localhost:5432/dummy"
ENV AUTH_SECRET="build-time-placeholder-not-a-runtime-secret"

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
COPY --from=builder /app/apps/chatbot/.next/standalone ./
COPY --from=builder /app/apps/chatbot/.next/static     ./apps/chatbot/.next/static
COPY --from=builder /app/apps/chatbot/public           ./apps/chatbot/public

# Copy Drizzle migration SQL files + runtime deps (not in standalone bundle)
COPY --from=builder /app/apps/chatbot/migrate.mjs              ./migrate.mjs
COPY --from=builder /app/apps/chatbot/lib/db/migrations/       ./lib/db/migrations/
COPY --from=builder /app/apps/chatbot/node_modules/drizzle-orm ./node_modules/drizzle-orm
COPY --from=builder /app/apps/chatbot/node_modules/postgres     ./node_modules/postgres
COPY --from=builder /app/apps/chatbot/node_modules/dotenv       ./node_modules/dotenv

ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
ENV PORT=3000
ENV HOSTNAME=0.0.0.0
EXPOSE 3000

# Run DB migration (best-effort) then start Next.js server
# Migration runs first; if it fails, log the error but still start the server
# so health checks can pass. Railway will show migration errors in logs.
CMD ["sh", "-c", "node migrate.mjs || echo '[WARN] Migration failed, starting server anyway...' ; node apps/chatbot/server.js"]
