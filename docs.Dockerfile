# ============================================================
# Walrus Memory Docs — Dockerfile
# Mintlify docs site — install + serve
# Build context: repo root
# ============================================================

FROM node:22.23.4-alpine@sha256:fe4f6d74e20370acb04ad889077d14d0f64a9c8ea6a42bc60cddf1e844699914

RUN corepack enable && corepack prepare pnpm@9.12.3 --activate

WORKDIR /app

# Copy only the docs workspace inputs first for better layer caching
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml ./
COPY docs/package.json ./docs/package.json

# Install workspace dependencies, including Mintlify
RUN pnpm install --frozen-lockfile

# Copy the full docs site after dependencies are in place
COPY docs/ ./docs/

WORKDIR /app/docs

ENV HOST=0.0.0.0
ENV PORT=3000

EXPOSE 3000

CMD ["pnpm", "exec", "mintlify", "dev", "--host", "0.0.0.0", "--port", "3000"]
