# syntax=docker/dockerfile:1
# Multi-stage image: ~250 MB, runs as the unprivileged "node" user.
# Works on any container host (Render, Koyeb, Fly.io, Railway) or locally via docker compose.

FROM node:22-bookworm-slim AS base
# Prisma's query engine needs OpenSSL
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssl ca-certificates \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app

# ── Build: install all dependencies, compile TypeScript, drop dev dependencies ──
FROM base AS build
COPY package.json package-lock.json ./
COPY prisma ./prisma
RUN npm ci
COPY tsconfig.json tsconfig.build.json ./
COPY src ./src
RUN npm run build && npm prune --omit=dev

# ── Runtime: only what the server needs ──
FROM base AS runtime
ENV NODE_ENV=production \
    PORT=4000 \
    LOG_TO_FILE=false
COPY --from=build --chown=node:node /app/node_modules ./node_modules
COPY --from=build --chown=node:node /app/dist ./dist
COPY --chown=node:node prisma ./prisma
COPY --chown=node:node public ./public
COPY --chown=node:node package.json ./
USER node
EXPOSE 4000

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||4000)+'/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

# Apply pending migrations and the idempotent seed, then start the server
CMD ["sh", "-c", "node_modules/.bin/prisma migrate deploy && node dist/db/seed.js && node dist/server.js"]
