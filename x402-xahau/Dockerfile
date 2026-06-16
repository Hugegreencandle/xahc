# syntax=docker/dockerfile:1
#
# Production image for the x402-xahau facilitator (reference-grade; see deploy/DEPLOY.md
# for the honest reference-vs-production posture).
#
# Runtime deps are PROD deps (ripple-address-codec, ripple-keypairs, xrpl,
# xrpl-binary-codec-prerelease). `ioredis` is an OPTIONAL dependency: it is only
# loaded when X402_REDIS_URL is set (the shared/durable replay store + limiter).
#
# Redis support is controlled by the WITH_REDIS build arg:
#   WITH_REDIS=true  (default) -> `npm ci --include=optional` installs ioredis so the
#                                  Redis path works in the deployed image.
#   WITH_REDIS=false           -> `npm ci --omit=dev --omit=optional` for a smaller,
#                                  in-memory-only image (zero extra deps).
# Either way devDependencies are omitted (there are none declared, but this stays honest).

ARG NODE_VERSION=22

# ---- builder: resolve node_modules reproducibly from the lockfile ----
FROM node:${NODE_VERSION}-slim AS deps
ARG WITH_REDIS=true
WORKDIR /app

# Copy only manifests first so the dependency layer caches independently of source.
COPY package.json package-lock.json ./

# Reproducible install straight from package-lock.json. `npm ci` fails if the lockfile
# is out of sync, which is what we want for a deploy image.
RUN if [ "$WITH_REDIS" = "true" ]; then \
      npm ci --omit=dev --include=optional; \
    else \
      npm ci --omit=dev --omit=optional; \
    fi \
    && npm cache clean --force

# ---- runtime: slim, non-root ----
FROM node:${NODE_VERSION}-slim AS runtime
WORKDIR /app

ENV NODE_ENV=production
# Default facilitator port (server.mjs: PORT || 4021). Overridable at runtime.
ENV PORT=4021

# Bring in the resolved modules and the application source.
COPY --from=deps /app/node_modules ./node_modules
COPY package.json package-lock.json server.mjs ./

# Run as the unprivileged `node` user that ships with the official image.
USER node

EXPOSE 4021

# Liveness probe: GET /health. Uses node's built-in fetch (Node 18+) so the image
# needs no curl/wget. /health is unauthenticated and never throws (minimal liveness
# JSON for callers without the shared secret).
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||4021)+'/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "server.mjs"]
