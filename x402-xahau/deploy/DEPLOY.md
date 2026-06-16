# Deploying the x402-xahau facilitator

This is the deployment guide for the `exact-xahau` x402 facilitator (`server.mjs`).

**Posture (be honest):** this facilitator is **reference-grade**. Every security check is
enforced (signatures cryptographically verified, replay protection fail-closed,
`delivered_amount` checked), and it has a passing live-testnet proof (`docs/FACILITATOR-TESTNET-PROOF.md`).
But the default replay store + rate limiter are **in-memory**: single-instance and not
durable across restarts. For any real / multi-instance deployment, run it with Redis
(`X402_REDIS_URL`) and front it with TLS termination. The payer's on-chain xahc
**guardrail Hook** remains the L1 spending authority.

---

## (a) Environment variable reference

Every variable below is read directly by `server.mjs` (`process.env.*`). No others exist —
do not invent more. "Required for /settle" means the live-settlement path; offline `/verify`
works without it.

| Name | Default | What it does | Required? |
|------|---------|--------------|-----------|
| `PORT` | `4021` | HTTP listen port. Validated as a TCP port (1–65535) at boot. | Optional |
| `XAHAU_WSS` | _(unset)_ | Xahau WS endpoint (`ws://`/`wss://`). Unset ⇒ **/settle DISABLED**, offline `/verify` only. | **Required for /settle** |
| `XAHAU_NETWORK_ID` | `21337` | Expected NetworkID enforced on every payment. mainnet `21337`, testnet `21338`. Must be a positive integer. | Recommended (set explicitly) |
| `XAHAU_NETWORK` | `xahau` | Named-network fallback for the id (`xahau`→21337, `xahau-testnet`→21338). If both this and `XAHAU_NETWORK_ID` are set they must agree, else boot fails. | Optional |
| `X402_SHARED_SECRET` | `""` | Guards `/settle`, `/metrics`, and the **verbose** form of `/health`. Empty ⇒ reference/open mode (those routes are unauthenticated). | **Required for production** |
| `X402_REDIS_URL` | _(unset)_ | `redis://`/`rediss://` URL. Switches replay store + limiter to the **shared, durable** backend (lazy-loads `ioredis`). Set-but-`ioredis`-missing ⇒ **fail-fast at boot**. | Optional (required for multi-instance) |
| `X402_REPLAY_TTL_MS` | `3600000` (1h) | Fallback TTL for a replay binding. | Optional |
| `X402_REPLAY_MAX` | `100000` | Hard cap on live replay bindings; full ⇒ fail-closed 503 (never evicts a live binding). | Optional |
| `X402_LEDGER_CLOSE_MS` | `4000` | Assumed ledger-close interval used to size binding expiry. | Optional |
| `X402_REPLAY_MARGIN_MS` | `300000` (5m) | Slack added to a tx's validity window before a binding may expire. | Optional |
| `X402_CONNECT_TIMEOUT_MS` | `8000` | Bounded xrpl connect timeout. | Optional |
| `X402_CONNECT_ATTEMPTS` | `3` | Connect attempts before failing closed (min 1). | Optional |
| `X402_CONNECT_BACKOFF_MS` | `500` | Backoff between connect attempts. | Optional |
| `X402_RATE_MAX` | `20` | Token-bucket capacity per client window (applies to `/verify` and `/settle`). | Optional |
| `X402_RATE_WINDOW_MS` | `60000` (1m) | Rate-limit window length. | Optional |
| `X402_TRUST_PROXY` | `0` | Trusted proxy hops for `X-Forwarded-For` client-IP derivation. `0` = ignore XFF (use socket addr). Only raise if a trusted proxy rewrites XFF (XFF is spoofable). | Optional |
| `X402_REQUEST_TIMEOUT_MS` | `15000` | Max time a slow client may drip a full request. | Optional |
| `X402_HEADERS_TIMEOUT_MS` | `10000` | Max time to receive headers (slowloris guard). | Optional |
| `X402_MAX_CONNECTIONS` | `1024` | Cap on concurrent sockets (min 1). | Optional |
| `X402_SHUTDOWN_DRAIN_MS` | `10000` | Graceful-shutdown drain budget for in-flight requests on SIGTERM/SIGINT. | Optional |

`validateConfig()` runs at boot: **fatal** misconfig (bad `PORT`, malformed `XAHAU_WSS`,
network id/name disagreement, malformed `X402_REDIS_URL`) exits the process; an unset
`XAHAU_WSS` is a non-fatal warning (settle disabled).

---

## (b) Docker / docker-compose

### Build the image

```sh
# Redis-capable image (default — installs the optional ioredis dep)
docker build -t x402-xahau-facilitator .

# In-memory-only image (smaller; omits ioredis)
docker build --build-arg WITH_REDIS=false -t x402-xahau-facilitator:nomemshare .
```

The image runs as the non-root `node` user, exposes `4021`, and has a `HEALTHCHECK` that
probes `GET /health` with node's built-in `fetch` (no curl needed).

### Run a single instance (in-memory, reference mode)

```sh
docker run --rm -p 4021:4021 \
  -e XAHAU_WSS=wss://xahau.network \
  -e XAHAU_NETWORK_ID=21337 \
  -e X402_SHARED_SECRET="$(openssl rand -hex 32)" \
  x402-xahau-facilitator
```

### docker-compose (facilitator + Redis)

```sh
cp deploy/.env.example .env      # fill in XAHAU_WSS, X402_SHARED_SECRET, etc.
docker compose up -d
docker compose logs -f facilitator
```

`docker-compose.yml` wires `X402_REDIS_URL=redis://redis:6379`, passes the other env via
`${VAR}` interpolation from `.env` (secrets never hardcoded), sets `restart: unless-stopped`,
and starts the facilitator only after Redis is healthy. The Redis service runs with
`--maxmemory-policy noeviction --appendonly yes` (see the eviction caveat below).

---

## (c) Railway

The sibling **xahau-mcp shim** already runs on Railway; mirror that pattern.

1. **New service from this repo/subdirectory.** Point the service root at `x402-xahau/`.
   Railway autodetects Node and runs `npm start` (`node server.mjs`). The included
   `Dockerfile` will be used if Railway is set to build from Dockerfile — either path works
   (the Dockerfile gives you the non-root user + healthcheck for free).
2. **Env vars** (Service → Variables): set `XAHAU_WSS`, `XAHAU_NETWORK_ID` (21337 mainnet),
   and `X402_SHARED_SECRET`. Railway provides `PORT` automatically and `server.mjs` honors it.
3. **Optional Redis (recommended for >1 replica):** add a Railway Redis plugin/service, then
   set `X402_REDIS_URL` to its **internal** connection URL (Railway private networking,
   `*.railway.internal`) so Redis traffic never leaves the project network. The
   Redis-capable image already includes `ioredis`; if you deploy via `npm` instead of the
   Dockerfile, ensure optional deps are installed (`npm ci --include=optional`) so the Redis
   path resolves — otherwise boot fail-fasts when `X402_REDIS_URL` is set.
4. **Configure the Redis plugin** with a non-evicting `maxmemory-policy` (noeviction or
   volatile-*) — see the caveat below.
5. Railway terminates TLS at the edge; the facilitator itself speaks plain HTTP behind it.

---

## (d) Operational caveats (from the code + testnet proof)

- **Xahau rippled speaks WS `api_version 1`.** The facilitator's settle/verify client already
  pins v1, so production verify/settle is fine. But any **client tooling** you point at the
  same Xahau node must also pin `api_version 1` — xrpl@4 defaults to 2 and Xahau rejects it
  with `invalid_API_version`. (`docs/FACILITATOR-TESTNET-PROOF.md`, `testnet-proof.mjs`.)
- **Hooked-account fee note is informational.** A hooked account pays a higher base fee; the
  facilitator surfaces this informationally and does not change settlement correctness.
- **In-memory store is single-instance and not durable.** Without `X402_REDIS_URL` the replay
  store + rate limiter live in one process and reset on restart. Replay protection is correct
  *within* that instance only — never run more than one replica without Redis.
- **Redis must use a non-evicting maxmemory policy.** A replay binding's lifetime is tied to
  its tx's on-ledger validity window. If Redis evicts a *live* binding under memory pressure,
  replay safety is lost and a payment could settle twice. Use `maxmemory-policy noeviction`
  (write fails loudly → facilitator fail-closes to a retryable 503) or a `volatile-*` policy
  (the facilitator's keys are TTL'd). **Never** `allkeys-*`.
- **`/metrics` and `/settle` require the shared secret** (and so does the verbose `/health`).
  With no secret configured they are open (reference mode). `/health`'s minimal liveness shape
  (`status`, `network`, `uptimeSec`) is always unauthenticated for LB probes.
- **Behind a load balancer / proxy:** set **`X402_TRUST_PROXY`** to the number of trusted
  proxy hops in front of the facilitator. Default `0` = do NOT trust `X-Forwarded-For` (key
  off `req.socket.remoteAddress`). With `n>0` the client IP is taken as the `(n+1)`-th entry
  from the right of `X-Forwarded-For` (stripping `n` trusted hops); a missing/malformed XFF
  falls back to the socket address. **Only set this if a trusted proxy actually rewrites XFF**
  — XFF is client-spoofable, so trusting it without a real proxy in front lets an attacker
  forge their rate-limit identity. With `0` and a proxy in front, every client appears as the
  proxy IP and the per-IP limit becomes effectively global (size `X402_RATE_MAX` accordingly,
  or rate-limit at the edge).
- **Graceful shutdown:** SIGTERM/SIGINT stops accepting, drains in-flight within
  `X402_SHUTDOWN_DRAIN_MS`, closes xrpl + Redis, and exits. Give your orchestrator a stop
  grace period ≥ that budget.

---

## (e) Pre-launch security checklist

- [ ] **`X402_SHARED_SECRET` set** to a long random value (e.g. `openssl rand -hex 32`).
      Without it, `/settle` / `/metrics` / verbose `/health` are open.
- [ ] **`XAHAU_NETWORK_ID` set correctly** (mainnet `21337` vs testnet `21338`) and, if you
      also set `XAHAU_NETWORK`, the two agree.
- [ ] **`XAHAU_WSS` points at the intended network** (and matches the network id).
- [ ] **Redis configured for multi-instance** (`X402_REDIS_URL`) with a **non-evicting**
      maxmemory policy and persistence on. Confirm `ioredis` is installed in the image.
- [ ] **TLS terminated at the proxy/LB** — the facilitator speaks plain HTTP.
- [ ] **Rate limiting** is meaningful: either set it at the edge, or remember the
      per-`remoteAddress` limiter collapses to one bucket behind a shared-IP proxy.
- [ ] **Secrets via env only** — never bake `X402_SHARED_SECRET` or a password-bearing
      `X402_REDIS_URL` into the image or commit them.
- [ ] **Health/liveness** wired to `GET /health`; readiness can use the authenticated verbose
      `/health` to confirm `xrplConnected` / `redisConnected`.
- [ ] **Stop grace ≥ `X402_SHUTDOWN_DRAIN_MS`** so in-flight settles drain cleanly.
