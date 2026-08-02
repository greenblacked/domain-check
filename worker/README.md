# Domain Check Worker

This directory contains the Cloudflare Worker gateway for Domain Check. It serves the built frontend, exposes the public scan API, applies abuse controls, and dispatches scans to sharded Go containers.

## Responsibilities

- Validate the public request contract and normalize hostnames.
- Apply per-client and per-target rate limits in `SecurityCoordinator`.
- Require Turnstile after repeated anonymous requests when enabled.
- Track active reservations and enforce a global scan cap.
- Route a scan consistently to a `ScannerContainer` shard.
- Forward correlation IDs and add browser security and cache headers.
- Serve the Vite assets from `../frontend/dist`.

`SecurityCoordinator` and `ScannerContainer` are Durable Object classes. The container image is built from the repository-level `Dockerfile`.

## Development

From the repository root, install dependencies and build the frontend:

```sh
npm --prefix worker ci
npm --prefix frontend ci
npm --prefix frontend run build
```

With Docker running, start the Worker from this directory:

```sh
npx wrangler dev --config ../wrangler.jsonc
```

The service listens on `http://localhost:8787` by default. The root path redirects to `/domain-check`.

## Commands

| Command | Purpose |
| --- | --- |
| `npm run lint` | Run ESLint over Worker source |
| `npm run check` | Type-check without emitting files |
| `npm test` | Run Vitest unit tests |
| `npm run format` | Check source and configuration formatting |
| `npm run build` | Create a dry-run Worker bundle in `../dist/worker` |
| `npm run validate:config` | Validate the deployment with a Wrangler dry run |

Tests run inside the Workers runtime via `@cloudflare/vitest-pool-workers`, so `cloudflare:workers` and `@cloudflare/containers` load for real and `SecurityCoordinator` is exercised against genuine Durable Object storage. `vitest.config.ts` declares the bindings inline rather than reading `wrangler.jsonc`, so the suite never needs the container image; tests that reach the scanner inject their own `SCANNER` stub.

## Bindings and variables

The Worker expects the bindings declared in `../wrangler.jsonc`:

| Name | Kind | Purpose |
| --- | --- | --- |
| `ASSETS` | Fetcher | Built frontend assets |
| `SCANNER` | Durable Object namespace | Sharded scanner containers |
| `SECURITY` | Durable Object namespace | Global rate and active-scan coordination |
| `CONTAINER_SHARDS` | Variable | Number of scanner shards, clamped from 1 to 10 |
| `TURNSTILE_ENABLED` | Variable | Enables Turnstile verification when set to `true` |
| `TURNSTILE_SITE_KEY` | Variable | Public key returned when a challenge is required |
| `TURNSTILE_SECRET_KEY` | Secret | Server-side Turnstile verification key |
| `RELEASE_SHA` | Variable | Release identifier included in request logs |

The production defaults allow 10 requests per client per minute, 4 per target per minute, and 20 active scans globally. A Turnstile challenge is required after 3 anonymous scans within 10 minutes. These limits are constants in `src/index.ts`.

## Public routes

| Method | Path | Behavior |
| --- | --- | --- |
| `POST` | `/api/v1/scans` | Reserve capacity and create a container scan |
| `GET` | `/api/v1/scans/{id}` | Poll the same container shard for a result |
| `GET` | `/health` | Proxy the scanner health endpoint |
| `GET` | `/ready` | Proxy the scanner readiness endpoint |
| `GET`, `HEAD` | all other paths | Serve frontend assets, with `/` redirected to `/domain-check` |

## Deploy

Replace the placeholder Turnstile site key in `../wrangler.jsonc`, then store the secret for the desired environment:

```sh
npx wrangler secret put TURNSTILE_SECRET_KEY --config ../wrangler.jsonc
npx wrangler secret put TURNSTILE_SECRET_KEY --env staging --config ../wrangler.jsonc
```

Build the frontend and deploy production or staging:

```sh
npm --prefix ../frontend run build
npx wrangler deploy --config ../wrangler.jsonc
npx wrangler deploy --env staging --config ../wrangler.jsonc
```

Run only the deploy command for the environment you intend to update. Confirm the route and `zone_name` in `wrangler.jsonc` before a production deployment.
