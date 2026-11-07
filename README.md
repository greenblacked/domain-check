# Domain Check

Domain Check is a read-only DNS and TLS inspector for public hostnames. It resolves a hostname, rejects private or reserved destinations, connects only to HTTPS on port 443, and reports the certificate and negotiated TLS details.

The application is designed for Cloudflare Workers and Containers. Scan results live in memory for 15 minutes and are not indexed or shared between users.

## Architecture

```text
Browser
  |  React UI and /api/v1 requests
  v
Cloudflare Worker
  |-- SecurityCoordinator Durable Object (rate limits and Turnstile)
  `-- ScannerContainer Durable Object
        `-- Go scanner container (DNS lookup and TLS handshake)
```

| Path | Contents |
| --- | --- |
| `frontend/` | React and Vite interface |
| `worker/` | Public API, static assets, abuse controls, container orchestration |
| `cmd/domain-check/` | Entry point for the Go container |
| `internal/api/` | The container's private scan API |
| `internal/scanner/` | Target validation and DNS, certificate, and TLS evidence |
| `wrangler.jsonc`, `Dockerfile` | Cloudflare deployment |

Each layer re-validates its own input. The frontend rejects malformed hostnames before sending, the Worker normalizes and validates again, and the container refuses anything that is not already normalized. Keep the three hostname rules in step when the contract changes.

## Requirements

- Go 1.25
- Node.js 22 and npm
- Docker, for the scanner image and local Worker development
- A Cloudflare account, Wrangler login, and a Containers-enabled zone for deployment

## Setup

Install each JavaScript workspace independently:

```sh
npm --prefix frontend ci
npm --prefix worker ci
```

The Go module has no external dependencies, so no download step is needed.

## Run the components locally

### Frontend only

Start Vite from `frontend/`:

```sh
npm run dev
```

Vite serves the UI and proxies `/api`, `/health`, and `/ready` to a Worker on `http://localhost:8787`. The interface can still be developed without the Worker by using the unit and end-to-end tests.

### Go scanner only

Start the private scanner API from the repository root:

```sh
go run ./cmd/domain-check
```

Check its health at `http://localhost:8080/health`. To start a real public scan, send a normalized hostname and UUID through the protected internal route:

```sh
curl -i http://localhost:8080/internal/v1/scans \
  -H 'Content-Type: application/json' \
  -H 'X-Internal-Gateway: cloudflare-worker-v1' \
  --data '{"hostname":"example.com","scan_id":"123e4567-e89b-42d3-a456-426614174000","correlation_id":"local-check"}'
```

Poll the returned scan ID at `/internal/v1/scans/{id}` with the same gateway header.

### Complete Worker stack

Build the assets first, make sure Docker is running, then start Wrangler from `worker/`:

```sh
npm --prefix frontend run build
cd worker
npx wrangler dev --config ../wrangler.jsonc
```

Wrangler serves the Worker at `http://localhost:8787`; `/` redirects to `/domain-check`. See [worker/README.md](worker/README.md) for configuration and deployment details.

## API

The public API accepts only normalized DNS hostnames. URLs, IP literals, ports, user information, and caller-selected resolvers are rejected.

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/api/v1/scans` | Queue a scan with `{"hostname":"example.com"}` |
| `GET` | `/api/v1/scans/{id}` | Poll scan status and retrieve the report |
| `GET` | `/health` | Check scanner liveness |
| `GET` | `/ready` | Check scanner readiness |

Successful scans move through `queued`, `running`, and `complete`. A terminal error produces `failed`. API responses include an `x-correlation-id` header for tracing.

Clients should poll with backoff and give up eventually rather than polling a stuck scan forever; the bundled UI caps both the retry count and the total polling window.

## Testing

Run the same checks CI runs:

```sh
# Go: race detector, randomised order, coverage
go test -race -shuffle=on -covermode=atomic -coverprofile=coverage.out ./cmd/... ./internal/...
go vet ./cmd/... ./internal/...

# Frontend
npm --prefix frontend run lint
npm --prefix frontend test
npm --prefix frontend run build

# Worker
npm --prefix worker run lint
npm --prefix worker run check
npm --prefix worker test
```

Go package patterns are scoped to `./cmd/...` and `./internal/...` rather than `./...`, because dependency trees under `node_modules` ship their own Go sources and would otherwise be pulled into vet, gofmt, and vulnerability scanning.

Worker tests run inside workerd through `@cloudflare/vitest-pool-workers`, so `SecurityCoordinator` is exercised against real Durable Object storage rather than a stub. They declare their bindings inline and inject their own scanner stub, so the suite never needs the container image.

The Playwright suite uses mocked API responses and does not require a running Worker:

```sh
cd frontend
npx playwright install chromium
npm run build
npm run test:e2e
```

## Continuous integration

`.github/workflows/ci.yml` runs on every branch push, on pull requests from forks, and on manual dispatch. A pull request opened from a branch in this repository skips its jobs, because the push event already built that exact commit.

| Job | Checks |
| --- | --- |
| Go build & tests | gofmt, `go mod tidy` drift, vet, build, race and shuffled tests, statement coverage floor |
| Go security | govulncheck, gosec, staticcheck |
| Dockerfile lint | hadolint |
| Frontend | ESLint, Vitest, typecheck and build, production dependency audit |
| Frontend end-to-end | Playwright against a production preview |
| Worker | ESLint, typecheck, workerd tests, dependency audit, Wrangler config dry run |
| Container image | Docker build and Trivy scan |
| Secret scan | gitleaks |

The analysis tools are pinned to explicit versions so runs are reproducible and an upstream release cannot enter the pipeline unreviewed; Dependabot raises upgrades as pull requests. Note that govulncheck must stay on a release built with Go 1.25 or newer, as older releases refuse to load this module.

The coverage floor exists to stop erosion, not to certify a target. `cmd/domain-check` is process wiring with no tests of its own, so the aggregate sits well below the tested packages.

## Security model

Target selection

- DNS answers are checked after resolution; private, loopback, link-local, documentation, carrier-grade NAT, multicast, and other reserved ranges are denied.
- The scanner connects to the exact validated address, always on TCP port 443. Callers cannot choose an upstream, port, redirect destination, or resolver.
- At most four resolved addresses are attempted, so a hostname with a large address set cannot monopolise a scan slot.
- TLS 1.2 is the minimum accepted protocol version.

Resource limits

- DNS resolution, every dial, and every handshake share one deadline derived from `SCAN_TIMEOUT`, so total scan time cannot exceed the configured budget regardless of how many addresses are tried.
- The container enforces `MAX_CONCURRENT_SCANS` as a single atomic claim, so simultaneous requests cannot overshoot the limit.
- The Worker enforces per-client, per-target, and global concurrency limits.

Abuse controls

- Repeated anonymous use can require Turnstile. When the verification response reports the hostname the challenge was solved on, it is compared against the host actually serving the request, so a token minted for another property sharing the secret is refused. The verification call carries its own timeout and fails closed if it cannot be reached.
- Rate-limit buckets are keyed by digest, which bounds the coordinator's stored state and avoids persisting caller addresses or the hostnames people look up.
- Coordinator state is reclaimed as counter windows lapse, with a backstop cap that logs when it evicts, so the store cannot grow until it exceeds the Durable Object value limit.

Request handling

- Request bodies and identifiers are strictly validated, and bodies are size-capped.
- The container's internal routes require the gateway header.
- Test-only address and certificate overrides require `APP_ENV=test`.

DNS rebinding defenses rely on validating the resolved addresses immediately before the scanner connects to one of those exact IPs.

## Deployment

Before deploying, replace the placeholder Turnstile site key in `wrangler.jsonc` and store the corresponding secret:

```sh
cd worker
npx wrangler secret put TURNSTILE_SECRET_KEY --config ../wrangler.jsonc
```

Then build the frontend and deploy:

```sh
npm --prefix frontend run build
cd worker
npx wrangler deploy --config ../wrangler.jsonc
```

Use `--env staging` for the staging environment. Review the route, zone, container limits, shard count, and Turnstile values in `wrangler.jsonc` before deploying to another account.

## Configuration

The Go scanner reads these environment variables:

| Variable | Default | Description |
| --- | --- | --- |
| `PORT` | `8080` | HTTP listen port |
| `DNS_RESOLVER` | system resolver | Optional DNS resolver address |
| `INTERNAL_GATEWAY` | `cloudflare-worker-v1` | Required internal gateway header value |
| `SCAN_TIMEOUT` | `12s` | Budget covering resolution, dials, and handshakes |
| `SCAN_RETENTION` | `15m` | In-memory result retention |
| `MAX_CONCURRENT_SCANS` | `8` | Concurrent scans per container |

Worker bindings and variables are documented in [worker/README.md](worker/README.md).
