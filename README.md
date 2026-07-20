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

- `frontend/` contains the React and Vite interface.
- `worker/` contains the public API, static asset handling, rate limiting, and container orchestration.
- `cmd/domain-check/` starts the Go HTTP service used by the container.
- `internal/api/` implements the container's private scan API.
- `internal/scanner/` validates targets and gathers DNS, certificate, and TLS evidence.
- `wrangler.jsonc` and `Dockerfile` define the Cloudflare deployment.

## Requirements

- Go 1.25
- Node.js 22 and npm
- Docker, for the scanner image and local Worker development
- A Cloudflare account, Wrangler login, and a configured Containers-enabled zone for deployment

## Install and verify

Install each JavaScript workspace independently:

```sh
npm --prefix frontend ci
npm --prefix worker ci
```

Run the same core checks used by CI:

```sh
go test -race ./...
npm --prefix frontend run lint
npm --prefix frontend test
npm --prefix frontend run build
npm --prefix worker run lint
npm --prefix worker run check
npm --prefix worker test
```

The Playwright suite uses mocked API responses, so it does not require a running Worker:

```sh
cd frontend
npx playwright install chromium
npm run build
npm run test:e2e
```

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

## Security model

- DNS answers are checked after resolution; private, loopback, link-local, documentation, carrier-grade NAT, multicast, and other reserved ranges are denied.
- The scanner always connects to TCP port 443 and does not accept arbitrary upstream URLs or ports.
- TLS 1.2 is the minimum accepted protocol version.
- Request bodies and identifiers are strictly validated.
- The Worker enforces per-client, per-target, and global concurrency limits. Repeated anonymous use can require Turnstile.
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
| `SCAN_TIMEOUT` | `12s` | Overall scan timeout |
| `SCAN_RETENTION` | `15m` | In-memory result retention |
| `MAX_CONCURRENT_SCANS` | `8` | Concurrent scans per container |

Worker bindings and variables are documented in [worker/README.md](worker/README.md).

