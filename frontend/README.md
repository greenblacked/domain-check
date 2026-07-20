# Domain Check frontend

This directory contains the React 19 and Vite interface for Domain Check. The UI validates hostnames, creates scans through `/api/v1/scans`, polls while a scan is active, and renders TLS findings and certificate evidence.

## Development

Install dependencies and start Vite:

```sh
npm ci
npm run dev
```

The development server proxies `/api`, `/health`, and `/ready` to `http://localhost:8787`. Start the Cloudflare Worker separately when testing against the complete backend.

The production application is served at `/domain-check`, while the Vite build uses `/` as its asset base so Cloudflare's SPA fallback can serve the same bundle.

## Commands

| Command | Purpose |
| --- | --- |
| `npm run dev` | Start the Vite development server |
| `npm run build` | Type-check and create `dist/` assets |
| `npm run preview` | Preview the production build on port 4173 |
| `npm run lint` | Run ESLint |
| `npm run format` | Check formatting with Prettier |
| `npm test` | Run Vitest component tests once |
| `npm run test:e2e` | Run the Playwright browser tests |
| `npm run typecheck` | Check the browser and Vite TypeScript projects |

## Tests

Unit tests use Vitest, Testing Library, and jsdom:

```sh
npm test
```

The Playwright tests mock API traffic and run against a production preview. Install Chromium once, then build and test:

```sh
npx playwright install chromium
npm run build
npm run test:e2e
```

## Source map

- `src/App.tsx` contains the scan form, polling flow, Turnstile widget, and report display.
- `src/api.ts` defines the typed API contract and request helpers.
- `src/styles.css` contains the responsive presentation.
- `src/App.test.tsx` covers component behavior.
- `e2e/domain-check.spec.ts` covers the browser workflow and keyboard-accessible evidence details.

The UI intentionally accepts hostname input only. Keep its normalization rules aligned with `normalizeHostname` in the Worker and Go scanner when the contract changes.

