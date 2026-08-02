import { env, reset, runInDurableObject } from 'cloudflare:test';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import worker, { type Env } from './index';

const SITE = 'https://tools.goldenman.cloud';
const SCAN_ID = '123e4567-e89b-42d3-a456-426614174000';

interface ScannerCall {
  url: string;
  gateway: string | null;
  correlation: string | null;
  body: string;
}

let scannerCalls: ScannerCall[];
let scannerReply: (request: Request) => Response | Promise<Response>;
let assetCalls: number;

beforeEach(() => {
  scannerCalls = [];
  assetCalls = 0;
  scannerReply = () => Response.json({ id: SCAN_ID, status: 'queued' }, { status: 202 });
});

// The coordinator is a single global instance, so rate-limit counters would
// otherwise carry from one test into the next.
afterEach(() => reset());

/**
 * The scanner namespace and the asset fetcher are the only bindings the tests
 * substitute; SECURITY stays the real Durable Object so reservation, rate
 * limiting, and release all run for real.
 */
function testEnv(overrides: Partial<Env> = {}): Env {
  return {
    ...env,
    SCANNER: {
      getByName: () => ({
        fetch: async (request: Request) => {
          scannerCalls.push({
            url: request.url,
            gateway: request.headers.get('x-internal-gateway'),
            correlation: request.headers.get('x-correlation-id'),
            body: request.method === 'POST' ? await request.clone().text() : '',
          });
          return scannerReply(request);
        },
      }),
    },
    ASSETS: {
      fetch: async () => {
        assetCalls++;
        return new Response('<!doctype html><title>app</title>', { headers: { 'content-type': 'text/html' } });
      },
    },
    ...overrides,
  } as unknown as Env;
}

// The handler takes no ExecutionContext and schedules no deferred work, so the
// response is complete once it resolves.
async function call(request: Request, overrides: Partial<Env> = {}) {
  return worker.fetch(request, testEnv(overrides));
}

function post(body: unknown, headers: HeadersInit = { 'content-type': 'application/json' }, ip: string = crypto.randomUUID()) {
  return new Request(`${SITE}/api/v1/scans`, {
    method: 'POST',
    headers: { ...Object.fromEntries(new Headers(headers)), 'CF-Connecting-IP': ip },
    body: typeof body === 'string' ? body : JSON.stringify(body),
  });
}

async function errorCode(response: Response) {
  const body = await response.json<{ error?: { code?: string } }>();
  return body.error?.code;
}

describe('POST /api/v1/scans', () => {
  it('rejects a body that is not declared as JSON', async () => {
    const response = await call(post({ hostname: 'example.com' }, { 'content-type': 'text/plain' }));
    expect(response.status).toBe(415);
    expect(await errorCode(response)).toBe('unsupported_media_type');
  });

  it.each([
    ['a URL', 'https://example.com'],
    ['an IPv4 literal', '127.0.0.1'],
    ['an IPv6 literal', '[::1]'],
    ['a host and port', 'example.com:8443'],
    ['a single label', 'localhost'],
    ['an all-numeric name', '1.2.3.4.5'],
    ['an underscore', 'bad_.example'],
    ['an empty name', ''],
    ['a trailing hyphen label', 'bad-.example'],
  ])('rejects %s', async (_label, hostname) => {
    const response = await call(post({ hostname }));
    expect(response.status).toBe(400);
    expect(await errorCode(response)).toBe('invalid_hostname');
    expect(scannerCalls).toHaveLength(0);
  });

  it.each([
    ['a non-string hostname', { hostname: 42 }],
    ['an unexpected field', { hostname: 'example.com', upstream: 'http://169.254.169.254' }],
    ['malformed JSON', '{"hostname":'],
  ])('rejects %s', async (_label, body) => {
    const response = await call(post(body));
    expect(response.status).toBe(400);
    expect(await errorCode(response)).toBe('invalid_request');
    expect(scannerCalls).toHaveLength(0);
  });

  it('rejects an oversized body', async () => {
    const response = await call(post({ hostname: `${'a'.repeat(2000)}.example` }));
    expect(response.status).toBe(400);
    expect(scannerCalls).toHaveLength(0);
  });

  it('queues a valid scan through the internal gateway', async () => {
    const response = await call(post({ hostname: 'example.com' }));
    expect(response.status).toBe(202);
    expect(response.headers.get('x-correlation-id')).toBeTruthy();
    expect(response.headers.get('cache-control')).toBe('no-store');
    expect(response.headers.get('x-content-type-options')).toBe('nosniff');

    expect(scannerCalls).toHaveLength(1);
    const forwarded = scannerCalls[0]!;
    expect(forwarded.url).toBe('http://scanner/internal/v1/scans');
    expect(forwarded.gateway).toBe('cloudflare-worker-v1');
    const body = JSON.parse(forwarded.body) as { hostname: string; scan_id: string; correlation_id: string };
    expect(body.hostname).toBe('example.com');
    expect(body.scan_id).toMatch(/^[0-9a-f-]{36}$/);
    expect(body.correlation_id).toBe(forwarded.correlation);
  });

  it.each([' Example.COM ', 'EXAMPLE.com.', 'example.com.'])('normalizes %j before dispatch', async (hostname) => {
    // The Worker normalizes; the container then refuses anything that is not
    // already normalized, so the two layers must agree on the canonical form.
    const response = await call(post({ hostname }));
    expect(response.status).toBe(202);
    expect(JSON.parse(scannerCalls[0]!.body).hostname).toBe('example.com');
  });

  it('surfaces a 503 and releases the reservation when the container is unreachable', async () => {
    scannerReply = () => {
      throw new Error('container asleep');
    };
    const response = await call(post({ hostname: 'example.com' }));
    expect(response.status).toBe(503);
    expect(response.headers.get('retry-after')).toBe('10');
    expect(await errorCode(response)).toBe('scanner_unavailable');
  });

  it('applies the per-target limit across different callers', async () => {
    const statuses: number[] = [];
    for (let i = 0; i < 6; i++) {
      statuses.push((await call(post({ hostname: 'shared-target.example' }, undefined, `ip-${i}`))).status);
    }
    // Four reservations succeed, the rest are refused for the same target.
    expect(statuses.filter((status) => status === 202)).toHaveLength(4);
    expect(statuses.filter((status) => status === 429).length).toBeGreaterThan(0);
    expect(scannerCalls).toHaveLength(4);
  });

  it('buckets rate limits by digest rather than by raw hostname or address', async () => {
    // Keeps every stored key a fixed 32 characters, which is what bounds the
    // coordinator blob, and avoids persisting addresses or the names looked up.
    const hostname = 'a-very-long-hostname-that-someone-looked-up.example.com';
    expect((await call(post({ hostname }, undefined, '203.0.113.42'))).status).toBe(202);

    const stub = env.SECURITY.get(env.SECURITY.idFromName('global'));
    const state = await runInDurableObject(stub, (_instance, ctx) =>
      ctx.storage.get<{ clients: Record<string, unknown>; targets: Record<string, unknown> }>('security'),
    );
    const keys = [...Object.keys(state?.clients ?? {}), ...Object.keys(state?.targets ?? {})];
    expect(keys.length).toBeGreaterThan(0);
    expect(keys).not.toContain(hostname);
    expect(keys).not.toContain('203.0.113.42');
    for (const key of keys) expect(key).toMatch(/^[0-9a-f]{32}$/);
  });
});

describe('GET /api/v1/scans/{id}', () => {
  it.each(['not-a-uuid', '%2e%2e%2f%2e%2e%2fetc%2fpasswd', `${SCAN_ID}extra`, '00000000-0000-0000-0000-000000000000'])(
    'rejects the identifier %j',
    async (id) => {
      const response = await call(new Request(`${SITE}/api/v1/scans/${id}`));
      expect(response.status).toBe(400);
      expect(await errorCode(response)).toBe('invalid_scan_id');
      expect(scannerCalls).toHaveLength(0);
    },
  );

  it('polls the container and passes the report through', async () => {
    scannerReply = () => Response.json({ id: SCAN_ID, status: 'running', progress: 25 });
    const response = await call(new Request(`${SITE}/api/v1/scans/${SCAN_ID}`));
    expect(response.status).toBe(200);
    expect(scannerCalls[0]?.url).toBe(`http://scanner/internal/v1/scans/${SCAN_ID}`);
    expect(scannerCalls[0]?.gateway).toBe('cloudflare-worker-v1');
    expect(await response.json()).toMatchObject({ status: 'running' });
  });

  it('reports the scanner as unavailable rather than failing open', async () => {
    scannerReply = () => {
      throw new Error('gone');
    };
    const response = await call(new Request(`${SITE}/api/v1/scans/${SCAN_ID}`));
    expect(response.status).toBe(503);
  });
});

describe('static routes', () => {
  it('redirects the root to the application path', async () => {
    const response = await call(new Request(`${SITE}/`, { redirect: 'manual' }));
    expect(response.status).toBe(302);
    expect(response.headers.get('location')).toBe(`${SITE}/domain-check`);
  });

  it('refuses non-GET methods on asset routes', async () => {
    const response = await call(new Request(`${SITE}/domain-check`, { method: 'DELETE' }));
    expect(response.status).toBe(405);
    expect(response.headers.get('allow')).toBe('GET, HEAD');
    expect(assetCalls).toBe(0);
  });

  it('serves assets with the hardened header set', async () => {
    const response = await call(new Request(`${SITE}/domain-check`));
    expect(response.status).toBe(200);
    expect(assetCalls).toBe(1);
    expect(response.headers.get('x-content-type-options')).toBe('nosniff');
    expect(response.headers.get('referrer-policy')).toBe('strict-origin-when-cross-origin');
    expect(response.headers.get('cache-control')).toBe('no-cache');
    const csp = response.headers.get('content-security-policy') ?? '';
    expect(csp).toContain("default-src 'self'");
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).toContain("base-uri 'none'");
    expect(csp).not.toContain('unsafe-inline');
  });
});

describe('health routes', () => {
  it('reports unavailable when the scanner cannot be reached', async () => {
    scannerReply = () => {
      throw new Error('down');
    };
    const response = await call(new Request(`${SITE}/health`));
    expect(response.status).toBe(503);
    expect(response.headers.get('retry-after')).toBe('10');
  });

  it('passes the scanner verdict through when reachable', async () => {
    scannerReply = () => Response.json({ status: 'ready' });
    const response = await call(new Request(`${SITE}/ready`));
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({ status: 'ready' });
  });
});
