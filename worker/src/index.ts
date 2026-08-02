import { Container } from '@cloudflare/containers';
import { DurableObject } from 'cloudflare:workers';

export interface Env {
  ASSETS: Fetcher;
  SCANNER: DurableObjectNamespace<ScannerContainer>;
  SECURITY: DurableObjectNamespace<SecurityCoordinator>;
  APP_ENV: string;
  CONTAINER_SHARDS: string;
  TURNSTILE_ENABLED: string;
  TURNSTILE_SITE_KEY: string;
  TURNSTILE_SECRET_KEY: string;
  RELEASE_SHA: string;
}

interface PublicScanRequest {
  hostname: string;
  turnstile_token?: string;
}

interface ReserveRequest {
  client: string;
  target: string;
  scan_id: string;
  turnstile_verified: boolean;
}

interface RateCounter {
  startedAt: number;
  count: number;
}

interface SecurityState {
  clients: Record<string, RateCounter>;
  targets: Record<string, RateCounter>;
  anonymous: Record<string, RateCounter>;
  active: Record<string, number>;
}

const API_PREFIX = '/api/v1';
const MAX_BODY_BYTES = 1024;
const CLIENT_LIMIT = 10;
const TARGET_LIMIT = 4;
const MAX_ACTIVE_SCANS = 20;
const RATE_WINDOW_MS = 60_000;
const CHALLENGE_WINDOW_MS = 10 * 60_000;
const CHALLENGE_AFTER = 3;
const ACTIVE_TTL_MS = 2 * 60_000;
// A Durable Object value is capped at 128 KiB and the whole security blob is
// rewritten on every reservation, so each counter map is bounded. Entries are
// normally removed as soon as their window lapses; the cap is only a backstop
// against a burst of unique clients or targets inside a single window.
const MAX_TRACKED_ENTRIES = 250;
const TURNSTILE_TIMEOUT_MS = 5_000;
const TURNSTILE_VERIFY_URL = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
const hostnamePattern = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

export class ScannerContainer extends Container {
  defaultPort = 8080;
  sleepAfter = '5m';
  pingEndpoint = 'scanner/ready';
  enableInternet = true;
  envVars = {
    APP_ENV: 'production',
    PORT: '8080',
    INTERNAL_GATEWAY: 'cloudflare-worker-v1',
    MAX_CONCURRENT_SCANS: '8',
    SCAN_TIMEOUT: '12s',
    SCAN_RETENTION: '15m',
  };

  override onStart(): void {
    console.log(JSON.stringify({ event: 'scanner_container_started' }));
  }

  override onStop(): void {
    console.log(JSON.stringify({ event: 'scanner_container_stopped' }));
  }

  override onError(error: unknown): void {
    console.error(JSON.stringify({ event: 'scanner_container_error', error: String(error) }));
  }
}

export class SecurityCoordinator extends DurableObject<Env> {
  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (request.method === 'POST' && url.pathname === '/reserve') {
      return this.reserve(await request.json<ReserveRequest>());
    }
    if (request.method === 'POST' && url.pathname === '/release') {
      const body = await request.json<{ scan_id: string }>();
      const state = await this.readState();
      const changed = this.collect(state, Date.now());
      if (!(body.scan_id in state.active) && !changed) return Response.json({ released: true });
      delete state.active[body.scan_id];
      await this.ctx.storage.put('security', state);
      return Response.json({ released: true });
    }
    return Response.json({ error: { code: 'not_found', message: 'route not found' } }, { status: 404 });
  }

  // collect drops everything that can no longer influence a decision: expired
  // reservations and counters whose fixed window has lapsed. Without it the
  // counter maps grow once per unique client and target and never shrink, and
  // the blob eventually exceeds the per-value storage limit, at which point
  // every reservation fails. Returns whether anything changed.
  private collect(state: SecurityState, now: number): boolean {
    let changed = false;
    for (const [id, expires] of Object.entries(state.active)) {
      if (expires <= now) {
        delete state.active[id];
        changed = true;
      }
    }
    changed = this.sweep(state.clients, now, RATE_WINDOW_MS, 'clients') || changed;
    changed = this.sweep(state.targets, now, RATE_WINDOW_MS, 'targets') || changed;
    changed = this.sweep(state.anonymous, now, CHALLENGE_WINDOW_MS, 'anonymous') || changed;
    return changed;
  }

  private sweep(counters: Record<string, RateCounter>, now: number, window: number, label: string): boolean {
    let changed = false;
    for (const [key, counter] of Object.entries(counters)) {
      if (now - counter.startedAt >= window) {
        delete counters[key];
        changed = true;
      }
    }
    const entries = Object.entries(counters);
    if (entries.length <= MAX_TRACKED_ENTRIES) return changed;
    // Over the cap, the entries closest to expiry are the cheapest to lose.
    // Evicting resets those callers' limits early, so make it observable.
    entries.sort(([, a], [, b]) => a.startedAt - b.startedAt);
    const evicted = entries.slice(0, entries.length - MAX_TRACKED_ENTRIES);
    for (const [key] of evicted) delete counters[key];
    console.warn(JSON.stringify({ event: 'security_state_evicted', map: label, evicted: evicted.length, retained: MAX_TRACKED_ENTRIES }));
    return true;
  }

  private async reserve(input: ReserveRequest): Promise<Response> {
    const now = Date.now();
    const state = await this.readState();
    const collected = this.collect(state, now);
    // Persist reclaimed space even when the reservation is refused, otherwise
    // the maps only ever shrink on the success path.
    const persistCollected = async () => {
      if (collected) await this.ctx.storage.put('security', state);
    };

    const anonymous = updateCounter(state.anonymous[input.client], now, CHALLENGE_WINDOW_MS, false);
    if (anonymous.count >= CHALLENGE_AFTER && !input.turnstile_verified) {
      state.anonymous[input.client] = anonymous;
      await this.ctx.storage.put('security', state);
      return Response.json({ allowed: false, code: 'turnstile_required' }, { status: 403 });
    }

    const client = updateCounter(state.clients[input.client], now, RATE_WINDOW_MS, false);
    if (client.count >= CLIENT_LIMIT) {
      await persistCollected();
      return Response.json({ allowed: false, code: 'client_rate_limit', retry_after: retryAfter(client, now, RATE_WINDOW_MS) }, { status: 429 });
    }
    const target = updateCounter(state.targets[input.target], now, RATE_WINDOW_MS, false);
    if (target.count >= TARGET_LIMIT) {
      await persistCollected();
      return Response.json({ allowed: false, code: 'target_rate_limit', retry_after: retryAfter(target, now, RATE_WINDOW_MS) }, { status: 429 });
    }
    if (Object.keys(state.active).length >= MAX_ACTIVE_SCANS) {
      await persistCollected();
      return Response.json({ allowed: false, code: 'concurrency_limit', retry_after: 10 }, { status: 429 });
    }

    state.clients[input.client] = updateCounter(client, now, RATE_WINDOW_MS, true);
    state.targets[input.target] = updateCounter(target, now, RATE_WINDOW_MS, true);
    state.anonymous[input.client] = updateCounter(anonymous, now, CHALLENGE_WINDOW_MS, true);
    state.active[input.scan_id] = now + ACTIVE_TTL_MS;
    await this.ctx.storage.put('security', state);
    return Response.json({ allowed: true });
  }

  private async readState(): Promise<SecurityState> {
    return (
      (await this.ctx.storage.get<SecurityState>('security')) ?? {
        clients: {},
        targets: {},
        anonymous: {},
        active: {},
      }
    );
  }
}

export function normalizeHostname(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  let hostname = value.trim().toLowerCase();
  if (hostname.endsWith('.')) hostname = hostname.slice(0, -1);
  if (!hostnamePattern.test(hostname)) return null;
  if (hostname === 'localhost' || hostname.split('.').every((label) => /^\d+$/.test(label))) return null;
  return hostname;
}

export function shardFor(scanID: string, shardCount: number): number {
  let hash = 2166136261;
  for (const char of scanID) {
    hash ^= char.charCodeAt(0);
    hash = Math.imul(hash, 16777619);
  }
  return (hash >>> 0) % Math.max(1, shardCount);
}

function updateCounter(current: RateCounter | undefined, now: number, window: number, increment: boolean): RateCounter {
  const counter = !current || now - current.startedAt >= window ? { startedAt: now, count: 0 } : current;
  return { startedAt: counter.startedAt, count: counter.count + (increment ? 1 : 0) };
}

function retryAfter(counter: RateCounter, now: number, window: number): number {
  return Math.max(1, Math.ceil((counter.startedAt + window - now) / 1000));
}

async function parsePublicRequest(request: Request): Promise<PublicScanRequest | null> {
  const declared = Number(request.headers.get('content-length') ?? '0');
  if (declared > MAX_BODY_BYTES) return null;
  const text = await request.text();
  if (new TextEncoder().encode(text).byteLength > MAX_BODY_BYTES) return null;
  try {
    const parsed = JSON.parse(text) as Record<string, unknown>;
    const keys = Object.keys(parsed);
    if (keys.some((key) => key !== 'hostname' && key !== 'turnstile_token')) return null;
    if (typeof parsed.hostname !== 'string') return null;
    if (parsed.turnstile_token !== undefined && typeof parsed.turnstile_token !== 'string') return null;
    return parsed as unknown as PublicScanRequest;
  } catch {
    return null;
  }
}

// Rate-limit buckets are keyed by digest so every stored key is a fixed 32
// characters, which keeps the security blob bounded and avoids persisting
// client addresses or the hostnames people look up.
export async function bucketKey(value: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest).slice(0, 16), (byte) => byte.toString(16).padStart(2, '0')).join('');
}

async function clientKey(request: Request): Promise<string> {
  return bucketKey(request.headers.get('CF-Connecting-IP') ?? 'local-anonymous');
}

export async function verifyTurnstile(token: string | undefined, request: Request, env: Env, correlationID: string): Promise<boolean> {
  if (env.TURNSTILE_ENABLED !== 'true') return true;
  if (!token || !env.TURNSTILE_SECRET_KEY) return false;
  const form = new FormData();
  form.set('secret', env.TURNSTILE_SECRET_KEY);
  form.set('response', token);
  const remoteIP = request.headers.get('CF-Connecting-IP');
  if (remoteIP) form.set('remoteip', remoteIP);

  let response: Response;
  try {
    // Without a deadline a stalled siteverify call holds the whole request open.
    response = await fetch(TURNSTILE_VERIFY_URL, { method: 'POST', body: form, signal: AbortSignal.timeout(TURNSTILE_TIMEOUT_MS) });
  } catch (error) {
    console.error(JSON.stringify({ event: 'turnstile_unreachable', correlation_id: correlationID, error: String(error) }));
    return false;
  }
  if (!response.ok) {
    console.error(JSON.stringify({ event: 'turnstile_http_error', correlation_id: correlationID, status: response.status }));
    return false;
  }

  const result = await response.json<{ success: boolean; hostname?: string; 'error-codes'?: string[] }>();
  if (!result.success) {
    console.warn(JSON.stringify({ event: 'turnstile_rejected', correlation_id: correlationID, codes: result['error-codes'] ?? [] }));
    return false;
  }
  // A token is only proof of a challenge solved on *this* site. Without this
  // check a token minted against any other property sharing the secret, or on
  // an attacker-controlled page using the same sitekey, would be accepted.
  const expected = new URL(request.url).hostname;
  if (result.hostname !== undefined && result.hostname !== expected) {
    console.warn(JSON.stringify({ event: 'turnstile_hostname_mismatch', correlation_id: correlationID, expected, got: result.hostname }));
    return false;
  }
  return true;
}

function securityStub(env: Env): DurableObjectStub<SecurityCoordinator> {
  return env.SECURITY.get(env.SECURITY.idFromName('global'));
}

function containerStub(env: Env, scanID: string): DurableObjectStub<ScannerContainer> {
  const shards = Math.max(1, Math.min(10, Number.parseInt(env.CONTAINER_SHARDS, 10) || 1));
  return env.SCANNER.getByName(`scanner-${shardFor(scanID, shards)}`);
}

async function release(env: Env, scanID: string): Promise<void> {
  await securityStub(env).fetch('https://security/release', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ scan_id: scanID }),
  });
}

function apiResponse(body: unknown, status: number, correlationID: string, extra: HeadersInit = {}): Response {
  const headers = new Headers(extra);
  headers.set('content-type', 'application/json; charset=utf-8');
  headers.set('cache-control', 'no-store');
  headers.set('x-content-type-options', 'nosniff');
  headers.set('x-correlation-id', correlationID);
  return new Response(JSON.stringify(body), { status, headers });
}

async function createScan(request: Request, env: Env, correlationID: string): Promise<Response> {
  if (!request.headers.get('content-type')?.toLowerCase().startsWith('application/json')) {
    return apiResponse({ error: { code: 'unsupported_media_type', message: 'Content-Type must be application/json' } }, 415, correlationID);
  }
  const input = await parsePublicRequest(request);
  if (!input) return apiResponse({ error: { code: 'invalid_request', message: 'Expected a small JSON body containing only hostname and optional turnstile_token' } }, 400, correlationID);
  const hostname = normalizeHostname(input.hostname);
  if (!hostname || hostname !== input.hostname.trim().toLowerCase().replace(/\.$/, '')) {
    return apiResponse({ error: { code: 'invalid_hostname', message: 'Enter a normalized DNS hostname without a URL, IP address, or port' } }, 400, correlationID);
  }

  const scanID = crypto.randomUUID();
  const client = await clientKey(request);
  const target = await bucketKey(hostname);
  const turnstileVerified = await verifyTurnstile(input.turnstile_token, request, env, correlationID);
  const reservation = await securityStub(env).fetch('https://security/reserve', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ client, target, scan_id: scanID, turnstile_verified: turnstileVerified } satisfies ReserveRequest),
  });
  const decision = await reservation.json<{ allowed: boolean; code?: string; retry_after?: number }>();
  if (!decision.allowed) {
    const headers: HeadersInit = {};
    if (decision.retry_after) headers['retry-after'] = String(decision.retry_after);
    if (decision.code === 'turnstile_required') {
      return apiResponse({ error: { code: decision.code, message: 'Complete the abuse-protection challenge to continue', site_key: env.TURNSTILE_SITE_KEY } }, 403, correlationID);
    }
    return apiResponse({ error: { code: decision.code ?? 'rate_limited', message: 'Scan limit reached; retry later' } }, reservation.status, correlationID, headers);
  }

  const internal = new Request('http://scanner/internal/v1/scans', {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-internal-gateway': 'cloudflare-worker-v1', 'x-correlation-id': correlationID },
    body: JSON.stringify({ hostname, scan_id: scanID, correlation_id: correlationID }),
  });
  try {
    const response = await containerStub(env, scanID).fetch(internal);
    if (!response.ok) await release(env, scanID);
    return withPublicHeaders(response, correlationID);
  } catch (error) {
    await release(env, scanID);
    console.error(JSON.stringify({ event: 'container_request_failed', correlation_id: correlationID, scan_id: scanID, error: String(error) }));
    return apiResponse({ error: { code: 'scanner_unavailable', message: 'Scanner is starting or unavailable; retry shortly' } }, 503, correlationID, { 'retry-after': '10' });
  }
}

async function getScan(env: Env, scanID: string, correlationID: string): Promise<Response> {
  if (!uuidPattern.test(scanID)) return apiResponse({ error: { code: 'invalid_scan_id', message: 'Invalid scan identifier' } }, 400, correlationID);
  try {
    const response = await containerStub(env, scanID).fetch(
      new Request(`http://scanner/internal/v1/scans/${scanID}`, { headers: { 'x-internal-gateway': 'cloudflare-worker-v1', 'x-correlation-id': correlationID } }),
    );
    if (response.ok) {
      const clone = response.clone();
      const scan = await clone.json<{ status?: string }>();
      if (scan.status === 'complete' || scan.status === 'failed') await release(env, scanID);
    }
    return withPublicHeaders(response, correlationID);
  } catch (error) {
    console.error(JSON.stringify({ event: 'container_poll_failed', correlation_id: correlationID, scan_id: scanID, error: String(error) }));
    return apiResponse({ error: { code: 'scanner_unavailable', message: 'Scanner is unavailable; retry shortly' } }, 503, correlationID, { 'retry-after': '10' });
  }
}

function withPublicHeaders(response: Response, correlationID: string): Response {
  const headers = new Headers(response.headers);
  headers.set('cache-control', 'no-store');
  headers.set('x-content-type-options', 'nosniff');
  headers.set('x-correlation-id', correlationID);
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

async function health(env: Env, path: '/health' | '/ready', correlationID: string): Promise<Response> {
  try {
    const response = await env.SCANNER.getByName('scanner-0').fetch(new Request(`http://scanner${path}`));
    return withPublicHeaders(response, correlationID);
  } catch {
    return apiResponse({ status: 'unavailable' }, 503, correlationID, { 'retry-after': '10' });
  }
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const correlationID = request.headers.get('cf-ray') ?? crypto.randomUUID();
    console.log(JSON.stringify({ event: 'request', method: request.method, path: url.pathname, correlation_id: correlationID, release_sha: env.RELEASE_SHA }));

    if (request.method === 'GET' && (url.pathname === '/health' || url.pathname === '/ready')) {
      return health(env, url.pathname, correlationID);
    }
    if (request.method === 'POST' && url.pathname === `${API_PREFIX}/scans`) {
      return createScan(request, env, correlationID);
    }
    if (request.method === 'GET' && url.pathname.startsWith(`${API_PREFIX}/scans/`)) {
      return getScan(env, url.pathname.slice(`${API_PREFIX}/scans/`.length), correlationID);
    }
    if (url.pathname === '/') return Response.redirect(new URL('/domain-check', url), 302);
    if (request.method !== 'GET' && request.method !== 'HEAD') {
      return apiResponse({ error: { code: 'method_not_allowed', message: 'Method not allowed' } }, 405, correlationID, { allow: 'GET, HEAD' });
    }
    const assetResponse = await env.ASSETS.fetch(request);
    const headers = new Headers(assetResponse.headers);
    headers.set('x-content-type-options', 'nosniff');
    headers.set('referrer-policy', 'strict-origin-when-cross-origin');
    headers.set('permissions-policy', 'camera=(), microphone=(), geolocation=()');
    headers.set('content-security-policy', "default-src 'self'; script-src 'self' https://challenges.cloudflare.com; frame-src https://challenges.cloudflare.com; connect-src 'self' https://challenges.cloudflare.com; style-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
    if (headers.get('content-type')?.includes('text/html')) headers.set('cache-control', 'no-cache');
    else headers.set('cache-control', 'public, max-age=31536000, immutable');
    return new Response(assetResponse.body, { status: assetResponse.status, statusText: assetResponse.statusText, headers });
  },
} satisfies ExportedHandler<Env>;

