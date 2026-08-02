import { env, runInDurableObject } from 'cloudflare:test';
import { beforeEach, describe, expect, it } from 'vitest';
import type { SecurityCoordinator } from './index';

const CLIENT_LIMIT = 10;
const TARGET_LIMIT = 4;
const CHALLENGE_AFTER = 3;
const MAX_TRACKED_ENTRIES = 250;
const RATE_WINDOW_MS = 60_000;
const CHALLENGE_WINDOW_MS = 10 * 60_000;

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
interface Decision {
  allowed: boolean;
  code?: string;
  retry_after?: number;
}

let stub: DurableObjectStub<SecurityCoordinator>;

beforeEach(() => {
  // A fresh coordinator per test keeps counter state from leaking between cases.
  stub = env.SECURITY.get(env.SECURITY.idFromName(crypto.randomUUID()));
});

async function reserve(overrides: Partial<Record<'client' | 'target' | 'scan_id', string>> & { turnstile_verified?: boolean } = {}) {
  const response = await stub.fetch('https://security/reserve', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      client: 'client-a',
      target: 'target-a',
      scan_id: crypto.randomUUID(),
      turnstile_verified: true,
      ...overrides,
    }),
  });
  return { status: response.status, decision: await response.json<Decision>() };
}

async function release(scanID: string) {
  return stub.fetch('https://security/release', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ scan_id: scanID }),
  });
}

function readState() {
  return runInDurableObject(stub, (_instance, state) => state.storage.get<SecurityState>('security'));
}

function writeState(value: SecurityState) {
  return runInDurableObject(stub, (_instance, state) => state.storage.put('security', value));
}

function emptyState(): SecurityState {
  return { clients: {}, targets: {}, anonymous: {}, active: {} };
}

describe('rate limiting', () => {
  it('allows a client up to the per-client limit and then refuses with a retry hint', async () => {
    // Distinct targets so the tighter per-target limit does not fire first.
    for (let i = 0; i < CLIENT_LIMIT; i++) {
      const { status } = await reserve({ target: `target-${i}` });
      expect(status).toBe(200);
    }
    const { status, decision } = await reserve({ target: 'target-final' });
    expect(status).toBe(429);
    expect(decision.code).toBe('client_rate_limit');
    expect(decision.retry_after).toBeGreaterThan(0);
  });

  it('limits repeated scans of the same target', async () => {
    for (let i = 0; i < TARGET_LIMIT; i++) {
      expect((await reserve({ client: `client-${i}` })).status).toBe(200);
    }
    const { status, decision } = await reserve({ client: 'client-late' });
    expect(status).toBe(429);
    expect(decision.code).toBe('target_rate_limit');
  });

  it('requires a challenge after repeated anonymous use', async () => {
    for (let i = 0; i < CHALLENGE_AFTER; i++) {
      expect((await reserve({ target: `target-${i}`, turnstile_verified: false })).status).toBe(200);
    }
    const refused = await reserve({ target: 'target-next', turnstile_verified: false });
    expect(refused.status).toBe(403);
    expect(refused.decision.code).toBe('turnstile_required');

    // A verified caller gets through at the same anonymous count.
    expect((await reserve({ target: 'target-next', turnstile_verified: true })).status).toBe(200);
  });

  it('caps globally concurrent scans', async () => {
    const state = emptyState();
    for (let i = 0; i < 20; i++) state.active[`scan-${i}`] = Date.now() + 60_000;
    await writeState(state);
    const { status, decision } = await reserve();
    expect(status).toBe(429);
    expect(decision.code).toBe('concurrency_limit');
  });

  it('frees a concurrency slot on release', async () => {
    const state = emptyState();
    for (let i = 0; i < 20; i++) state.active[`scan-${i}`] = Date.now() + 60_000;
    await writeState(state);
    expect((await reserve()).status).toBe(429);

    await release('scan-0');
    expect((await reserve()).status).toBe(200);
  });
});

describe('state reclamation', () => {
  it('drops counters whose window has lapsed and reservations that have expired', async () => {
    const stale = Date.now() - 2 * CHALLENGE_WINDOW_MS;
    await writeState({
      clients: { 'stale-client': { startedAt: stale, count: 9 } },
      targets: { 'stale-target': { startedAt: stale, count: 3 } },
      anonymous: { 'stale-client': { startedAt: stale, count: 5 } },
      active: { 'expired-scan': Date.now() - 1 },
    });

    expect((await reserve()).status).toBe(200);

    const state = await readState();
    expect(state?.clients).not.toHaveProperty('stale-client');
    expect(state?.targets).not.toHaveProperty('stale-target');
    expect(state?.anonymous).not.toHaveProperty('stale-client');
    expect(state?.active).not.toHaveProperty('expired-scan');
  });

  it('reclaims space even when the reservation is refused', async () => {
    // Regression: reclamation used to be discarded on every rejection path,
    // so a saturated client meant state only ever grew.
    const stale = Date.now() - 2 * CHALLENGE_WINDOW_MS;
    const state = emptyState();
    for (let i = 0; i < 40; i++) state.clients[`stale-${i}`] = { startedAt: stale, count: 1 };
    state.clients['client-a'] = { startedAt: Date.now(), count: CLIENT_LIMIT };
    await writeState(state);

    expect((await reserve()).status).toBe(429);

    const after = await readState();
    expect(Object.keys(after?.clients ?? {}).filter((key) => key.startsWith('stale-'))).toHaveLength(0);
  });

  it('evicts the entries closest to expiry once a map exceeds its cap', async () => {
    const now = Date.now();
    const state = emptyState();
    // 400 live counters, oldest first: only the newest cap-worth may survive.
    for (let i = 0; i < 400; i++) state.clients[`client-${i}`] = { startedAt: now - (400 - i) * 10, count: 1 };
    await writeState(state);

    expect((await reserve({ client: 'client-new' })).status).toBe(200);

    const after = await readState();
    const retained = Object.keys(after?.clients ?? {});
    expect(retained.length).toBeLessThanOrEqual(MAX_TRACKED_ENTRIES + 1);
    expect(retained).toContain('client-399');
    expect(retained).not.toContain('client-0');
  });

  it('keeps the stored blob far below the Durable Object value limit under churn', async () => {
    // Regression for unbounded growth: counter maps had no eviction, so the
    // blob grew once per unique client and target until writes began failing
    // at the 128 KiB per-value limit and every scan was refused from then on.
    for (let i = 0; i < 300; i++) {
      const scanID = crypto.randomUUID();
      await reserve({ client: `client-${i}`, target: `target-${i}`, scan_id: scanID });
      await release(scanID);
    }

    const state = await readState();
    const bytes = new TextEncoder().encode(JSON.stringify(state)).byteLength;
    expect(bytes).toBeLessThan(64 * 1024);
    expect(Object.keys(state?.clients ?? {}).length).toBeLessThanOrEqual(MAX_TRACKED_ENTRIES);
    expect(Object.keys(state?.targets ?? {}).length).toBeLessThanOrEqual(MAX_TRACKED_ENTRIES);
    expect(Object.keys(state?.anonymous ?? {}).length).toBeLessThanOrEqual(MAX_TRACKED_ENTRIES);
  });

  it('leaves live counters within their window untouched', async () => {
    const now = Date.now();
    await writeState({
      clients: { 'live-client': { startedAt: now - RATE_WINDOW_MS / 2, count: 2 } },
      targets: {},
      anonymous: {},
      active: {},
    });

    expect((await reserve({ client: 'other-client' })).status).toBe(200);

    const state = await readState();
    expect(state?.clients['live-client']?.count).toBe(2);
  });
});

describe('routing', () => {
  it('rejects unknown coordinator routes', async () => {
    const response = await stub.fetch('https://security/nope', { method: 'POST' });
    expect(response.status).toBe(404);
  });
});
