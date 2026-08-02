import { env } from 'cloudflare:test';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { verifyTurnstile, type Env } from './index';

const SITE = 'https://tools.goldenman.cloud';
const VERIFY_URL = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';

afterEach(() => vi.unstubAllGlobals());

function enabled(overrides: Partial<Env> = {}): Env {
  return { ...env, TURNSTILE_ENABLED: 'true', TURNSTILE_SECRET_KEY: 'test-secret-key', ...overrides };
}

function request(url = `${SITE}/api/v1/scans`) {
  return new Request(url, { method: 'POST', headers: { 'CF-Connecting-IP': '203.0.113.9' } });
}

/** Stubs the single outbound call verifyTurnstile makes and records it. */
function stubSiteverify(reply: { body?: unknown; status?: number; throws?: Error }) {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  vi.stubGlobal('fetch', async (input: RequestInfo, init: RequestInit = {}) => {
    calls.push({ url: String(input), init });
    if (reply.throws) throw reply.throws;
    return Response.json(reply.body ?? {}, { status: reply.status ?? 200 });
  });
  return calls;
}

describe('verifyTurnstile', () => {
  it('is a no-op when the challenge is disabled', async () => {
    const calls = stubSiteverify({ body: { success: true } });
    await expect(verifyTurnstile(undefined, request(), { ...env, TURNSTILE_ENABLED: 'false' }, 'c')).resolves.toBe(true);
    expect(calls).toHaveLength(0);
  });

  it('refuses when enabled but no token is supplied', async () => {
    const calls = stubSiteverify({ body: { success: true } });
    await expect(verifyTurnstile(undefined, request(), enabled(), 'c')).resolves.toBe(false);
    expect(calls).toHaveLength(0);
  });

  it('refuses when the secret is not configured', async () => {
    await expect(verifyTurnstile('token', request(), enabled({ TURNSTILE_SECRET_KEY: '' }), 'c')).resolves.toBe(false);
  });

  it('accepts a token solved on this site', async () => {
    const calls = stubSiteverify({ body: { success: true, hostname: 'tools.goldenman.cloud' } });
    await expect(verifyTurnstile('token', request(), enabled(), 'c')).resolves.toBe(true);
    expect(calls[0]?.url).toBe(VERIFY_URL);
  });

  it('refuses a token solved on a different site', async () => {
    // Regression: the siteverify hostname was parsed but never compared, so a
    // token minted anywhere else under the same secret was accepted here.
    stubSiteverify({ body: { success: true, hostname: 'attacker.example' } });
    await expect(verifyTurnstile('token', request(), enabled(), 'c')).resolves.toBe(false);
  });

  it('compares against the host actually serving the request', async () => {
    stubSiteverify({ body: { success: true, hostname: 'staging.goldenman.cloud' } });
    await expect(verifyTurnstile('token', request('https://staging.goldenman.cloud/api/v1/scans'), enabled(), 'c')).resolves.toBe(true);
  });

  it('accepts a successful verification that omits the hostname', async () => {
    stubSiteverify({ body: { success: true } });
    await expect(verifyTurnstile('token', request(), enabled(), 'c')).resolves.toBe(true);
  });

  it('refuses an unsuccessful verification', async () => {
    stubSiteverify({ body: { success: false, 'error-codes': ['invalid-input-response'] } });
    await expect(verifyTurnstile('token', request(), enabled(), 'c')).resolves.toBe(false);
  });

  it('refuses when siteverify returns a non-2xx status', async () => {
    stubSiteverify({ body: { success: true, hostname: 'tools.goldenman.cloud' }, status: 500 });
    await expect(verifyTurnstile('token', request(), enabled(), 'c')).resolves.toBe(false);
  });

  it('refuses instead of throwing when siteverify cannot be reached', async () => {
    stubSiteverify({ throws: new Error('network down') });
    await expect(verifyTurnstile('token', request(), enabled(), 'c')).resolves.toBe(false);
  });

  it('bounds the siteverify call with an abort signal', async () => {
    // Regression: an unbounded siteverify call held the whole scan request open.
    const calls = stubSiteverify({ body: { success: true, hostname: 'tools.goldenman.cloud' } });
    await verifyTurnstile('token', request(), enabled(), 'c');
    expect(calls[0]?.init.signal).toBeInstanceOf(AbortSignal);
  });

  it('forwards the caller address to siteverify', async () => {
    const calls = stubSiteverify({ body: { success: true } });
    await verifyTurnstile('token', request(), enabled(), 'c');
    const form = calls[0]?.init.body as FormData;
    expect(form.get('remoteip')).toBe('203.0.113.9');
    expect(form.get('response')).toBe('token');
    expect(form.get('secret')).toBe('test-secret-key');
  });
});
