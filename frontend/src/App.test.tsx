import { act, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import App from './App';

const SCAN_ID = '123e4567-e89b-42d3-a456-426614174000';

function scanBody(status: 'queued' | 'running' | 'complete' | 'failed', progress = 25) {
  return {
    id: SCAN_ID,
    hostname: 'example.com',
    correlation_id: 'test-correlation',
    status,
    progress,
    created_at: '2026-01-01T00:00:00Z',
    ...(status === 'complete'
      ? {
          report: {
            schema_version: '1.0.0',
            hostname: 'example.com',
            resolved_ips: ['203.0.113.10'],
            tls: {
              version: 'TLS 1.3',
              cipher_suite: 'TLS_AES_128_GCM_SHA256',
              subject: 'CN=example.com',
              issuer: 'CN=Example CA',
              not_before: '2026-01-01T00:00:00Z',
              not_after: '2027-01-01T00:00:00Z',
              dns_names: ['example.com'],
              days_remaining: 300,
            },
            findings: [{ code: 'TLS_SUPPORTED', severity: 'info', title: 'TLS endpoint available', evidence: 'TLS 1.3' }],
            scanned_at: '2026-01-01T00:00:01Z',
          },
        }
      : {}),
    ...(status === 'failed' ? { error: 'resolved address is private, reserved, or non-routable' } : {}),
  };
}

function ok(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
}

/** Queues one response per call so a test can script a whole poll sequence. */
function stubFetch(...responses: Array<() => Response | Promise<Response>>) {
  const calls: string[] = [];
  let index = 0;
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL) => {
      calls.push(String(input));
      const next = responses[Math.min(index, responses.length - 1)]!;
      index++;
      return next();
    }),
  );
  return calls;
}

function startScan() {
  render(<App />);
  fireEvent.change(screen.getByLabelText('Domain hostname'), { target: { value: 'example.com' } });
  fireEvent.click(screen.getByRole('button', { name: 'Run check' }));
}

function pollsIn(calls: string[]) {
  return calls.filter((url) => url.includes(`/api/v1/scans/${SCAN_ID}`));
}

async function advance(ms: number) {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(ms);
  });
}

/**
 * Runs the poll loop forward. React only schedules the next poll when effects
 * flush at the end of an act() block, so time has to be advanced in rounds
 * rather than in one jump. Each round is longer than the maximum backoff, so it
 * lets exactly one poll through.
 */
async function pump(rounds = 8) {
  for (let index = 0; index < rounds; index++) await advance(6_000);
}

beforeEach(() => vi.useFakeTimers());

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe('validation', () => {
  it.each(['http://127.0.0.1:8080', 'example.com:443', '1.2.3.4', 'localhost'])('rejects %s before any request', async (value) => {
    const calls = stubFetch(() => ok(scanBody('queued')));
    render(<App />);
    fireEvent.change(screen.getByLabelText('Domain hostname'), { target: { value } });
    fireEvent.click(screen.getByRole('button', { name: 'Run check' }));
    await advance(0);
    expect(screen.getByRole('alert')).toHaveTextContent('not a URL, IP address, or port');
    expect(calls).toHaveLength(0);
  });
});

describe('polling', () => {
  it('keeps polling until the scan completes', async () => {
    const calls = stubFetch(
      () => ok(scanBody('queued', 5)),
      () => ok(scanBody('running', 25)),
      () => ok(scanBody('running', 60)),
      () => ok(scanBody('complete', 100)),
    );
    startScan();
    await pump();

    expect(screen.getByText('Scan complete')).toBeInTheDocument();
    expect(pollsIn(calls)).toHaveLength(3);
  });

  it('recovers from a transient poll failure instead of stalling', async () => {
    // Regression: a failed poll only set an error message. Because the effect
    // depended on the unchanged scan object it never re-ran, so polling stopped
    // permanently while the card kept claiming to be in progress.
    const calls = stubFetch(
      () => ok(scanBody('queued', 5)),
      () => Promise.reject(new TypeError('network down')),
      () => ok(scanBody('complete', 100)),
    );
    startScan();
    await pump();

    expect(screen.getByText('Scan complete')).toBeInTheDocument();
    expect(pollsIn(calls).length).toBeGreaterThanOrEqual(2);
  });

  it('gives up after repeated failures and stops presenting the scan as busy', async () => {
    stubFetch(
      () => ok(scanBody('queued', 5)),
      () => Promise.reject(new TypeError('network down')),
    );
    startScan();
    await pump(10);

    expect(screen.getByText('Check stopped')).toBeInTheDocument();
    expect(document.querySelector('[aria-busy="true"]')).toBeNull();
    expect(screen.queryByRole('progressbar')).toBeNull();
  });

  it('stops polling once the scan has failed', async () => {
    const calls = stubFetch(
      () => ok(scanBody('queued', 5)),
      () => ok(scanBody('failed', 100)),
    );
    startScan();
    await pump(3);

    expect(screen.getByText('Check stopped safely')).toBeInTheDocument();
    const settled = calls.length;
    await pump(5);
    expect(calls).toHaveLength(settled);
  });

  it('surfaces a challenge requirement returned by the API', async () => {
    stubFetch(() => ok({ error: { code: 'turnstile_required', message: 'Complete the challenge', site_key: 'site-key-1' } }, 403));
    startScan();
    await advance(0);

    expect(screen.getByRole('alert')).toHaveTextContent('Complete the challenge');
    expect(screen.getByText(/security check is required/i)).toBeInTheDocument();
  });
});
