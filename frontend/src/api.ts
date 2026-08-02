export interface Finding {
  code: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  title: string;
  evidence: string;
}

export interface ScanReport {
  schema_version: string;
  hostname: string;
  resolved_ips: string[];
  tls: {
    version: string;
    cipher_suite: string;
    subject: string;
    issuer: string;
    not_before: string;
    not_after: string;
    dns_names: string[];
    days_remaining: number;
  };
  findings: Finding[];
  scanned_at: string;
}

export interface Scan {
  id: string;
  hostname: string;
  correlation_id: string;
  status: 'queued' | 'running' | 'complete' | 'failed';
  progress: number;
  created_at: string;
  completed_at?: string;
  report?: ScanReport;
  error?: string;
}

export class APIError extends Error {
  constructor(
    public code: string,
    message: string,
    public siteKey?: string,
  ) {
    super(message);
  }
}

async function decode(response: Response): Promise<Scan> {
  const body = (await response.json()) as Scan & { error?: { code: string; message: string; site_key?: string } };
  if (!response.ok) {
    // `typeof null` is also 'object', so a body of {"error": null} used to pass
    // this check and then throw a TypeError on the next line.
    const issue: { code: string; message: string; site_key?: string } =
      body.error && typeof body.error === 'object'
        ? body.error
        : { code: 'request_failed', message: 'The request could not be completed.' };
    throw new APIError(issue.code, issue.message, issue.site_key);
  }
  return body;
}

const REQUEST_TIMEOUT_MS = 10_000;

/**
 * Every request carries a deadline. Without one a stalled connection leaves the
 * promise pending forever, which silently strands the caller's poll loop.
 */
async function send(path: string, init: RequestInit): Promise<Scan> {
  let response: Response;
  try {
    response = await fetch(path, { ...init, signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) });
  } catch {
    throw new APIError('network_error', 'The service could not be reached. Check your connection and try again.');
  }
  return decode(response);
}

export async function createScan(hostname: string, turnstileToken?: string): Promise<Scan> {
  return send('/api/v1/scans', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ hostname, ...(turnstileToken ? { turnstile_token: turnstileToken } : {}) }),
  });
}

export async function getScan(id: string): Promise<Scan> {
  return send(`/api/v1/scans/${encodeURIComponent(id)}`, { headers: { accept: 'application/json' } });
}
