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
    const issue: { code: string; message: string; site_key?: string } =
      typeof body.error === 'object'
        ? body.error
        : { code: 'request_failed', message: 'The request could not be completed.' };
    throw new APIError(issue.code, issue.message, issue.site_key);
  }
  return body;
}

export async function createScan(hostname: string, turnstileToken?: string): Promise<Scan> {
  const response = await fetch('/api/v1/scans', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ hostname, ...(turnstileToken ? { turnstile_token: turnstileToken } : {}) }),
  });
  return decode(response);
}

export async function getScan(id: string): Promise<Scan> {
  return decode(await fetch(`/api/v1/scans/${encodeURIComponent(id)}`, { headers: { accept: 'application/json' } }));
}
