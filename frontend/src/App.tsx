import { FormEvent, useEffect, useRef, useState } from 'react';
import { APIError, createScan, getScan, type Scan } from './api';

declare global {
  interface Window {
    turnstile?: {
      render: (element: HTMLElement, options: { sitekey: string; callback: (token: string) => void; 'error-callback': () => void }) => string;
      remove: (widget: string) => void;
    };
  }
}

const hostnamePattern = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const POLL_INTERVAL_MS = 650;
const MAX_POLL_BACKOFF_MS = 5_000;
const MAX_POLL_FAILURES = 5;
const MAX_POLL_DURATION_MS = 120_000;

function App() {
  const [hostname, setHostname] = useState('');
  const [scan, setScan] = useState<Scan | null>(null);
  const [error, setError] = useState('');
  const [siteKey, setSiteKey] = useState('');
  const [turnstileToken, setTurnstileToken] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [pollFailures, setPollFailures] = useState(0);
  const [pollAbandoned, setPollAbandoned] = useState(false);
  const pollDeadline = useRef(0);

  // Polling is driven by state rather than by a self-rescheduling timer: a
  // failed attempt bumps pollFailures, which both re-runs this effect and backs
  // the next attempt off. Previously a failure only set an error message, so a
  // single dropped request left the scan spinning forever with no further polls.
  useEffect(() => {
    if (!scan || (scan.status !== 'queued' && scan.status !== 'running') || pollAbandoned) return;
    if (pollFailures >= MAX_POLL_FAILURES || Date.now() >= pollDeadline.current) {
      setPollAbandoned(true);
      setError('The scan did not finish in time. Please run the check again.');
      return;
    }
    const delay = Math.min(POLL_INTERVAL_MS * 2 ** pollFailures, MAX_POLL_BACKOFF_MS);
    const timer = window.setTimeout(() => {
      getScan(scan.id).then(
        (next) => {
          setPollFailures(0);
          setError('');
          setScan(next);
        },
        (reason) => {
          setPollFailures((failures) => failures + 1);
          setError(messageFor(reason));
        },
      );
    }, delay);
    return () => window.clearTimeout(timer);
  }, [scan, pollFailures, pollAbandoned]);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const normalized = hostname.trim().toLowerCase().replace(/\.$/, '');
    if (!hostnamePattern.test(normalized) || normalized.split('.').every((label) => /^\d+$/.test(label))) {
      setError('Enter a hostname such as example.com—not a URL, IP address, or port.');
      return;
    }
    setError('');
    setSubmitting(true);
    try {
      const created = await createScan(normalized, turnstileToken || undefined);
      setHostname(normalized);
      setPollFailures(0);
      setPollAbandoned(false);
      pollDeadline.current = Date.now() + MAX_POLL_DURATION_MS;
      setScan(created);
      setTurnstileToken('');
      setSiteKey('');
    } catch (reason) {
      if (reason instanceof APIError && reason.code === 'turnstile_required' && reason.siteKey) setSiteKey(reason.siteKey);
      setError(messageFor(reason));
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="shell">
      <header className="topbar">
        <a className="brand" href="/domain-check" aria-label="Goldenman Tools home">
          <span className="brand-mark" aria-hidden="true">G</span>
          <span>Goldenman Tools</span>
        </a>
        <span className="secure-note"><span aria-hidden="true">●</span> Edge protected</span>
      </header>

      <main>
        <section className="hero" aria-labelledby="page-title">
          <p className="eyebrow">Public DNS + TLS inspector</p>
          <h1 id="page-title">Know what your domain presents to the world.</h1>
          <p className="intro">A focused, read-only check of public address records and the certificate served on standard HTTPS.</p>

          <form className="scan-form" onSubmit={submit} noValidate>
            <label htmlFor="hostname">Domain hostname</label>
            <div className="input-row">
              <span className="protocol" aria-hidden="true">https://</span>
              <input
                id="hostname"
                name="hostname"
                value={hostname}
                onChange={(event) => setHostname(event.target.value)}
                placeholder="example.com"
                autoCapitalize="none"
                autoCorrect="off"
                spellCheck="false"
                aria-describedby="hostname-help"
                aria-invalid={Boolean(error)}
              />
              <button type="submit" disabled={submitting || Boolean(siteKey && !turnstileToken)}>
                {submitting ? 'Starting…' : 'Run check'}
              </button>
            </div>
            <p id="hostname-help" className="help">Hostname only. Ports, URLs, IP addresses, and custom resolvers are never accepted.</p>
          </form>

          {siteKey && <Turnstile siteKey={siteKey} onToken={setTurnstileToken} onError={() => setError('The security challenge could not load. Please refresh and try again.')} />}
          {turnstileToken && <p className="challenge-ready">Challenge complete. Run the check again.</p>}
          {error && <div className="error" role="alert"><span aria-hidden="true">!</span><p>{error}</p></div>}
        </section>

        {scan && <ScanResult scan={scan} abandoned={pollAbandoned} />}

        <section className="principles" aria-label="How checks stay safe">
          <article><span>01</span><h2>Public targets only</h2><p>Private, reserved, loopback, and link-local addresses are rejected after DNS resolution.</p></article>
          <article><span>02</span><h2>Fixed network scope</h2><p>The scanner uses standard TLS on port 443. Callers cannot choose an upstream or redirect destination.</p></article>
          <article><span>03</span><h2>Short-lived results</h2><p>Scan state expires after 15 minutes. Reports are not indexed or shared across users.</p></article>
        </section>
      </main>

      <footer><span>Domain Check</span><span>Read-only public surface analysis</span></footer>
    </div>
  );
}

function ScanResult({ scan, abandoned }: { scan: Scan; abandoned: boolean }) {
  if (scan.status === 'queued' || scan.status === 'running') {
    // Once polling has been given up the card must stop claiming to be busy,
    // otherwise it spins indefinitely and assistive technology keeps announcing
    // work that is no longer happening.
    if (abandoned) {
      return (
        <section className="result-card" aria-live="polite">
          <p className="eyebrow">Check stopped</p>
          <h2>{scan.hostname}</h2>
          <p>No result came back in time. The scan may still be running—run the check again to pick it up.</p>
        </section>
      );
    }
    return (
      <section className="result-card progress-card" aria-live="polite" aria-busy="true">
        <div className="result-heading"><div><p className="eyebrow">Scan in progress</p><h2>{scan.hostname}</h2></div><span>{scan.progress}%</span></div>
        <div className="progress-track" role="progressbar" aria-label="Scan progress" aria-valuemin={0} aria-valuemax={100} aria-valuenow={scan.progress}><span style={{ width: `${scan.progress}%` }} /></div>
        <p>Resolving public addresses and negotiating TLS securely…</p>
      </section>
    );
  }
  if (scan.status === 'failed') {
    return <section className="result-card" aria-live="polite"><p className="eyebrow">Check stopped safely</p><h2>{scan.hostname}</h2><div className="error inline" role="alert"><span aria-hidden="true">!</span><p>{scan.error || 'The scan could not be completed.'}</p></div></section>;
  }
  if (!scan.report) return null;
  return (
    <section className="result-card" aria-live="polite">
      <div className="result-heading"><div><p className="eyebrow">Scan complete</p><h2>{scan.hostname}</h2></div><span className="status-pill">Complete</span></div>
      <dl className="summary-grid">
        <div><dt>Addresses</dt><dd>{scan.report.resolved_ips.join(', ')}</dd></div>
        <div><dt>TLS</dt><dd>{scan.report.tls.version}</dd></div>
        <div><dt>Certificate</dt><dd>{scan.report.tls.days_remaining} days remaining</dd></div>
      </dl>
      <div className="findings">
        <h3>Findings</h3>
        {scan.report.findings.map((finding) => (
          <details key={finding.code}>
            <summary><span className={`severity ${finding.severity}`}>{finding.severity}</span><strong>{finding.title}</strong><span className="expand">Evidence</span></summary>
            <div className="evidence"><code>{finding.code}</code><p>{finding.evidence}</p></div>
          </details>
        ))}
      </div>
      <p className="correlation">Reference: {scan.correlation_id}</p>
    </section>
  );
}

function Turnstile({ siteKey, onToken, onError }: { siteKey: string; onToken: (token: string) => void; onError: () => void }) {
  const target = useRef<HTMLDivElement>(null);
  useEffect(() => {
    let widget = '';
    const render = () => {
      if (target.current && window.turnstile) widget = window.turnstile.render(target.current, { sitekey: siteKey, callback: onToken, 'error-callback': onError });
    };
    let script = document.querySelector<HTMLScriptElement>('script[data-turnstile]');
    if (!script) {
      script = document.createElement('script');
      script.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';
      script.async = true;
      script.defer = true;
      script.dataset.turnstile = 'true';
      document.head.appendChild(script);
    }
    if (window.turnstile) render(); else script.addEventListener('load', render, { once: true });
    return () => { if (widget && window.turnstile) window.turnstile.remove(widget); };
  }, [siteKey, onToken, onError]);
  return <div className="challenge"><p>One quick security check is required after repeated anonymous use.</p><div ref={target} /></div>;
}

function messageFor(reason: unknown): string {
  if (reason instanceof APIError) return reason.message;
  return 'The service could not be reached. Check your connection and try again.';
}

export default App;

