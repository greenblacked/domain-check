import { expect, test } from '@playwright/test';

const scanID = '123e4567-e89b-42d3-a456-426614174000';

test('completes a scan and exposes technical evidence by keyboard', async ({ page }) => {
  let polls = 0;
  await page.route('**/api/v1/scans', async (route) => {
    await route.fulfill({ status: 202, contentType: 'application/json', body: JSON.stringify(scan('queued', 5)) });
  });
  await page.route(`**/api/v1/scans/${scanID}`, async (route) => {
    polls++;
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify(scan(polls > 1 ? 'complete' : 'running', polls > 1 ? 100 : 45)),
    });
  });

  await page.goto('');
  await page.getByLabel('Domain hostname').fill('fixture.test');
  await page.getByRole('button', { name: 'Run check' }).click();
  await expect(page.getByRole('progressbar')).toBeVisible();
  await expect(page.getByText('Scan complete')).toBeVisible();
  await expect(page.getByText('TLS endpoint available')).toBeVisible();
  await page.locator('details summary', { hasText: 'TLS endpoint available' }).focus();
  await page.keyboard.press('Enter');
  await expect(page.getByText('TLS 1.3 / TLS_AES_128_GCM_SHA256')).toBeVisible();
});

test('shows understandable validation errors', async ({ page }) => {
  await page.goto('');
  await page.getByLabel('Domain hostname').fill('https://127.0.0.1:8443');
  await page.getByRole('button', { name: 'Run check' }).click();
  await expect(page.getByRole('alert')).toContainText('not a URL, IP address, or port');
});

function scan(status: 'queued' | 'running' | 'complete', progress: number) {
  return {
    id: scanID,
    hostname: 'fixture.test',
    correlation_id: 'e2e-correlation',
    status,
    progress,
    created_at: '2026-01-01T00:00:00Z',
    ...(status === 'complete'
      ? {
          completed_at: '2026-01-01T00:00:01Z',
          report: {
            schema_version: '1.0.0',
            hostname: 'fixture.test',
            resolved_ips: ['203.0.113.10'],
            tls: {
              version: 'TLS 1.3',
              cipher_suite: 'TLS_AES_128_GCM_SHA256',
              subject: 'CN=fixture.test',
              issuer: 'CN=Fixture CA',
              not_before: '2026-01-01T00:00:00Z',
              not_after: '2027-01-01T00:00:00Z',
              dns_names: ['fixture.test'],
              days_remaining: 365,
            },
            findings: [
              { code: 'TLS_SUPPORTED', severity: 'info', title: 'TLS endpoint available', evidence: 'TLS 1.3 / TLS_AES_128_GCM_SHA256' },
            ],
            scanned_at: '2026-01-01T00:00:01Z',
          },
        }
      : {}),
  };
}
