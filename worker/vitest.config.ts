import { cloudflareTest } from '@cloudflare/vitest-pool-workers';
import { defineConfig } from 'vitest/config';

// Tests run inside workerd rather than Node, so `cloudflare:workers` and
// `@cloudflare/containers` load for real and SecurityCoordinator is exercised
// against genuine Durable Object storage. Bindings are declared inline instead
// of read from wrangler.jsonc so the suite never needs the container image:
// tests that reach the scanner inject their own SCANNER stub.
export default defineConfig({
  plugins: [
    cloudflareTest({
      main: './src/index.ts',
      miniflare: {
        compatibilityDate: '2026-07-18',
        compatibilityFlags: ['nodejs_compat'],
        durableObjects: {
          SECURITY: { className: 'SecurityCoordinator' },
        },
        bindings: {
          APP_ENV: 'test',
          CONTAINER_SHARDS: '1',
          TURNSTILE_ENABLED: 'false',
          TURNSTILE_SITE_KEY: 'test-site-key',
          TURNSTILE_SECRET_KEY: 'test-secret-key',
          RELEASE_SHA: 'test',
        },
      },
    }),
  ],
});
