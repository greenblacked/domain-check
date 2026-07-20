import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';

// `index.ts` imports workerd-only modules (`cloudflare:workers`, and
// `@cloudflare/containers` which itself depends on them). The unit tests only
// exercise pure functions, so those modules are aliased to inert stubs.
export default defineConfig({
  resolve: {
    alias: {
      'cloudflare:workers': fileURLToPath(new URL('./src/test-stubs/cloudflare-workers.ts', import.meta.url)),
      '@cloudflare/containers': fileURLToPath(new URL('./src/test-stubs/cloudflare-containers.ts', import.meta.url)),
    },
  },
  test: {
    environment: 'node',
  },
});
