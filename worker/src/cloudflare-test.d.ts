import type { Env as WorkerEnv } from './index';

// Teaches `cloudflare:test` about this Worker's bindings so `env` in the test
// suites is typed as the real environment rather than an empty interface.
declare global {
  namespace Cloudflare {
    // eslint-disable-next-line @typescript-eslint/no-empty-object-type
    interface Env extends WorkerEnv {}
  }
}

export {};
