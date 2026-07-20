// Runtime stand-in for the workerd-only `cloudflare:workers` module so unit
// tests can import from index.ts under Node. Type checking still uses the real
// declarations from @cloudflare/workers-types.
export class DurableObject {}
