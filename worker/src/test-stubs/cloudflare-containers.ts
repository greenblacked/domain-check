// Runtime stand-in for `@cloudflare/containers`, which imports workerd-only
// modules and cannot load under Node. Type checking still uses the real package.
export class Container {}
