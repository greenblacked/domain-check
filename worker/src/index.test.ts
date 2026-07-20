import { describe, expect, it } from 'vitest';
import { normalizeHostname, shardFor } from './index';

describe('normalizeHostname', () => {
  it('normalizes case and a terminal dot', () => {
    expect(normalizeHostname('Example.COM.')).toBe('example.com');
  });

  it.each(['https://example.com', 'example.com:443', '127.0.0.1', '[::1]', 'localhost', 'bad_.example'])(
    'rejects unsafe input %s',
    (value) => expect(normalizeHostname(value)).toBeNull(),
  );
});

describe('shardFor', () => {
  it('is stable and bounded', () => {
    const id = '123e4567-e89b-42d3-a456-426614174000';
    expect(shardFor(id, 3)).toBe(shardFor(id, 3));
    expect(shardFor(id, 3)).toBeGreaterThanOrEqual(0);
    expect(shardFor(id, 3)).toBeLessThan(3);
  });
});

