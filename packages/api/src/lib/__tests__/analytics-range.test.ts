import { describe, expect, it } from 'vitest';

import { resolveRange } from '../analytics-range.js';

/** ADR-0006: UTC day ranges inside the 365-day window. */

const NOW = new Date('2026-06-15T12:00:00Z');

describe('resolveRange', () => {
  it('defaults to the last 30 days, today included', () => {
    expect(resolveRange({}, NOW)).toEqual({ from: '2026-05-17', to: '2026-06-15' });
    expect(resolveRange({ to: '2026-06-01' }, NOW)).toEqual({ from: '2026-05-03', to: '2026-06-01' });
  });

  it('accepts the full 365-day window and keeps a defaulted from inside it', () => {
    expect(resolveRange({ from: '2025-06-16', to: '2026-06-15' }, NOW)).toEqual({ from: '2025-06-16', to: '2026-06-15' });
    expect(resolveRange({ to: '2025-06-20' }, NOW)).toEqual({ from: '2025-06-16', to: '2025-06-20' });
  });

  it.each([
    [{ from: '2025-06-15' }, /on or after 2025-06-16/],
    [{ to: '2026-06-16' }, /future/],
    [{ from: '2026-06-10', to: '2026-06-01' }, /after to/],
    [{ from: '2026-02-30' }, /real dates/],
  ])('refuses %o', (query, message) => {
    const result = resolveRange(query, NOW);
    expect(result).toHaveProperty('error');
    expect((result as { error: string }).error).toMatch(message);
  });
});
