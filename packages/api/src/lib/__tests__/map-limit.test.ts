import { describe, expect, it } from 'vitest';

import { mapLimit } from '../map-limit.js';

describe('mapLimit', () => {
  it('keeps input order and never runs more than `limit` at once', async () => {
    let running = 0;
    let peak = 0;
    const out = await mapLimit([5, 1, 4, 2, 3], 2, async (n) => {
      running++;
      peak = Math.max(peak, running);
      await new Promise((r) => setTimeout(r, n));
      running--;
      return n * 10;
    });
    expect(out).toEqual([50, 10, 40, 20, 30]);
    expect(peak).toBe(2);
  });

  it('handles an empty list and refuses a bad limit', async () => {
    expect(await mapLimit([], 4, async () => 1)).toEqual([]);
    await expect(mapLimit([1], 0, async () => 1)).rejects.toBeInstanceOf(RangeError);
  });
});
