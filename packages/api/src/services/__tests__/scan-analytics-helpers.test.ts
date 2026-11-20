import { describe, expect, it } from 'vitest';

import { daysBetween, splitRange, toWeeks, weekStart } from '../scan-analytics.js';
import { csvCell, csvLine } from '../../lib/csv.js';

/** ADR-0006 D3/D4 helpers and CSV escaping. */

const NOW = new Date('2026-06-15T12:00:00Z');

describe('splitRange', () => {
  it('reads yesterday and today live, earlier days from rollups', () => {
    expect(splitRange({ from: '2026-06-01', to: '2026-06-15' }, NOW)).toEqual({
      rollup: { from: '2026-06-01', to: '2026-06-13' },
      live: { from: '2026-06-14', to: '2026-06-15' },
    });
    expect(splitRange({ from: '2026-06-01', to: '2026-06-10' }, NOW)).toEqual({ rollup: { from: '2026-06-01', to: '2026-06-10' }, live: null });
    expect(splitRange({ from: '2026-06-15', to: '2026-06-15' }, NOW)).toEqual({ rollup: null, live: { from: '2026-06-15', to: '2026-06-15' } });
  });
});

describe('weeks', () => {
  it('ISO weeks start on Monday (UTC)', () => {
    expect(weekStart('2026-06-15')).toBe('2026-06-15'); // Monday
    expect(weekStart('2026-06-21')).toBe('2026-06-15'); // Sunday
    expect(weekStart('2026-06-14')).toBe('2026-06-08');
  });

  it('sums days into weeks; a weekly unique is the sum of daily uniques', () => {
    const days = daysBetween('2026-06-12', '2026-06-16').map((date, i) => ({ date, total: i + 1, unique: 1 }));
    expect(toWeeks(days)).toEqual([
      { date: '2026-06-08', total: 1 + 2 + 3, unique: 3 },
      { date: '2026-06-15', total: 4 + 5, unique: 2 },
    ]);
  });
});

describe('CSV', () => {
  it('quotes separators and quotes, and neutralises formula starts', () => {
    expect(csvCell('Athens')).toBe('Athens');
    expect(csvCell('Paris, "centre"')).toBe('"Paris, ""centre"""');
    expect(csvCell('=HYPERLINK("x")')).toBe(`"'=HYPERLINK(""x"")"`);
    expect(csvCell('+1')).toBe("'+1");
    expect(csvCell('@SUM(A1)')).toBe("'@SUM(A1)");
    expect(csvCell(-5)).toBe('-5');
    expect(csvCell(null)).toBe('');
    expect(csvLine(['a', null, 3])).toBe('a,,3\r\n');
  });
});
