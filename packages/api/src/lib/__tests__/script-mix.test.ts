import { describe, expect, it } from 'vitest';

import { labelScripts } from '../script-mix.js';

describe('UTS #39 restriction level of a label', () => {
  it.each([
    ['paypal', ['Latin']],
    ['ουτοπία', ['Greek']],
    ['παράδειγμα', ['Greek']],
    ['εθνικήτράπεζα', ['Greek']],
    ['москва', ['Cyrillic']],
    ['日本語', ['Han']],
    ['abc-123', ['Latin']],
  ])('%s is single-script (Highly Restrictive)', (label, scripts) => {
    expect(labelScripts(label)).toEqual({ highlyRestrictive: true, scripts });
  });

  it.each(['東京tokyo', 'ひらがなカタカナ漢字abc', '한국어seoul'])('%s is an allowed CJK + Latin mix', (label) => {
    expect(labelScripts(label).highlyRestrictive).toBe(true);
  });

  it.each([
    ['pаypal', ['Latin', 'Cyrillic']],
    ['gοogle', ['Latin', 'Greek']],
    ['раураl', ['Cyrillic', 'Latin']],
    ['ηellenic', ['Greek', 'Latin']],
    ['gօogle', ['Latin', 'Armenian']],
  ])('%s mixes scripts (below Highly Restrictive)', (label, scripts) => {
    expect(labelScripts(label)).toEqual({ highlyRestrictive: false, scripts });
  });

  it('digits and hyphens are neutral; an empty label passes', () => {
    expect(labelScripts('123-456').highlyRestrictive).toBe(true);
    expect(labelScripts('').highlyRestrictive).toBe(true);
  });
});
