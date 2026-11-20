import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

import { CONFUSABLES_FILE, CONFUSABLES_SHA256, CONFUSABLES_VERSION, parseConfusables, skeleton } from '../confusables.js';

describe('confusables data', () => {
  it('is the pinned, unmodified file: SHA-256 matches the constant and the README', () => {
    const hash = createHash('sha256').update(readFileSync(CONFUSABLES_FILE)).digest('hex');
    expect(hash).toBe(CONFUSABLES_SHA256);
    const readme = readFileSync(new URL('../../../data/third-party/unicode/README.md', import.meta.url), 'utf8');
    expect(readme).toContain(CONFUSABLES_SHA256);
    expect(readme).toContain(`Version | ${CONFUSABLES_VERSION}`);
  });

  it("matches the Unicode version of this Node.js (regex Script_Extensions and NFKC use it)", () => {
    const [major, minor] = CONFUSABLES_VERSION.split('.');
    expect(process.versions.unicode).toBe(`${major}.${minor}`);
  });

  it('refuses a data file of another version', () => {
    expect(() => parseConfusables('# Version: 16.0.0\n0430 ;\t0061 ;\tMA\n')).toThrow(/expected 17\.0\.0/);
    expect(CONFUSABLES_VERSION).toBe('17.0.0');
  });

  it('parses source → target sequences', () => {
    const table = parseConfusables('# Version: 17.0.0\n0430 ;\t0061 ;\tMA\t# a\n006D ;\t0072 006E ;\tMA\t# m → rn\n');
    expect(table.get(0x430)).toBe('a');
    expect(table.get(0x6d)).toBe('rn');
  });
});

describe('UTS #39 skeleton', () => {
  it.each([
    ['раураl', 'paypal'], // Cyrillic р а у а р + Latin l
    ['аррӏе', 'apple'], // Cyrillic а р р palochka е
    ['gοοgle', 'google'], // Greek omicron
    ['gօօgle', 'google'], // Armenian oh
    ['հսbble', 'hubble'], // Armenian ho, seh
    ['νινα', 'viva'], // all-Greek: nu iota nu alpha
  ])('%s and %s share a skeleton', (a, b) => {
    expect(skeleton(a)).toBe(skeleton(b));
  });

  it('maps ASCII confusables (1 → l, 0 → O, m → rn)', () => {
    expect(skeleton('paypa1')).toBe(skeleton('paypal'));
    expect(skeleton('g00gle').toLowerCase()).toBe(skeleton('google'));
    expect(skeleton('microsoft')).toBe(skeleton('rnicrosoft'));
  });

  it('removes default-ignorable code points (zero-width joiner, soft hyphen)', () => {
    expect(skeleton('pay‍pal')).toBe(skeleton('paypal'));
    expect(skeleton('pay­pal')).toBe(skeleton('paypal'));
  });

  it('keeps unrelated strings apart', () => {
    expect(skeleton('paypal')).not.toBe(skeleton('paypai'));
    expect(skeleton('ουτοπία')).not.toBe(skeleton('outopia'));
  });
});
