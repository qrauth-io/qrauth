import { describe, it, expect } from 'vitest';
import { jsonForScript } from '../script-json.js';

/**
 * Audit 2026-10 FINDING-024: a value serialised into an inline <script> must
 * not be able to close the script element or open a comment.
 */
describe('jsonForScript', () => {
  it('escapes the characters that matter inside a script element', () => {
    const out = jsonForScript('</script><script>alert(1)</script><!-- & -->');

    expect(out).not.toContain('<');
    expect(out).not.toContain('>');
    expect(out).not.toContain('&');
  });

  it('still evaluates to the original value', () => {
    for (const value of ['</script>', "it's", 'line\u2028sep\u2029', null, true, ['a', '<b>'], { url: 'https://x/?a=1&b=<2>' }]) {
      // eslint-disable-next-line no-new-func
      expect(new Function(`return ${jsonForScript(value)};`)()).toEqual(value);
    }
  });

  it('escapes the line separators that end a JavaScript string', () => {
    expect(jsonForScript('a\u2028b\u2029c')).toBe('"a\\u2028b\\u2029c"');
  });
});
