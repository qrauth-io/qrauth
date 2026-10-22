/**
 * Serialise a value for use inside an inline `<script>` (audit 2026-10
 * FINDING-024). JSON alone is not enough there: the HTML parser ends the
 * script element at the first `</script>` wherever it appears, and treats
 * `<!--` specially, before any JavaScript is parsed. `<`, `>` and `&` are
 * written as unicode escapes, which mean the same to JavaScript and nothing
 * to HTML. The line and paragraph separators (U+2028, U+2029) are escaped
 * too: older engines treat them as line terminators inside a string literal.
 */
const LINE_SEPARATOR = String.fromCharCode(0x2028);
const PARAGRAPH_SEPARATOR = String.fromCharCode(0x2029);

const ESCAPES: Record<string, string> = {
  '<': '\\u003c',
  '>': '\\u003e',
  '&': '\\u0026',
  [LINE_SEPARATOR]: '\\u2028',
  [PARAGRAPH_SEPARATOR]: '\\u2029',
};

const NEEDS_ESCAPE = new RegExp(`[<>&${LINE_SEPARATOR}${PARAGRAPH_SEPARATOR}]`, 'g');

export function jsonForScript(value: unknown): string {
  return JSON.stringify(value ?? null).replace(NEEDS_ESCAPE, (char) => ESCAPES[char]);
}
