/**
 * Parse an application/x-www-form-urlencoded body.
 *
 * A key sent more than once becomes an array, as the query string parser
 * does, so a handler can tell "sent twice" from "sent once" instead of
 * silently taking the last value. The result has no prototype: a body cannot
 * introduce `__proto__` or `constructor` as anything but plain keys.
 */
export function parseFormBody(body: string): Record<string, string | string[]> {
  const parsed: Record<string, string | string[]> = Object.create(null);
  for (const [key, value] of new URLSearchParams(body)) {
    const existing = parsed[key];
    if (existing === undefined) {
      parsed[key] = value;
    } else {
      parsed[key] = Array.isArray(existing) ? [...existing, value] : [existing, value];
    }
  }
  return parsed;
}
