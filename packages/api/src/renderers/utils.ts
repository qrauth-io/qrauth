export function esc(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

/**
 * Returns the URL when its parsed protocol is http: or https:, otherwise null.
 * Link targets on the verify page go through this so only web URLs are ever
 * emitted as an href.
 */
export function safeHttpHref(url: string | null | undefined): string | null {
  if (!url) return null;
  try {
    const { protocol } = new URL(url);
    return protocol === 'http:' || protocol === 'https:' ? url : null;
  } catch {
    return null;
  }
}

/** Bare host for an org domain stored either as a hostname or as a URL. */
export function displayHost(domain: string | null | undefined): string | null {
  if (!domain) return null;
  const trimmed = domain.trim();
  try {
    return new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`).hostname;
  } catch {
    return null;
  }
}
