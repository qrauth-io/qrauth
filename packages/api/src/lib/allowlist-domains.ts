import { domainToUnicode } from 'node:url';
import {
  contentLinkUrls,
  destinationHostRefusal,
  isLinkedContentType,
  type AllowlistEntry,
  type AllowlistEntryInput,
  type AllowlistEntryView,
  type AllowlistNormalisation,
} from '@qrauth/shared';

import { registrableDomain } from './public-suffix.js';

/**
 * Destination allowlist domains (ADR-0008 D8): normalising submitted
 * entries to registrable domains with the Public Suffix List, and matching
 * destination hosts against them. Hosts and entries are compared in ASCII
 * (punycode) form, which is how WHATWG URL parsing returns a host, so an
 * internationalised entry matches only the exact same name.
 */

function unicodeOf(asciiDomain: string): string {
  return domainToUnicode(asciiDomain) || asciiDomain;
}

function view(entry: AllowlistEntry): AllowlistEntryView {
  return { ...entry, unicode: unicodeOf(entry.domain) };
}

function hostOfInput(raw: string): string | null {
  try {
    const url = new URL(raw.includes('://') ? raw : `https://${raw}`);
    if (url.protocol !== 'https:' && url.protocol !== 'http:') return null;
    return url.hostname.replace(/\.$/, '') || null;
  } catch {
    return null;
  }
}

/** One submitted entry, reduced to its registrable domain, or why it cannot be. */
export function normaliseAllowlistEntry(input: Required<AllowlistEntryInput>): AllowlistNormalisation {
  const raw = input.domain.trim();
  const wildcard = raw.startsWith('*.');
  const candidate = wildcard ? raw.slice(2) : raw;
  const host = hostOfInput(candidate);
  if (!host) return { input: raw, ok: false, message: `“${raw}” is not a domain name.` };

  const hostRefusal = destinationHostRefusal(host);
  if (hostRefusal) return { input: raw, ok: false, message: `“${raw}”: ${hostRefusal}.` };

  const { suffix, domain } = registrableDomain(host);
  if (!domain) {
    return {
      input: raw,
      ok: false,
      message: `“${unicodeOf(suffix)}” is a public suffix: anyone can register names under it. Enter your own domain, such as example.${unicodeOf(suffix)}.`,
    };
  }

  const notes: string[] = [];
  if (candidate.includes('/') || candidate.includes('?') || candidate.includes('#')) notes.push('Only the domain is kept.');
  if (host !== domain) notes.push(`Reduced to the registrable domain ${unicodeOf(domain)}.`);
  if (wildcard) notes.push('Subdomains are covered by “Include subdomains”, not a wildcard.');
  return {
    input: raw,
    ok: true,
    entry: view({ domain, includeSubdomains: input.includeSubdomains }),
    note: notes.length > 0 ? notes.join(' ') : null,
  };
}

/**
 * Every submitted entry's outcome, and the allowlist as it would be stored:
 * valid entries only, a domain listed twice merged (subdomains included if
 * either entry includes them), sorted by domain.
 */
export function normaliseAllowlist(inputs: ReadonlyArray<Required<AllowlistEntryInput>>): {
  results: AllowlistNormalisation[];
  allowlist: AllowlistEntryView[];
} {
  const merged = new Map<string, AllowlistEntry>();
  const results = inputs.map((input): AllowlistNormalisation => {
    const result = normaliseAllowlistEntry(input);
    if (!result.ok) return result;
    const seen = merged.get(result.entry.domain);
    merged.set(result.entry.domain, {
      domain: result.entry.domain,
      includeSubdomains: result.entry.includeSubdomains || (seen?.includeSubdomains ?? false),
    });
    if (!seen) return result;
    const duplicate = 'Listed more than once; merged into one entry.';
    return { ...result, note: result.note ? `${result.note} ${duplicate}` : duplicate };
  });
  const allowlist = [...merged.values()].sort((a, b) => a.domain.localeCompare(b.domain)).map(view);
  return { results, allowlist };
}

/** An ASCII host is the entry's domain, or (with includeSubdomains) a subdomain of it. */
export function hostAllowed(host: string, allowlist: readonly AllowlistEntry[]): boolean {
  const h = host.toLowerCase().replace(/\.$/, '');
  return allowlist.some((e) => h === e.domain || (e.includeSubdomains && h.endsWith(`.${e.domain}`)));
}

/** The URLs whose host is not allowed; a URL that does not parse is never allowed. */
export function urlsOutside(urls: readonly string[], allowlist: readonly AllowlistEntry[]): string[] {
  return urls.filter((u) => {
    try {
      return !hostAllowed(new URL(u).hostname, allowlist);
    } catch {
      return true;
    }
  });
}

/**
 * The outbound destinations of a code the allowlist governs: the URL of a
 * URL code, the links of a smart link or link list code, none otherwise
 * (other types point at their own hosted page).
 */
export function policyDestinations(code: { contentType: string | null; destinationUrl: string; content: unknown }): string[] {
  const contentType = code.contentType || 'url';
  if (contentType === 'url') return [code.destinationUrl];
  return isLinkedContentType(contentType) ? contentLinkUrls(contentType, code.content) : [];
}

export function allowlistView(allowlist: readonly AllowlistEntry[]): AllowlistEntryView[] {
  return allowlist.map(view);
}
