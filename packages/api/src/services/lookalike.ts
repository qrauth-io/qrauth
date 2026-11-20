import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { domainToUnicode, fileURLToPath } from 'node:url';
import { skeleton } from '../lib/confusables.js';
import { labelScripts } from '../lib/script-mix.js';
import { registrableDomain } from '../lib/public-suffix.js';

/**
 * Lookalike detection for QR destinations and links (ADR-0007), on top of
 * the edit-distance check in services/domain.ts.
 *
 * A host is normalised (punycode → Unicode per UTS #46 via node:url, NFKC,
 * lowercase) and then:
 *   - mixed script: a label below UTS #39 "Highly Restrictive" (Latin with
 *     Cyrillic or Greek in one label, for example) is a lookalike on its own;
 *   - confusable: the UTS #39 skeleton of the host, or of any of its parent
 *     domains, equals the skeleton of a protected domain (every parent
 *     a.b.c → a.b.c, b.c, so the registrable domain is always among them);
 *   - curated brands also compare the registered name (registrableLabel,
 *     from the Public Suffix List).
 * A protected domain itself, its subdomains, and the other official domains
 * of the same brand are exempt.
 */

export interface NormalizedHost {
  /** ASCII form (punycode), as URL.hostname gives it, without a trailing dot. */
  ascii: string;
  /**
   * Unicode form: UTS #46 to Unicode (which already applies the IDNA case
   * mapping), then NFKC. Not lowercased again: lowercasing would turn
   * Cherokee capitals, which IDNA keeps and confusables.txt maps to Latin,
   * into Cherokee small letters, which it maps to small capitals.
   */
  unicode: string;
}

export function normalizeHost(hostname: string): NormalizedHost {
  const ascii = hostname.toLowerCase().replace(/\.$/, '');
  const unicode = (domainToUnicode(ascii) || ascii).normalize('NFKC');
  return { ascii, unicode };
}

/** Hostname of a URL, normalised; null when it does not parse. */
export function normalizeUrlHost(url: string): NormalizedHost | null {
  try {
    return normalizeHost(new URL(url).hostname);
  } catch {
    return null;
  }
}

/**
 * Skeleton for comparisons, of the IDNA output as is, lowercased afterwards
 * (`0` → `O` → `o`, Cherokee `Ꭺ` → `A` → `a`).
 */
export function hostSkeleton(unicodeHost: string): string {
  return skeleton(unicodeHost).toLowerCase();
}

/** The host and each parent domain with at least two labels: a.b.c → [a.b.c, b.c]. */
export function parentDomains(host: string): string[] {
  const labels = host.split('.');
  const out: string[] = [];
  for (let i = 0; i <= labels.length - 2; i++) out.push(labels.slice(i).join('.'));
  return out;
}

/** True when host is domain or one of its subdomains (ASCII forms). */
export function isSameOrSubdomain(host: string, domain: string): boolean {
  return host === domain || host.endsWith(`.${domain}`);
}

/**
 * The registered name of a host, in Unicode: the label in front of its
 * public suffix (Public Suffix List, ICANN and PRIVATE sections), e.g.
 * `google` for www.google.com.hk, `δπθ` for ουτοπία.δπθ.gr, `paypa1` for
 * paypa1.github.io. A host that is itself a public suffix (`gov.gr`) gives
 * its leftmost label.
 */
export function registrableLabel(asciiHost: string): string {
  const host = asciiHost.toLowerCase().replace(/\.$/, '');
  return unicodeLabel(registrableDomain(host).label ?? host.split('.')[0]);
}

/** The string without combining marks (NFD, marks removed, NFC): äpple → apple. */
export function stripMarks(value: string): string {
  return value.normalize('NFD').replace(/\p{M}/gu, '').normalize('NFC');
}

/** One ASCII (punycode) label in Unicode, NFKC. */
export function unicodeLabel(asciiLabel: string): string {
  return (domainToUnicode(asciiLabel) || asciiLabel).normalize('NFKC');
}

export interface MixedScriptLabel {
  label: string;
  scripts: string[];
}

/** The first label of a host that is not Highly Restrictive, or null. */
export function mixedScriptLabel(unicodeHost: string): MixedScriptLabel | null {
  for (const label of unicodeHost.split('.')) {
    const mix = labelScripts(label);
    if (!mix.highlyRestrictive) return { label, scripts: mix.scripts };
  }
  return null;
}

// ---------------------------------------------------------------------------
// Curated protected list (data/protected-domains.txt)
// ---------------------------------------------------------------------------

export interface CuratedBrand {
  name: string;
  /**
   * `[strict]` after the name: the brand's exact name on a TLD that is not
   * listed for it is a lookalike too (aade.com, paypal.xyz). For banks,
   * public services, payment and identity providers with distinctive names.
   */
  strict: boolean;
  /**
   * `[strict wordlike]`: a strict brand whose name is an ordinary word
   * (visa, kraken, stripe). Still strict on other TLDs (visa.xyz); as a
   * hyphen token it counts only next to a phishing keyword (visa-login.com,
   * not visa-team.com), ADR-0007 D11.
   */
  wordlike: boolean;
  /** Official domains, lowercase ASCII. */
  domains: string[];
  /**
   * Multi-tenant domains among `domains` (marked `@` in the file): customers
   * choose subdomains there (contoso.sharepoint.com), so only the apex and
   * hosts listed explicitly are the brand's own; a tenant label is checked
   * like a registered name.
   */
  multiTenant: string[];
}

const CURATED_FILE = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'data', 'protected-domains.txt');
const DOMAIN_RE = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$/;

/** Parses `Name [strict]: domain @tenant-domain …` lines; throws on a malformed entry. */
export function parseCuratedList(text: string): CuratedBrand[] {
  const brands: CuratedBrand[] = [];
  text.split('\n').forEach((raw, index) => {
    const line = raw.trim();
    if (!line || line.startsWith('#')) return;
    const sep = line.lastIndexOf(': ');
    const head = sep > 0 ? line.slice(0, sep).trim() : '';
    const flag = /^(.*?)\s*\[([\w ]+)\]$/.exec(head);
    const flags = flag ? flag[2].trim().split(/\s+/) : [];
    const unknown = flags.find((f) => f !== 'strict' && f !== 'wordlike');
    if (unknown) throw new Error(`protected-domains.txt line ${index + 1}: unknown flag [${unknown}]`);
    if (flags.includes('wordlike') && !flags.includes('strict')) {
      throw new Error(`protected-domains.txt line ${index + 1}: [wordlike] applies to strict brands only ([strict wordlike])`);
    }
    const name = flag ? flag[1] : head;
    const tokens = sep > 0 ? line.slice(sep + 2).trim().split(/\s+/) : [];
    const domains = tokens.map((t) => t.replace(/^@/, ''));
    const bad = domains.find((d) => !DOMAIN_RE.test(d));
    if (!name || domains.length === 0 || bad) {
      throw new Error(`protected-domains.txt line ${index + 1}: expected "Name: domain …"${bad ? ` (bad domain ${bad})` : ''}`);
    }
    brands.push({ name, strict: flags.includes('strict'), wordlike: flags.includes('wordlike'), domains, multiTenant: tokens.filter((t) => t.startsWith('@')).map((t) => t.slice(1)) });
  });
  return brands;
}

/**
 * True when `host` is covered by protected `domain`: the domain itself or a
 * subdomain, or, for a multi-tenant domain, only the domain itself.
 */
export function coveredBy(host: string, domain: string, multiTenant: boolean): boolean {
  return multiTenant ? host === domain : isSameOrSubdomain(host, domain);
}

let curated: CuratedBrand[] | null = null;

export function curatedBrands(): CuratedBrand[] {
  curated ??= parseCuratedList(readFileSync(CURATED_FILE, 'utf8'));
  return curated;
}

// ---------------------------------------------------------------------------
// Wording (verify page, JSON domain_warning, link list entries)
// ---------------------------------------------------------------------------

export interface LookalikeWarning {
  domain: string;
  verifiedOrgName: string;
  reason: string;
  scripts?: string[];
  /** Only curated brands are named; a verified organization's name is its own choice and is not shown. */
  source?: 'curated' | 'verified';
}

function namedTarget(w: LookalikeWarning): string {
  return w.source === 'curated' && w.verifiedOrgName ? `${w.domain} (${w.verifiedOrgName})` : w.domain;
}

function scriptList(scripts: string[] | undefined): string {
  const names = (scripts ?? []).map((s) => s.replace(/_/g, ' '));
  if (names.length >= 2) return `${names.slice(0, -1).join(', ')} and ${names[names.length - 1]}`;
  return 'different';
}

/** A warning at or above this similarity makes the destination suspicious. */
export const SUSPICIOUS_SIMILARITY = 80;

/**
 * Warning order everywhere a warning is shown or recorded (ADR-0007 D11):
 * suspicious brand and domain matches ("looks like paypal.com") first, then
 * mixed-script warnings, then matches below the suspicious threshold;
 * strongest first within each group. The first warning of a suspicious
 * result is therefore the reason it is suspicious, and incidents record it.
 */
export function compareLookalikeWarnings(a: LookalikeWarning & { similarity: number }, b: LookalikeWarning & { similarity: number }): number {
  const group = (w: LookalikeWarning & { similarity: number }) => {
    if (w.reason === 'mixed_script') return 1;
    return w.similarity >= SUSPICIOUS_SIMILARITY ? 0 : 2;
  };
  return group(a) - group(b) || b.similarity - a.similarity;
}

/** One sentence for the verify page and the JSON `domain_warning.message`. */
export function lookalikeMessage(w: LookalikeWarning): string {
  if (w.reason === 'mixed_script') {
    return `This address mixes ${scriptList(w.scripts)} letters in one name, a common way to imitate another site. Proceed with caution.`;
  }
  return `This address looks like ${namedTarget(w)}, but it is a different site. Proceed with caution.`;
}

/** Short note under a link of a smart link or link list. */
export function lookalikeNote(w: LookalikeWarning): string {
  if (w.reason === 'mixed_script') return `Mixes ${scriptList(w.scripts)} letters`;
  return `Looks like ${namedTarget(w)}`;
}
