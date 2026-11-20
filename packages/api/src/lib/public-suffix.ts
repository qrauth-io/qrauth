import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { domainToASCII, fileURLToPath } from 'node:url';

/**
 * Public Suffix List lookup (https://publicsuffix.org/list/), from the
 * bundled, unmodified list in data/third-party/psl (MPL-2.0; ADR-0007).
 * Both the ICANN and the PRIVATE sections are used.
 *
 * Algorithm (https://github.com/publicsuffix/list/wiki/Format): the
 * matching rule with the most labels wins, an exception rule (`!`) wins over
 * any other and removes its leftmost label, `*` matches any one label, and
 * a host no rule matches has its last label as the suffix.
 */

export const PSL_SHA256 = '617d1b276660e5a01209d7b58159450e400cf636634a7a9c2cfd50a1c6675d01';

export const PSL_FILE = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'data', 'third-party', 'psl', 'public_suffix_list.dat');

interface Rules {
  normal: Set<string>;
  wildcard: Set<string>; // rule `*.x.y` stored as `x.y`
  exception: Set<string>; // rule `!a.x.y` stored as `a.x.y`
}

/** Parses the list; rule labels are stored in ASCII (punycode) form. */
export function parsePublicSuffixList(text: string): Rules {
  const rules: Rules = { normal: new Set(), wildcard: new Set(), exception: new Set() };
  for (const raw of text.split('\n')) {
    const line = raw.trim().split(/\s/, 1)[0];
    if (!line || line.startsWith('//')) continue;
    if (line.startsWith('!')) rules.exception.add(toAscii(line.slice(1)));
    else if (line.startsWith('*.')) rules.wildcard.add(toAscii(line.slice(2)));
    else rules.normal.add(toAscii(line));
  }
  return rules;
}

function toAscii(rule: string): string {
  return (domainToASCII(rule) || rule).toLowerCase();
}

let rules: Rules | null = null;

function loaded(): Rules {
  rules ??= parsePublicSuffixList(readFileSync(PSL_FILE, 'utf8'));
  return rules;
}

/** Number of labels of the public suffix of an ASCII host. */
function suffixLength(labels: string[], r: Rules): number {
  let best = 1; // default rule `*`
  for (let i = 0; i < labels.length; i++) {
    const candidate = labels.slice(i).join('.');
    const length = labels.length - i;
    if (r.exception.has(candidate)) return length - 1;
    if (r.normal.has(candidate)) best = Math.max(best, length);
    const parent = labels.slice(i + 1).join('.');
    if (i + 1 < labels.length && r.wildcard.has(parent)) best = Math.max(best, length);
  }
  return best;
}

export interface Registrable {
  /** Public suffix, e.g. `co.uk`, `github.io`. */
  suffix: string;
  /** Registrable domain (suffix plus one label), or null when the host is itself a suffix. */
  domain: string | null;
  /** The label in front of the suffix (the registered name), or null. */
  label: string | null;
}

/** Splits an ASCII (punycode) host into its public suffix and registrable domain. */
export function registrableDomain(asciiHost: string, r: Rules = loaded()): Registrable {
  const labels = asciiHost.toLowerCase().replace(/\.$/, '').split('.');
  const length = Math.min(suffixLength(labels, r), labels.length);
  const suffix = labels.slice(labels.length - length).join('.');
  if (labels.length <= length) return { suffix, domain: null, label: null };
  const label = labels[labels.length - length - 1];
  return { suffix, domain: `${label}.${suffix}`, label };
}
