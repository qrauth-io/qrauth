import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { registrableDomain } from '../lib/public-suffix.js';
import { hostSkeleton, stripMarks, unicodeLabel } from './lookalike.js';

/**
 * Brand-in-host rules of the lookalike check (ADR-0007 D11):
 * - a protected domain's name used as labels in front of another
 *   registrable domain (eurobank.gr.secure-login.com), or as hyphen tokens
 *   (paypal-com-login.net; for most names only next to a keyword);
 * - a strict brand's name as a hyphen token of a registered name
 *   (paypal-secure.com);
 * - a strict brand's name run together with a phishing keyword
 *   (paypalsecure.com), keywords from data/phishing-keywords.txt in two
 *   tiers: credential words match inside a longer word, general words only
 *   as a whole token.
 * Everything is compared on UTS #39 skeletons (and without combining marks).
 */

export const KEYWORDS_FILE = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'data', 'phishing-keywords.txt');

/** Hyphen tokens of brand names shorter than this match only next to a keyword (db-tools.io passes). */
export const BRAND_TOKEN_MIN_LENGTH = 4;
/** The keyword rule (paypalsecure.com) needs a brand name at least this long. */
export const BRAND_KEYWORD_MIN_LENGTH = 5;
const KEYWORD_MIN_LENGTH = 3;
/** Credential keywords shorter than this (kyc, 2fa) match a whole token only, never inside a longer word. */
export const CREDENTIAL_INSIDE_MIN_LENGTH = 4;

export type KeywordTier = 'credential' | 'general';

export interface PhishingKeywords {
  /** Match anywhere in a token (paypallogin). */
  credential: string[];
  /** Match a whole token only (paypal-secure; not accountants). */
  general: string[];
}

const TIER_HEADER = /^\[(credential|general)\]$/u;

/**
 * Parses the keyword file: `[credential]` and `[general]` headers, then one
 * lowercase word per line, `#` comments; throws on a malformed entry.
 */
export function parseKeywords(text: string): PhishingKeywords {
  const words: PhishingKeywords = { credential: [], general: [] };
  let tier: KeywordTier | null = null;
  text.split('\n').forEach((raw, index) => {
    const word = raw.trim();
    if (!word || word.startsWith('#')) return;
    const header = TIER_HEADER.exec(word);
    if (header) {
      tier = header[1] as KeywordTier;
      return;
    }
    if (!tier) throw new Error(`phishing-keywords.txt line ${index + 1}: a word before the [credential] or [general] header`);
    if (word !== word.toLowerCase() || /[\s.\-[\]]/u.test(word) || [...word].length < KEYWORD_MIN_LENGTH) {
      throw new Error(`phishing-keywords.txt line ${index + 1}: expected one lowercase word of ${KEYWORD_MIN_LENGTH}+ letters`);
    }
    if (words.credential.includes(word) || words.general.includes(word)) {
      throw new Error(`phishing-keywords.txt line ${index + 1}: duplicate "${word}"`);
    }
    words[tier].push(word);
  });
  return words;
}

let keywordForms: PhishingKeywords | null = null;

/** Keywords by tier, in keywordForm (read once). */
export function phishingKeywords(): PhishingKeywords {
  if (!keywordForms) {
    const words = parseKeywords(readFileSync(KEYWORDS_FILE, 'utf8'));
    const forms = (list: string[]) => [...new Set(list.map((w) => keywordForm(tokenSkeleton(w))))];
    keywordForms = { credential: forms(words.credential), general: forms(words.general) };
  }
  return keywordForms;
}

/** Digits read as letters in keywords (s1gnin, pa55word, v3rify); the skeleton already maps 1 → l and 0 → o. */
const PLAIN_LETTERS: Record<string, string> = { '0': 'o', '1': 'l', '3': 'e', '5': 's', i: 'l' };

/**
 * The form keywords are compared in: a token skeleton with the digits
 * phishing uses for letters replaced (0 → o, 3 → e, 5 → s), and 1, i and l
 * merged into one letter, since 1 stands for either (s1gnin, l0g1n).
 */
export function keywordForm(skeleton: string): string {
  return skeleton.replace(/[0135i]/gu, (c) => PLAIN_LETTERS[c]!);
}

/** The skeleton of one token, without combining marks (päypal → paypal). */
export function tokenSkeleton(token: string): string {
  return hostSkeleton(stripMarks(token.normalize('NFKC').toLowerCase()));
}

/** Whether a token skeleton contains a credential keyword (paypallogin, mysignin, s1gnin). */
export function hasCredentialKeyword(skeleton: string): boolean {
  const form = keywordForm(skeleton);
  return phishingKeywords().credential.some((k) => (k.length < CREDENTIAL_INSIDE_MIN_LENGTH ? form === k : form.includes(k)));
}

/** Whether a token skeleton is a keyword: contains a credential keyword, or is a general one (secure; not accountants). */
export function hasKeyword(skeleton: string): boolean {
  return hasCredentialKeyword(skeleton) || phishingKeywords().general.includes(keywordForm(skeleton));
}

/**
 * The name tokens of a protected domain: its registrable domain split on
 * dots and hyphens (eurobank.gr → eurobank, gr; deutsche-bank.de →
 * deutsche, bank, de). A domain that is itself a public suffix (gov.gr)
 * gives its own labels.
 */
export function protectedNameTokens(asciiDomain: string): string[] {
  return protectedNameLabels(asciiDomain).flatMap((l) => l.split('-')).filter(Boolean);
}

/** The labels of a protected domain's registrable domain, as skeletons (deutsche-bank.de → deutsche-bank, de). */
export function protectedNameLabels(asciiDomain: string): string[] {
  const name = registrableDomain(asciiDomain).domain ?? asciiDomain;
  return name.split('.').map((l) => tokenSkeleton(unicodeLabel(l)));
}

export interface HostTokens {
  /** The host's registrable domain (ASCII), or null when the host is a public suffix. */
  registrable: string | null;
  /** Skeletons of the labels left of the public suffix, in order. */
  labels: string[];
  /** Skeletons of the hyphen tokens of those labels, in order. */
  tokens: string[];
}

/** Labels and tokens left of the public suffix (www.paypal.com.account-check.net → www, paypal, com, account, check). */
export function hostTokens(asciiHost: string): HostTokens {
  const { suffix, domain } = registrableDomain(asciiHost);
  const left = asciiHost.slice(0, Math.max(0, asciiHost.length - suffix.length - 1));
  const unicodeLabels = left ? left.split('.').map(unicodeLabel) : [];
  return {
    registrable: domain,
    labels: unicodeLabels.map(tokenSkeleton),
    tokens: unicodeLabels.flatMap((l) => l.split('-')).filter(Boolean).map(tokenSkeleton),
  };
}

/** Where `name` starts as a contiguous run in `tokens`, or -1. */
export function findRun(tokens: string[], name: string[]): number {
  if (name.length === 0 || name.length > tokens.length) return -1;
  outer: for (let i = 0; i + name.length <= tokens.length; i++) {
    for (let j = 0; j < name.length; j++) if (tokens[i + j] !== name[j]) continue outer;
    return i;
  }
  return -1;
}

/** Whether `name` occurs as a contiguous run in `tokens`. */
export function containsRun(tokens: string[], name: string[]): boolean {
  return findRun(tokens, name) >= 0;
}

/**
 * A protected domain's name inside a host, left of its public suffix:
 * - `dotted`: its labels as labels (eurobank.gr.secure-login.com);
 * - `hyphen`: its tokens as a run of hyphen tokens (paypal-com-login.net),
 *   or run together into one token (paypalcom-login.net), with `keyword`
 *   telling whether another token holds a phishing keyword.
 */
export type EmbeddedName = { form: 'dotted' } | { form: 'hyphen'; keyword: boolean };

export function embeddedName(host: HostTokens, nameLabels: string[], nameTokens: string[]): EmbeddedName | null {
  if (containsRun(host.labels, nameLabels)) return { form: 'dotted' };
  let start = findRun(host.tokens, nameTokens);
  let length = nameTokens.length;
  if (start < 0) {
    start = host.tokens.indexOf(nameTokens.join(''));
    length = 1;
  }
  if (start < 0) return null;
  const keyword = host.tokens.some((t, i) => (i < start || i >= start + length) && hasKeyword(t));
  return { form: 'hyphen', keyword };
}

/** Whether a token skeleton is exactly a keyword of either tier. */
export function isKeyword(skeleton: string): boolean {
  const { credential, general } = phishingKeywords();
  const form = keywordForm(skeleton);
  return credential.includes(form) || general.includes(form);
}

/** Whether a token skeleton is exactly a credential keyword (wallet, l0gin). */
export function isCredentialKeyword(skeleton: string): boolean {
  return phishingKeywords().credential.includes(keywordForm(skeleton));
}

/**
 * A brand name run together with a phishing keyword in one hyphen token:
 * - the brand at the start or end of the token, and the rest exactly a
 *   keyword of either tier (paypalsecure, securepaypal);
 * - or the brand anywhere, with a credential keyword before or after it
 *   (mypaypallogin).
 * A wordlike brand is never matched inside a longer word: only at the start
 * or end of the token with the rest exactly a credential keyword
 * (stripewallet, stripel0gin; not pinstripewallet, stripedwallets or
 * fireservicesupport).
 */
export function brandWithKeyword(tokenSkeletons: string[], brandSkeleton: string, wordlike = false): boolean {
  const restIsKeyword = wordlike ? isCredentialKeyword : isKeyword;
  return tokenSkeletons.some((t) => {
    if (t === brandSkeleton) return false;
    if (t.startsWith(brandSkeleton) && restIsKeyword(t.slice(brandSkeleton.length))) return true;
    if (t.endsWith(brandSkeleton) && restIsKeyword(t.slice(0, -brandSkeleton.length))) return true;
    if (wordlike) return false;
    for (let at = t.indexOf(brandSkeleton); at >= 0; at = t.indexOf(brandSkeleton, at + 1)) {
      if (hasCredentialKeyword(t.slice(0, at)) || hasCredentialKeyword(t.slice(at + brandSkeleton.length))) return true;
    }
    return false;
  });
}
