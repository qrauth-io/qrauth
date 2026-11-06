import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { CONFUSABLES_FILE, CONFUSABLES_SHA256, CONFUSABLES_VERSION, skeleton } from '../lib/confusables.js';
import { PSL_FILE, PSL_SHA256, registrableDomain } from '../lib/public-suffix.js';
import { curatedBrands } from './lookalike.js';
import { phishingKeywords } from './lookalike-words.js';

/** Characters of a SHA-256 shown in the startup log. */
const CHECKSUM_PREFIX_LENGTH = 12;

export interface LookalikeDataSummary {
  confusables: { version: string | null; sha256: string; matchesPinned: boolean };
  psl: { version: string | null; sha256: string; matchesPinned: boolean };
  curated: { brands: number; domains: number };
  keywords: number;
}

/**
 * Loads the lookalike data (ADR-0007 D1, D3, D8, D11) and describes it: the
 * versions and checksums of the bundled confusables and Public Suffix List
 * files, and the sizes of the curated list and the keyword list. Run at
 * startup, so the data is read before the first request and its versions
 * are in the log.
 */
export function lookalikeDataSummary(): LookalikeDataSummary {
  const confusables = readFileSync(CONFUSABLES_FILE, 'utf8');
  const psl = readFileSync(PSL_FILE, 'utf8');
  const sha = (text: string) => createHash('sha256').update(text).digest('hex');
  // Use each file through its loader, so a broken file fails here.
  skeleton('a');
  registrableDomain('example.com');
  const brands = curatedBrands();
  return {
    confusables: {
      version: /^# Version: (\S+)/m.exec(confusables)?.[1] ?? null,
      sha256: sha(confusables),
      matchesPinned: sha(confusables) === CONFUSABLES_SHA256 && confusables.includes(`# Version: ${CONFUSABLES_VERSION}`),
    },
    psl: { version: /^\/\/ VERSION: (\S+)/m.exec(psl)?.[1] ?? null, sha256: sha(psl), matchesPinned: sha(psl) === PSL_SHA256 },
    curated: { brands: brands.length, domains: brands.reduce((n, b) => n + b.domains.length, 0) },
    keywords: phishingKeywords().credential.length + phishingKeywords().general.length,
  };
}

/** How long the startup preload took (milliseconds), and the protected set's size. */
export interface LookalikePreloadTiming {
  dataMs: number;
  referencesMs: number;
  references: number;
}

/** One line for the startup log. */
export function lookalikeDataLine(s: LookalikeDataSummary, timing?: LookalikePreloadTiming): string {
  const short = (hash: string) => hash.slice(0, CHECKSUM_PREFIX_LENGTH);
  const loaded = timing
    ? `; loaded in ${Math.round(timing.dataMs + timing.referencesMs)} ms (data ${Math.round(timing.dataMs)} ms, ` +
      `protected set of ${timing.references} domains ${Math.round(timing.referencesMs)} ms)`
    : '';
  return (
    `Lookalike data: confusables ${s.confusables.version} (sha256 ${short(s.confusables.sha256)}), ` +
    `PSL ${s.psl.version} (sha256 ${short(s.psl.sha256)}), ` +
    `curated list ${s.curated.brands} brands / ${s.curated.domains} domains, ${s.keywords} phishing keywords` +
    loaded
  );
}

/**
 * Reads the lookalike data and loads the protected set (ADR-0007 D11),
 * then logs one line with versions, checksums and load times. Started
 * after the server listens and not awaited: a request that needs the
 * protected set before it is loaded waits for the same load, as without
 * the preload. Failures are logged, never thrown.
 */
export async function preloadLookalikeData(
  loadReferences: () => Promise<number>,
  log: { info: (obj: object, msg: string) => void; error: (obj: object, msg: string) => void },
  now: () => number = () => performance.now(),
): Promise<void> {
  try {
    const start = now();
    const summary = lookalikeDataSummary();
    const dataDone = now();
    const references = await loadReferences();
    const timing = { dataMs: dataDone - start, referencesMs: now() - dataDone, references };
    const line = lookalikeDataLine(summary, timing);
    if (summary.confusables.matchesPinned && summary.psl.matchesPinned) {
      log.info({ event: 'lookalike.data_loaded', ...summary, ...timing }, line);
    } else {
      log.error({ event: 'lookalike.data_checksum_mismatch', ...summary, ...timing }, `${line}: does not match the pinned checksums`);
    }
  } catch (err) {
    log.error({ err, event: 'lookalike.data_load_failed' }, 'Lookalike data could not be loaded');
  }
}
