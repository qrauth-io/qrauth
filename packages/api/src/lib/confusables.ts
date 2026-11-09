import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * UTS #39 confusable skeletons (https://www.unicode.org/reports/tr39/#Confusable_Detection)
 * from the bundled Unicode data file (data/third-party/unicode, Unicode
 * License v3). Read once, on first use; never fetched at runtime.
 *
 * skeleton(X): NFD, remove default-ignorable code points, replace each code
 * point with its prototype from confusables.txt, NFD again. Two strings are
 * confusable when their skeletons are equal.
 */

export const CONFUSABLES_VERSION = '17.0.0';
/** SHA-256 of the bundled confusables.txt (also in its README). */
export const CONFUSABLES_SHA256 = '091c7f82fc39ef208faf8f94d29c244de99254675e09de163160c810d13ef22a';

export const CONFUSABLES_FILE = join(
  dirname(fileURLToPath(import.meta.url)),
  '..',
  '..',
  'data',
  'third-party',
  'unicode',
  'confusables.txt',
);

/** Parses confusables.txt: `<source> ; <target sequence> ; MA # comment`. */
export function parseConfusables(text: string, expectedVersion = CONFUSABLES_VERSION): Map<number, string> {
  const version = /^# Version: (\S+)/m.exec(text)?.[1];
  if (version !== expectedVersion) {
    throw new Error(`confusables.txt is version ${version ?? 'unknown'}, expected ${expectedVersion}`);
  }
  const table = new Map<number, string>();
  for (const line of text.split('\n')) {
    const data = line.split('#', 1)[0].trim();
    if (!data) continue;
    const [source, target] = data.split(';').map((field) => field.trim());
    if (!source || !target) continue;
    table.set(parseInt(source, 16), String.fromCodePoint(...target.split(/\s+/).map((hex) => parseInt(hex, 16))));
  }
  return table;
}

let table: Map<number, string> | null = null;

function confusables(): Map<number, string> {
  table ??= parseConfusables(readFileSync(CONFUSABLES_FILE, 'utf8'));
  return table;
}

const DEFAULT_IGNORABLE = /\p{Default_Ignorable_Code_Point}/gu;

/** The UTS #39 skeleton of a string. */
export function skeleton(input: string): string {
  const map = confusables();
  let out = '';
  for (const ch of input.normalize('NFD').replace(DEFAULT_IGNORABLE, '')) {
    out += map.get(ch.codePointAt(0)!) ?? ch;
  }
  return out.normalize('NFD');
}
