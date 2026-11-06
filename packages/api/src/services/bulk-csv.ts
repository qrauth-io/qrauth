import { parse } from 'csv-parse/sync';
import {
  BULK_IMPORT_COLUMNS,
  BULK_IMPORT_MAX_BYTES,
  BULK_IMPORT_MAX_ROWS,
  type BulkImportColumn,
  type BulkImportDelimiter,
} from '@qrauth/shared';

/**
 * Reading a bulk import file (ADR-0008 D9): UTF-8 with or without a BOM,
 * `,` or `;` as the field delimiter (detected from the header row), quoted
 * fields (which may contain the delimiter, quotes and line breaks). The
 * route caps the body at BULK_IMPORT_MAX_BYTES before this runs.
 */

const UTF8_BOM = Buffer.from([0xef, 0xbb, 0xbf]);
/** One CSV record: a long label is 200 characters, so 64 KiB is far beyond any valid row. */
const MAX_RECORD_CHARS = 64 * 1024;

export type BulkCsvErrorCode =
  | 'file-empty'
  | 'file-too-large'
  | 'file-not-text'
  | 'file-not-utf8'
  | 'csv-malformed'
  | 'header-missing-url'
  | 'header-unknown-columns'
  | 'header-duplicate-columns'
  | 'too-many-rows'
  | 'no-rows';

/** The whole file was refused (422 at the route); nothing was validated. */
export class BulkCsvError extends Error {
  constructor(
    readonly code: BulkCsvErrorCode,
    message: string,
  ) {
    super(message);
    this.name = 'BulkCsvError';
  }
}

export interface ParsedCsvRow {
  /** Row number in the file: the header is row 1. */
  row: number;
  /** Trimmed cell per known column; a missing cell is ''. */
  cells: Record<BulkImportColumn, string>;
  /** The row had a different number of fields than the header. */
  fieldCountMismatch: { expected: number; actual: number } | null;
}

export interface ParsedCsv {
  delimiter: BulkImportDelimiter;
  columns: BulkImportColumn[];
  rows: ParsedCsvRow[];
}

const NOT_UTF8_MESSAGE =
  'The file is not UTF-8 text. In Excel, save it with "CSV UTF-8 (Comma delimited)"; the plain "CSV" option saves Greek and other non-Latin text in a legacy encoding.';

/** Text of the file: strict UTF-8, BOM removed; binary content is refused. */
export function decodeCsvText(bytes: Buffer): string {
  if (bytes.length > BULK_IMPORT_MAX_BYTES) {
    throw new BulkCsvError('file-too-large', `The file is larger than ${BULK_IMPORT_MAX_BYTES / (1024 * 1024)} MB.`);
  }
  const body = bytes.subarray(0, 3).equals(UTF8_BOM) ? bytes.subarray(3) : bytes;
  // A NUL byte never appears in CSV text; it marks a spreadsheet, image or archive.
  if (body.includes(0)) throw new BulkCsvError('file-not-text', 'The file is not a CSV text file.');
  let text: string;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(body);
  } catch {
    throw new BulkCsvError('file-not-utf8', NOT_UTF8_MESSAGE);
  }
  if (text.trim().length === 0) throw new BulkCsvError('file-empty', 'The file is empty.');
  return text;
}

/**
 * The delimiter of the header row: whichever of `,` and `;` occurs more
 * often outside quotes before the first line break. A header with neither
 * is a single column (`,`).
 */
export function detectDelimiter(text: string): BulkImportDelimiter {
  let commas = 0;
  let semicolons = 0;
  let quoted = false;
  for (const ch of text) {
    if (ch === '"') quoted = !quoted;
    else if (!quoted && (ch === '\n' || ch === '\r')) break;
    else if (!quoted && ch === ',') commas++;
    else if (!quoted && ch === ';') semicolons++;
  }
  return semicolons > commas ? ';' : ',';
}

const KNOWN = new Map(BULK_IMPORT_COLUMNS.map((c) => [c.toLowerCase(), c]));

function readHeader(header: string[]): BulkImportColumn[] {
  const names = header.map((h) => h.trim());
  const unknown = names.filter((n) => !KNOWN.has(n.toLowerCase()));
  if (unknown.length > 0) {
    const listed = unknown.map((n) => (n === '' ? '(empty)' : `"${n}"`)).join(', ');
    throw new BulkCsvError(
      'header-unknown-columns',
      `Unknown column${unknown.length > 1 ? 's' : ''}: ${listed}. Allowed columns: ${BULK_IMPORT_COLUMNS.join(', ')}.`,
    );
  }
  const columns = names.map((n) => KNOWN.get(n.toLowerCase())!);
  const duplicates = columns.filter((c, i) => columns.indexOf(c) !== i);
  if (duplicates.length > 0) {
    throw new BulkCsvError('header-duplicate-columns', `Column listed more than once: ${[...new Set(duplicates)].join(', ')}.`);
  }
  if (!columns.includes('url')) throw new BulkCsvError('header-missing-url', 'The header row needs a "url" column.');
  return columns;
}

function emptyCells(): Record<BulkImportColumn, string> {
  return Object.fromEntries(BULK_IMPORT_COLUMNS.map((c) => [c, ''])) as Record<BulkImportColumn, string>;
}

function parseRecords(text: string, delimiter: BulkImportDelimiter): string[][] {
  try {
    return parse(text, {
      delimiter,
      relax_column_count: true,
      // A quote inside an unquoted cell (=HYPERLINK("…") typed by hand) is
      // kept as text; an unclosed quoted cell is still an error.
      relax_quotes: true,
      // Empty lines stay records (skipped below) so row numbers match a
      // spreadsheet's. The whole file is at most 1 MB, so it is read in full.
      skip_empty_lines: false,
      max_record_size: MAX_RECORD_CHARS,
    }) as string[][];
  } catch (err) {
    const line = (err as { lines?: number }).lines;
    const reason = err instanceof Error ? err.message.replace(/^Invalid [^:]*: /, '') : 'unreadable';
    throw new BulkCsvError('csv-malformed', `The file is not valid CSV${line ? ` (near line ${line})` : ''}: ${reason}`);
  }
}

/** Parse an import file. Throws BulkCsvError when the file as a whole is refused. */
export function parseImportCsv(bytes: Buffer): ParsedCsv {
  const text = decodeCsvText(bytes);
  const delimiter = detectDelimiter(text);
  const records = parseRecords(text, delimiter);
  const [header, ...data] = records;
  if (!header) throw new BulkCsvError('file-empty', 'The file is empty.');
  const columns = readHeader(header);

  // Empty lines and rows whose every cell is blank (a spreadsheet's
  // trailing ;;;) are not data, but keep their row number.
  const rows: ParsedCsvRow[] = [];
  data.forEach((fields, i) => {
    if (fields.every((f) => f.trim() === '')) return;
    const cells = emptyCells();
    columns.forEach((col, j) => {
      cells[col] = (fields[j] ?? '').trim();
    });
    rows.push({
      row: i + 2,
      cells,
      fieldCountMismatch: fields.length === columns.length ? null : { expected: columns.length, actual: fields.length },
    });
  });

  if (rows.length > BULK_IMPORT_MAX_ROWS) {
    throw new BulkCsvError(
      'too-many-rows',
      `The file has more than ${BULK_IMPORT_MAX_ROWS.toLocaleString('en')} data rows; split it into files of at most ${BULK_IMPORT_MAX_ROWS.toLocaleString('en')}.`,
    );
  }
  if (rows.length === 0) throw new BulkCsvError('no-rows', 'The file has a header row but no data rows.');
  return { delimiter, columns, rows };
}
