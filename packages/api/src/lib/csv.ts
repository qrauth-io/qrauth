/**
 * The one CSV writer for every export (scan analytics, audit log). Cells
 * that a spreadsheet would read as a formula (starting with = + - @, tab or
 * carriage return) are prefixed with an apostrophe, so an exported value
 * such as a QR label or a user agent cannot run as a formula when opened.
 */

/** Characters that make a spreadsheet treat a cell as a formula. */
const FORMULA_START = /^[=+\-@\t\r]/;
const NEEDS_QUOTES = /[",\r\n]/;

export type CsvValue = string | number | null | undefined;

/** One CSV cell: empty for null, formula starts neutralised, quoted when needed. */
export function csvCell(value: CsvValue): string {
  if (value === null || value === undefined) return '';
  let text = String(value);
  if (typeof value === 'string' && FORMULA_START.test(text)) text = `'${text}`;
  return NEEDS_QUOTES.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

/** One CSV record, CRLF-terminated (RFC 4180). */
export function csvLine(cells: ReadonlyArray<CsvValue>): string {
  return `${cells.map(csvCell).join(',')}\r\n`;
}

/**
 * UTF-8 byte order mark, for CSV files meant for spreadsheet apps: without it
 * Excel reads the file in the system's legacy encoding and mangles Greek and
 * other non-Latin text (bulk import results and the ZIP manifest).
 */
export const CSV_UTF8_BOM = '\uFEFF';
