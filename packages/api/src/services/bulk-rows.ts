import {
  BULK_IMPORT_DEFAULT_TIMEZONE,
  BULK_IMPORT_MAX_TAGS_PER_ROW,
  endOfDayInTimeZone,
  FOLDER_NAME_MAX,
  TAG_NAME_MAX,
  bulkCreateQRCodeItemSchema,
  tagSeparatorFor,
  type BulkDryRunRow,
  type BulkDryRunTotals,
  type BulkImportDelimiter,
  type BulkImportResult,
  type BulkRowStatus,
} from '@qrauth/shared';

import type { ParsedCsvRow } from './bulk-csv.js';

/**
 * Bulk import rows (ADR-0008 D9): the per-row rules that need no database
 * or network (the single-create schema, expiry dates, folder and tag
 * names), and how a row is shown in a dry run. services/bulk-import.ts adds
 * the organization's checks.
 */

export interface BulkRowDraft {
  row: number;
  url: string;
  label: string | null;
  folder: string | null;
  tags: string[];
  expiresAt: string | null;
  /** The cell as written when it was a date only (YYYY-MM-DD), kept for display. */
  expiresDate?: string | null;
  scanMode: 'FLASH' | 'PAGE' | null;
}

/** bulk_jobs.input of an import. */
export interface ImportJobInput {
  drafts: BulkRowDraft[];
  /** Rows the dry run refused, listed in the results as skipped. */
  refused: Array<{ row: number; url: string; error: string }>;
}

/** One entry of bulk_jobs.results. */
export interface StoredImportResult extends BulkImportResult {
  url: string;
  label: string | null;
}

export interface RowIssue {
  severity: 'error' | 'warning';
  code: string;
  message: string;
}

export interface ValidatedRow {
  draft: BulkRowDraft;
  issues: RowIssue[];
  /** Web Risk could not answer: the job issues the code and re-checks it right away (as single create). */
  webRiskUnavailable: boolean;
}

const DATE_ONLY = /^\d{4}-\d{2}-\d{2}$/;

/**
 * An `expiresAt` cell as an ISO 8601 UTC datetime. A date alone means
 * 23:59:59 of that day in `timeZone` (the uploader's, default UTC); a
 * datetime may carry an offset. Null when the value is not a date.
 */
export function parseExpiresAt(value: string, timeZone: string = BULK_IMPORT_DEFAULT_TIMEZONE): string | null {
  if (DATE_ONLY.test(value)) {
    // Refuse dates that do not exist (2027-02-30 would roll over to March).
    const asUtcMidnight = new Date(`${value}T00:00:00.000Z`);
    if (Number.isNaN(asUtcMidnight.getTime()) || asUtcMidnight.toISOString().slice(0, 10) !== value) return null;
    return endOfDayInTimeZone(value, timeZone);
  }
  if (!/^\d{4}-\d{2}-\d{2}T/.test(value)) return null;
  const ms = Date.parse(value);
  return Number.isNaN(ms) ? null : new Date(ms).toISOString();
}

/** Tags of one cell: split on the file's tag separator, trimmed, blanks dropped, case-insensitive duplicates removed. */
export function splitTags(cell: string, delimiter: BulkImportDelimiter): string[] {
  const seen = new Set<string>();
  const tags: string[] = [];
  for (const raw of cell.split(tagSeparatorFor(delimiter))) {
    const tag = raw.trim();
    if (tag === '' || seen.has(tag.toLowerCase())) continue;
    seen.add(tag.toLowerCase());
    tags.push(tag);
  }
  return tags;
}

/** A parsed CSV row as a draft (cells as written, tags split). */
export function draftOf(parsed: ParsedCsvRow, delimiter: BulkImportDelimiter): { draft: BulkRowDraft; issues: RowIssue[] } {
  const { cells } = parsed;
  const issues: RowIssue[] = [];
  if (parsed.fieldCountMismatch) {
    const { expected, actual } = parsed.fieldCountMismatch;
    issues.push({ severity: 'error', code: 'field-count', message: `Row has ${actual} fields; the header has ${expected}.` });
  }
  const scanMode = cells.scanMode.toUpperCase();
  return {
    draft: {
      row: parsed.row,
      url: cells.url,
      label: cells.label || null,
      folder: cells.folder || null,
      tags: splitTags(cells.tags, delimiter),
      expiresAt: cells.expiresAt || null,
      expiresDate: DATE_ONLY.test(cells.expiresAt) ? cells.expiresAt : null,
      scanMode: scanMode === '' ? null : (scanMode as BulkRowDraft['scanMode']),
    },
    issues,
  };
}

const FIELD_CODES: Record<string, string> = {
  destinationUrl: 'url-invalid',
  label: 'label-too-long',
  expiresAt: 'expires-invalid',
  scanMode: 'scan-mode-invalid',
};

/**
 * The checks of one row that need no database: the single-create schema
 * (bulkCreateQRCodeItemSchema), the expiry date, folder and tag names.
 * Returns the draft with the URL normalised and the expiry as ISO.
 */
export function checkRowFields(
  draft: BulkRowDraft,
  now: Date,
  timeZone: string = BULK_IMPORT_DEFAULT_TIMEZONE,
): { draft: BulkRowDraft; issues: RowIssue[] } {
  const issues: RowIssue[] = [];
  if (draft.url === '') {
    return { draft, issues: [{ severity: 'error', code: 'url-required', message: 'The url cell is empty.' }] };
  }

  let expiresAt: string | null = null;
  if (draft.expiresAt) {
    expiresAt = parseExpiresAt(draft.expiresAt, timeZone);
    if (!expiresAt) {
      issues.push({ severity: 'error', code: 'expires-invalid', message: 'expiresAt must be a date (2027-12-31) or an ISO 8601 datetime.' });
    } else if (Date.parse(expiresAt) <= now.getTime()) {
      issues.push({ severity: 'error', code: 'expires-past', message: 'expiresAt is in the past.' });
    }
  }

  const parsed = bulkCreateQRCodeItemSchema.safeParse({
    destinationUrl: draft.url,
    ...(draft.label ? { label: draft.label } : {}),
    ...(expiresAt ? { expiresAt } : {}),
    ...(draft.scanMode ? { scanMode: draft.scanMode } : {}),
  });
  if (!parsed.success) {
    // One issue per field: a URL can fail several of the schema's checks.
    const seen = new Set<string>();
    for (const issue of parsed.error.issues) {
      const field = String(issue.path[0] ?? '');
      const code = FIELD_CODES[field] ?? 'invalid';
      if (seen.has(code)) continue;
      seen.add(code);
      const message = field === 'scanMode' ? 'scanMode must be FLASH or PAGE.' : issue.message;
      issues.push({ severity: 'error', code, message });
    }
  }

  if (draft.folder && draft.folder.length > FOLDER_NAME_MAX) {
    issues.push({ severity: 'error', code: 'folder-too-long', message: `Folder names are at most ${FOLDER_NAME_MAX} characters.` });
  }
  const longTag = draft.tags.find((t) => t.length > TAG_NAME_MAX);
  if (longTag) issues.push({ severity: 'error', code: 'tag-too-long', message: `Tag names are at most ${TAG_NAME_MAX} characters ("${longTag.slice(0, 40)}").` });
  if (draft.tags.length > BULK_IMPORT_MAX_TAGS_PER_ROW) {
    issues.push({ severity: 'error', code: 'too-many-tags', message: `A row can have at most ${BULK_IMPORT_MAX_TAGS_PER_ROW} tags.` });
  }

  const url = parsed.success ? parsed.data.destinationUrl : draft.url;
  return { draft: { ...draft, url, expiresAt: expiresAt ?? draft.expiresAt }, issues };
}

export const hasError = (issues: readonly RowIssue[]) => issues.some((i) => i.severity === 'error');

export function rowStatus(issues: readonly RowIssue[]): BulkRowStatus {
  if (hasError(issues)) return 'error';
  return issues.length > 0 ? 'warning' : 'ok';
}

/** A validated row as the dry run shows it: errors first. */
export function dryRunRowView({ draft, issues }: ValidatedRow): BulkDryRunRow {
  const sorted = [...issues].sort((a, b) => (a.severity === b.severity ? 0 : a.severity === 'error' ? -1 : 1));
  return {
    row: draft.row,
    status: rowStatus(issues),
    code: sorted[0]?.code ?? null,
    messages: sorted.map((i) => i.message),
    url: draft.url,
    label: draft.label,
    folder: draft.folder,
    tags: draft.tags,
    expiresAt: draft.expiresAt,
    expiresDate: draft.expiresDate ?? null,
    scanMode: draft.scanMode,
  };
}

export function dryRunTotals(rows: readonly BulkDryRunRow[], newFolders: string[], newTags: string[]): BulkDryRunTotals {
  const count = (s: BulkRowStatus) => rows.filter((r) => r.status === s).length;
  return { rows: rows.length, ok: count('ok'), warning: count('warning'), error: count('error'), newFolders, newTags };
}
