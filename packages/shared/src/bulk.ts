import { z } from "zod";

import { MAX_TAGS_PER_REQUEST, SEARCH_QUERY_MAX } from "./qr-organize.js";

/**
 * Bulk operations (Milestone 2 PR C, ADR-0008 D9): CSV import of URL codes
 * and ZIP export of rendered codes. Business plan and above (D5). The API,
 * the dashboard and the Node SDK share these limits and wire shapes.
 */

// ---------------------------------------------------------------------------
// CSV import
// ---------------------------------------------------------------------------

/** Largest CSV file accepted (bytes, including a BOM). */
export const BULK_IMPORT_MAX_BYTES = 1024 * 1024;
/** Data rows per file, not counting the header row. */
export const BULK_IMPORT_MAX_ROWS = 1000;
/** A dry run can be committed for this long, by the member or key that ran it. */
export const BULK_DRY_RUN_TTL_SECONDS = 3600;
/** Tags per row, the same cap as a bulk tag request. */
export const BULK_IMPORT_MAX_TAGS_PER_ROW = 20;

/** Columns in the order of the template. Only `url` is required. */
export const BULK_IMPORT_COLUMNS = ["url", "label", "folder", "tags", "expiresAt", "scanMode"] as const;
export type BulkImportColumn = (typeof BULK_IMPORT_COLUMNS)[number];

/** The two field delimiters a file may use; detected from the header row. */
export const BULK_IMPORT_DELIMITERS = [",", ";"] as const;
export type BulkImportDelimiter = (typeof BULK_IMPORT_DELIMITERS)[number];

/**
 * Tags in one cell are split on `;` in a comma-delimited file and on `|` in a
 * semicolon-delimited file, so the tag separator is never the field delimiter.
 */
export function tagSeparatorFor(delimiter: BulkImportDelimiter): ";" | "|" {
  return delimiter === "," ? ";" : "|";
}

/** The downloadable template (comma-delimited, UTF-8, CRLF line ends). */
export const BULK_IMPORT_TEMPLATE_CSV =
  "url,label,folder,tags,expiresAt,scanMode\r\n" +
  "https://example.com/menu,Table 1 menu,Restaurant,menu;table-1,2027-12-31,FLASH\r\n" +
  "https://example.com/offer,Spring offer,,offers,,PAGE\r\n";

/** Time zone of a date-only `expiresAt` when the upload names none (API callers). */
export const BULK_IMPORT_DEFAULT_TIMEZONE = "UTC";

/** True for an IANA time zone name the runtime knows (e.g. "Europe/Athens", "UTC"). */
export function isValidTimeZone(timeZone: string): boolean {
  if (timeZone.length === 0 || timeZone.length > 64) return false;
  try {
    new Intl.DateTimeFormat("en-US", { timeZone });
    return true;
  } catch {
    return false;
  }
}

/** Offset of `timeZone` from UTC at `instantMs`, in ms (Athens in summer: +3 h). */
function zoneOffsetMs(instantMs: number, timeZone: string): number {
  const parts = new Intl.DateTimeFormat("en-US", {
    timeZone,
    hourCycle: "h23",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  }).formatToParts(new Date(instantMs));
  const get = (type: string) => Number(parts.find((p) => p.type === type)?.value);
  const asUtc = Date.UTC(get("year"), get("month") - 1, get("day"), get("hour"), get("minute"), get("second"));
  return asUtc - Math.floor(instantMs / 1000) * 1000;
}

/**
 * The instant of 23:59:59 on `date` (YYYY-MM-DD) in `timeZone`, as an ISO
 * 8601 UTC string. Correct across daylight-saving changes: the offset is
 * read at the result itself.
 */
export function endOfDayInTimeZone(date: string, timeZone: string): string {
  const [y, m, d] = date.split("-").map(Number);
  const wall = Date.UTC(y, m - 1, d, 23, 59, 59);
  let instant = wall - zoneOffsetMs(wall, timeZone);
  instant = wall - zoneOffsetMs(instant, timeZone);
  return new Date(instant).toISOString();
}

export type BulkRowStatus = "ok" | "warning" | "error";

/** One data row of a dry run, as read and normalised. */
export interface BulkDryRunRow {
  /** Row number in the file: the header is row 1, the first data row is row 2. */
  row: number;
  status: BulkRowStatus;
  /** Machine-readable reason of an error or warning (first one wins). */
  code: string | null;
  /** Human-readable reasons, errors first. */
  messages: string[];
  url: string;
  label: string | null;
  folder: string | null;
  tags: string[];
  /** ISO 8601 datetime, or null. */
  expiresAt: string | null;
  /** The date as written when the cell was a date only (YYYY-MM-DD); `expiresAt` is 23:59:59 of it in the upload's time zone. */
  expiresDate: string | null;
  scanMode: "FLASH" | "PAGE" | null;
}

export interface BulkDryRunTotals {
  rows: number;
  ok: number;
  warning: number;
  error: number;
  /** Folder and tag names the import would create. */
  newFolders: string[];
  newTags: string[];
}

/** POST /api/v1/bulk/imports/dry-run and GET /api/v1/bulk/imports/dry-run/:id. */
export interface BulkDryRunView {
  id: string;
  expiresAt: string;
  delimiter: BulkImportDelimiter;
  columns: BulkImportColumn[];
  /** IANA time zone of date-only expiry dates (the upload's `timezone`, default UTC). */
  timezone: string;
  totals: BulkDryRunTotals;
  rows: BulkDryRunRow[];
}

// ---------------------------------------------------------------------------
// Jobs
// ---------------------------------------------------------------------------

export const BULK_JOB_KINDS = ["IMPORT", "EXPORT"] as const;
export type BulkJobKind = (typeof BULK_JOB_KINDS)[number];
export const BULK_JOB_STATUSES = ["QUEUED", "RUNNING", "SUCCEEDED", "FAILED"] as const;
export type BulkJobStatus = (typeof BULK_JOB_STATUSES)[number];

/** Results, files and the job itself are deleted this long after the job ends. */
export const BULK_ARTIFACT_TTL_HOURS = 24;

/** GET /api/v1/bulk/jobs/:id */
export interface BulkJobView {
  id: string;
  kind: BulkJobKind;
  status: BulkJobStatus;
  /** Rows (import) or codes (export) in the job. */
  total: number;
  processed: number;
  succeeded: number;
  failed: number;
  skipped: number;
  /** Why a FAILED job stopped. */
  error: string | null;
  createdAt: string;
  startedAt: string | null;
  finishedAt: string | null;
  /** When the results or the ZIP are deleted. */
  expiresAt: string | null;
  /** Export: size of the ZIP in bytes once it is ready. */
  fileBytes: number | null;
}

/** One line of an import's results CSV. */
export interface BulkImportResult {
  row: number;
  status: "created" | "skipped" | "failed";
  token: string | null;
  error: string | null;
}

// ---------------------------------------------------------------------------
// ZIP export
// ---------------------------------------------------------------------------

export const BULK_EXPORT_MAX_CODES = 1000;
/** Uncompressed size of all files in one ZIP. */
export const BULK_EXPORT_MAX_BYTES = 256 * 1024 * 1024;
/** Download links are valid this long. */
export const BULK_EXPORT_LINK_TTL_SECONDS = 300;
export const BULK_EXPORT_FORMATS = ["svg", "png"] as const;
export type BulkExportFormat = (typeof BULK_EXPORT_FORMATS)[number];
/** PNG width at screen size, the same range as a single export. */
export const BULK_EXPORT_PNG_PX_MIN = 64;
export const BULK_EXPORT_PNG_PX_MAX = 1024;
/** Print-size PNGs in a ZIP stay at or under 16 megapixels (4,000 px a side). */
export const BULK_EXPORT_PRINT_MAX_PX = 4000;

const tokenList = z.array(z.string().min(1).max(64)).min(1).max(BULK_EXPORT_MAX_CODES);

/**
 * The QR list's filters (GET /api/v1/qrcodes) as a JSON body: tag ids as an
 * array and outsidePolicy as a boolean, where the list takes query strings.
 */
export const bulkExportFilterSchema = z
  .object({
    q: z.string().trim().max(SEARCH_QUERY_MAX).optional(),
    contentType: z.string().trim().toLowerCase().min(1).max(32).optional(),
    tagIds: z.array(z.string().min(1).max(64)).max(MAX_TAGS_PER_REQUEST).optional(),
    /** A folder id, or `unfiled`. */
    folderId: z.string().min(1).max(64).optional(),
    outsidePolicy: z.boolean().optional(),
    status: z.enum(["ACTIVE", "EXPIRED", "REVOKED"]).optional(),
  })
  .strict();

export const bulkExportSelectionSchema = z.union([
  z.object({ tokens: tokenList }).strict(),
  z.object({ importJobId: z.string().min(1).max(64) }).strict(),
  z.object({ filter: bulkExportFilterSchema }).strict(),
]);

const pngScreen = z.object({ px: z.number().int().min(BULK_EXPORT_PNG_PX_MIN).max(BULK_EXPORT_PNG_PX_MAX) }).strict();
const pngPrint = z
  .object({
    sizeMm: z.number().min(10).max(1000),
    dpi: z.number().int().min(72).max(1200).default(300),
  })
  .strict()
  .refine((p) => Math.round((p.sizeMm / 25.4) * p.dpi) <= BULK_EXPORT_PRINT_MAX_PX, {
    message: `A print-size PNG in a ZIP can be at most ${BULK_EXPORT_PRINT_MAX_PX} px wide (for example 300 mm at 300 dpi)`,
  });

export const bulkExportRequestSchema = z
  .object({
    selection: bulkExportSelectionSchema,
    formats: z
      .array(z.enum(BULK_EXPORT_FORMATS))
      .min(1)
      .max(BULK_EXPORT_FORMATS.length)
      .refine((f) => new Set(f).size === f.length, { message: "Each format once" }),
    /** Required when formats include png: a screen width or a print size. */
    png: z.union([pngScreen, pngPrint]).optional(),
  })
  .strict()
  .refine((r) => !r.formats.includes("png") || r.png !== undefined, {
    message: "PNG needs a size: { px } or { sizeMm, dpi }",
    path: ["png"],
  });

/** The request as the API reads it (dpi defaulted). */
export type BulkExportRequest = z.infer<typeof bulkExportRequestSchema>;
/** The request body as a client sends it (dpi optional). */
export type BulkExportRequestInput = z.input<typeof bulkExportRequestSchema>;

/** POST /api/v1/bulk/exports/:id/link */
export interface BulkExportLink {
  url: string;
  expiresAt: string;
}
