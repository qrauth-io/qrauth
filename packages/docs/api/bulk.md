---
title: Bulk Import and Export
description: Create up to 1,000 URL QR codes from a CSV file, and download up to 1,000 codes as SVG and PNG files in a ZIP.
---

# Bulk Import and Export

Create URL QR codes from a CSV file, and export rendered codes as a ZIP file.

- **Import** has two steps. A **dry run** checks every row with the same rules as [creating a single code](./qrcodes#create-qr-code) and creates nothing. A **commit** then creates the valid rows in a background job.
- **Export** renders up to 1,000 codes as SVG and/or PNG files into a ZIP with a `manifest.csv`, and gives you a short-lived download link.

Bulk import creates URL codes only. For other content types, use [single create](./qrcodes#create-qr-code).

## Access

| | Import | Export |
|---|---|---|
| Plan | Business and above | Business and above |
| Role | `OWNER`, `ADMIN`, `MANAGER` or `MEMBER` | Any role, including `VIEWER` |
| Email | A verified email (for an API key: an owner's) | — |
| Jobs at a time | One import per organization | One export per organization |

A dry run, a job, its results and its ZIP belong to the member or API key that started them. For anyone else, including other members of the organization, the id answers `404`.

**Headers:** `X-API-Key: <key>` (or a dashboard session)

## CSV format

| Column | Required | Value |
|--------|----------|-------|
| `url` | Yes | An `http` or `https` URL with a public host, as for single create. It is normalised (for example `HTTPS://Example.COM` becomes `https://example.com/`) |
| `label` | No | Up to 200 characters |
| `folder` | No | A folder name, up to 64 characters. Matched without regard to case; created if missing |
| `tags` | No | Tag names, up to 20 per row and 32 characters each. Matched without regard to case; created if missing |
| `expiresAt` | No | A date (`2027-12-31`), meaning 23:59:59 that day in the upload's [time zone](#time-zone), or an ISO 8601 datetime with its own offset (`2027-12-31T18:00:00+02:00`). Must be in the future |
| `scanMode` | No | `FLASH` (default) or `PAGE`, in any case |

- The first row is the header. Column names are matched without regard to case and can be in any order. An unknown column refuses the whole file, and the error lists it.
- **Encoding:** UTF-8, with or without a byte order mark.
- **Delimiter:** a comma or a semicolon, detected from the header row.
- **Tags in one cell:** separated by `;` in a comma-delimited file and by `|` in a semicolon-delimited file, so the separator is never the field delimiter.
- **Quoting:** a quoted field can contain the delimiter, quotes (written twice, `""`) and line breaks.
- **Blank rows** are skipped. Row numbers in results count every row of the file, with the header as row 1.
- **Limits:** at most 1 MB and 1,000 data rows.

Download the template from `GET /api/v1/bulk/imports/template.csv`, or from the dashboard's Bulk import page:

```csv
url,label,folder,tags,expiresAt,scanMode
https://example.com/menu,Table 1 menu,Restaurant,menu;table-1,2027-12-31,FLASH
https://example.com/offer,Spring offer,,offers,,PAGE
```

### Excel and Greek text

- **Save as "CSV UTF-8 (Comma delimited) (*.csv)".** The plain "CSV (Comma delimited)" option saves in the computer's legacy encoding (Windows-1253 for Greek). The API refuses such files with `file-not-utf8`.
- **Greek and other European regional settings use `;` as the list separator,** so Excel writes semicolon-delimited files. The API detects this. In such a file, separate tags with `|`.
- Values that look like formulas (`=`, `+`, `-`, `@`) are stored as plain text. In the results CSV and the ZIP manifest they are prefixed with an apostrophe, so a spreadsheet does not run them.

## Dry run

```
POST /api/v1/bulk/imports/dry-run?timezone=Europe/Athens
Content-Type: text/csv
```

The body is the file itself, not a multipart form.

### Time zone

`timezone` (optional) is an IANA time zone name, such as `Europe/Athens` or `UTC`.

- A date-only `expiresAt` ends at 23:59:59 that day in this zone, including on days when the clocks change.
- Without the parameter, dates end at 23:59:59 UTC. The dashboard sends the browser's time zone.
- An unknown name is refused with `422` and code `timezone-invalid`.
- Rows show both the instant (`expiresAt`) and the date as written (`expiresDate`). Every row is checked with the rules of single create:

- the URL rules;
- the organization's [destination allowlist](./policies);
- [Web Risk](../guide/fraud-detection), once per distinct URL;
- lookalike detection;
- the QR code quota for the whole file;
- the folder and tag limits (200 folders and 100 tags per organization).

The result is kept for one hour. Only the member or API key that made it can read or commit it.

**Response `201`:**

```json
{
  "id": "lrpj5k_cDoVs-qTox2uh1w",
  "expiresAt": "2026-11-05T18:09:46.601Z",
  "delimiter": ";",
  "columns": ["url", "label", "folder", "tags", "expiresAt", "scanMode"],
  "timezone": "Europe/Athens",
  "totals": { "rows": 6, "ok": 3, "warning": 2, "error": 1, "newFolders": ["Δημαρχείο"], "newTags": ["μενού"] },
  "rows": [
    { "row": 2, "status": "ok", "code": null, "messages": [], "url": "https://www.thessaloniki.gr/menu", "label": "Μενού", "folder": "Δημαρχείο", "tags": ["μενού"], "expiresAt": "2027-12-31T21:59:59.000Z", "expiresDate": "2027-12-31", "scanMode": "FLASH" },
    { "row": 5, "status": "warning", "code": "lookalike", "messages": ["The destination looks like paypal.com (PayPal); it is recorded as a fraud incident when created."], "url": "https://paypa1.com/login", "label": null, "folder": null, "tags": [], "expiresAt": null, "expiresDate": null, "scanMode": null }
  ]
}
```

A row's `status` is `ok`, `warning` (it will be created) or `error` (it will be skipped). `code` names the first reason:

| `code` | Status | Reason |
|--------|--------|--------|
| `url-required`, `url-invalid` | error | No URL, or not an `http(s)` URL with a public host |
| `label-too-long`, `folder-too-long`, `tag-too-long`, `too-many-tags` | error | A value is over its limit |
| `expires-invalid`, `expires-past` | error | `expiresAt` is not a date, or is in the past |
| `scan-mode-invalid` | error | `scanMode` is not `FLASH` or `PAGE` |
| `field-count` | error | The row has a different number of fields than the header |
| `destination-not-allowed` | error | The URL is outside the organization's allowlist |
| `destination-flagged` | error | Web Risk lists the URL |
| `folder-limit`, `tag-limit` | error | Creating the folder or tag would exceed the organization's limit |
| `quota-exceeded` | error | The row is past the plan's QR code limit |
| `web-risk-unavailable` | warning | Web Risk did not answer. The code is created and checked again straight away, as with single create |
| `lookalike` | warning | The destination looks like a verified organization's or a protected brand's domain. The code is created and a fraud incident is recorded |
| `duplicate-url` | warning | An earlier row has the same URL |

`GET /api/v1/bulk/imports/dry-run/:id` returns the same body while the dry run is valid.

**File errors (`422`):**

| `code` | When |
|--------|------|
| `file-empty`, `no-rows` | The file is empty, or has a header row only |
| `file-not-text`, `file-not-utf8` | The file is binary, or is not UTF-8 text |
| `csv-malformed` | The CSV cannot be read (for example, an unclosed quote) |
| `header-missing-url`, `header-unknown-columns`, `header-duplicate-columns` | The header row has no `url` column, has an unknown column, or lists a column twice |
| `too-many-rows` | More than 1,000 data rows |

A body over 1 MB is refused with `413` before it is read in full.

## Commit

```
POST /api/v1/bulk/imports/dry-run/:id/commit
```

This starts the import job and returns `202` with the [job](#jobs).

- When the job runs, rows are checked again as of that moment. The policy, the quota or a Web Risk listing may have changed since the dry run, and rows that now fail are skipped.
- Missing folders and tags are created first.
- Each code gets the usual entry in its edit history, attributed to you.
- A dry run can be committed once.

| Status | `code` | When |
|--------|--------|------|
| `404` | — | No such dry run for this caller, or it expired after an hour |
| `409` | `bulk-job-active` | An import is already queued or running in the organization (`activeJobId` names it) |
| `422` | `nothing-to-import` | Every row of the dry run has an error |

### Results

```
GET /api/v1/bulk/imports/:jobId/results.csv
```

One line per row of the file, in file order. Columns: `row`, `status` (`created`, `skipped` or `failed`), `token`, `verifyUrl`, `url`, `label`, `error`. The file starts with a UTF-8 byte order mark, so spreadsheet apps read non-Latin text correctly.

## Export

```
POST /api/v1/bulk/exports
Content-Type: application/json
```

```json
{
  "selection": { "importJobId": "cmw3suiog00052g1ejedfep1b" },
  "formats": ["svg", "png"],
  "png": { "px": 512 }
}
```

| Field | Value |
|-------|-------|
| `selection` | One of: `{ "tokens": ["…"] }` (up to 1,000 tokens of your organization), `{ "importJobId": "…" }` (the codes an import of yours created), or `{ "filter": { … } }` with the [list filters](./qrcodes#list-qr-codes) `q`, `contentType`, `tagIds` (array), `folderId` (or `"unfiled"`), `outsidePolicy` (boolean) and `status` |
| `formats` | `["svg"]`, `["png"]` or both |
| `png` | Required with `png`. Either `{ "px": 64–1024 }` (screen size), or `{ "sizeMm": 10–1000, "dpi": 72–1200 }` (print size; `dpi` defaults to 300). A print size can be at most 4,000 px wide, for example 300 mm at 300 dpi |

The response is `202` with the [job](#jobs).

- Codes are rendered in their stored style on the render service's export lane, so issuing new codes is never slowed down.
- File names are the label's letters and digits plus the token, for example `Table-1-menu_K4S6VsPx.svg`. They are never paths.
- `manifest.csv` lists every file with its token, label, destination, verify URL and status.
- The uncompressed total is capped at 256 MB. A larger export fails with an error asking for fewer codes or a smaller PNG.

| Status | `code` | When |
|--------|--------|------|
| `400` | — | Invalid body: more than 1,000 tokens, PNG without a size, a print size over 4,000 px |
| `404` | `export-import-not-found` | The import job is not yours, or was deleted |
| `404` | — | A tag or folder in the filter is not in your organization |
| `409` | `bulk-job-active` | An export is already queued or running in the organization |
| `422` | `export-empty`, `export-too-many` | No code matches, or more than 1,000 do |

### Download

```
POST /api/v1/bulk/exports/:jobId/link
```

```json
{ "url": "https://qrauth.io/api/v1/bulk/exports/cmw3…/download?expires=1793898886&sig=…", "expiresAt": "2026-11-05T17:14:46.000Z" }
```

- The link is valid for 5 minutes and works without an API key or session. Treat it like a password.
- Only the member or key that started the export can create one.
- `409 export-not-ready` while the job runs; `410 export-expired` once the ZIP is deleted.
- An invalid, expired or altered link answers `403 link-invalid`.

## Jobs

```
GET /api/v1/bulk/jobs/:id
```

```json
{
  "id": "cmw3svc9w04nv2g1etex12juh",
  "kind": "EXPORT",
  "status": "SUCCEEDED",
  "total": 1000, "processed": 1000, "succeeded": 1000, "failed": 0, "skipped": 0,
  "error": null,
  "createdAt": "2026-11-05T17:08:54.884Z",
  "startedAt": "2026-11-05T17:08:54.891Z",
  "finishedAt": "2026-11-05T17:08:58.568Z",
  "expiresAt": "2026-11-06T17:08:58.568Z",
  "fileBytes": 11180850
}
```

- `status` is `QUEUED`, `RUNNING`, `SUCCEEDED` or `FAILED`. A `SUCCEEDED` import can still have skipped or failed rows.
- A job runs once.
- A job that stops reporting progress (for example during a server restart) is marked `FAILED` within the hour; start it again.
- A job, its results and its ZIP are deleted 24 hours after it ends (`expiresAt`).
- Poll every few seconds. Job reads count against the API rate limit.

## Audit

Each job writes `bulk.start` when it is started and `bulk.finish` when it ends to the [audit log](./audit-log). Both entries record the job id, kind, counts and who started it. They stay in the log after the job is deleted.

Created codes appear as `qr.created`, and new folders and tags as `folder.create` and `tag.create`.

## Node SDK

```ts
import { readFile, writeFile } from 'node:fs/promises';

const dryRun = await qrauth.bulkImportDryRun(await readFile('codes.csv'), { timezone: 'Europe/Athens' });
if (dryRun.totals.error > 0) console.table(dryRun.rows.filter((r) => r.status === 'error'));

const job = await qrauth.waitForBulkJob((await qrauth.commitBulkImport(dryRun.id)).id);
await writeFile('results.csv', await qrauth.getBulkImportResultsCsv(job.id));

const exportJob = await qrauth.createBulkExport({ selection: { importJobId: job.id }, formats: ['svg', 'png'], png: { px: 512 } });
await qrauth.waitForBulkJob(exportJob.id);
await writeFile('codes.zip', await qrauth.downloadBulkExport(exportJob.id));
```
