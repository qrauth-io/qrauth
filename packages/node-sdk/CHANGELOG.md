# Changelog — @qrauth/node

## Unreleased

### Added

- **Bulk import and export.** `bulkImportDryRun(csv, { timezone? })` checks a CSV file (UTF-8 with or without a BOM, `,` or `;` delimited, at most 1 MB and 1,000 rows; columns `url`, `label`, `folder`, `tags`, `expiresAt`, `scanMode`) with the rules of `create()` and returns each row's status without creating anything (a date-only `expiresAt` ends at 23:59:59 that day in `timezone`, an IANA name, default UTC; rows carry `expiresDate`); `commitBulkImport(dryRunId)` starts the import of its valid rows within an hour (rows are checked again when the job runs), `getBulkJob(id)` and `waitForBulkJob(id, options?)` follow the job, and `getBulkImportResultsCsv(id)` returns one line per row with the new token and verify URL. `createBulkExport(options)` renders up to 1,000 codes as SVG and/or PNG into a ZIP with a `manifest.csv`, `createBulkExportLink(id)` returns a 5-minute download link and `downloadBulkExport(id)` downloads the ZIP. Business plan and above; import needs a MEMBER key or higher; one import and one export at a time per organization (`ConflictError`, `reason` `'bulk-job-active'`); a refused file is a `QRAuthError` with `statusCode` 422 and the reason in its message; jobs, results and ZIPs are deleted 24 hours after the job ends. `getBulkImportTemplate()` returns the CSV template. New exported types: `BulkDryRun`, `BulkDryRunRow`, `BulkDryRunTotals`, `BulkRowStatus`, `BulkJob`, `BulkJobKind`, `BulkJobStatus`, `BulkExportOptions`, `BulkExportSelection`, `BulkExportLink`.
- **Organization policies.** `getPolicy()`, `updatePolicy(options)` and `previewPolicy(allowlist)` for `/api/v1/policies`: a destination allowlist (`allowlistMode` `'OFF'` or `'ENFORCE'`, up to 200 domains, each reduced to its registrable domain and stored in punycode, `includeSubdomains` default `true`) and `destinationEditMinRole` (`'MEMBER'`, `'MANAGER'` or `'ADMIN'`). Needs an OWNER or ADMIN key; changes need the Business plan or above. `list()` takes `outsidePolicy` (`true` or `false`), and `QRCodeDetail.outsidePolicy` marks codes outside an enforced allowlist. A destination outside it is a `QRAuthError` with `statusCode` 422 (`bulk()`: `errorCode` `'DESTINATION_NOT_ALLOWED'`); a role below the minimum is an `AuthorizationError` with `reason` `'destination-edit-role-required'`. New exported types: `OrgPolicy`, `UpdatePolicyOptions`, `AllowlistMode`, `DestinationEditRole`, `AllowlistEntry`, `AllowlistEntryInput`, `AllowlistNormalisation`, `PolicyPreview`, `PolicyAffectedCode`.
- **Audit log.** `listAuditEntries(params?)` reads one page of the organization's audit log from `GET /api/v1/audit` (newest first; `nextCursor` for the next page), `iterateAuditEntries(params?)` yields every matching entry across pages, and `exportAuditCsv(params?)` returns `GET /api/v1/audit/export.csv` as text. Filters: `actor`, `actorType`, `action`, `resourceType`, `resourceId`, `from`, `to` (`Date` or ISO 8601 string); `cursor` and `limit` (1–100, default 50) for pages. Needs an OWNER or ADMIN key and the Business plan or above. New exported types: `AuditEntry`, `AuditActorView`, `AuditActorType`, `AuditPage`, `AuditFilterParams`, `AuditListParams`, `AuthorizationErrorOptions`.
- `AuthorizationError.reason`: the API's machine-readable `code` for a 403, when it sends one (e.g. `'governance-plan-required'`, `'audit-role-required'`). The constructor's `options` argument accepts `reason`.
- `VerificationResult.domain_warning.reason`: why the destination is a lookalike (`'confusable'` for a Unicode confusable, `'mixed_script'` for letters of different scripts in one name, or an edit-distance reason such as `'typosquatting'`). Optional; older API versions do not send it. `similar_to` can now also be one of QRAuth's protected brands, not only a verified organization's domain.

## 0.6.0 (2026-11-02)

### Added

- **Search and filters on `list()`.** New `ListQRCodesOptions` fields: `q` (label substring, destination host substring of URL codes, token prefix or content type key), `contentType` (ignoring case), `tagIds` (codes with any of the tags) and `folderId` (a folder id, or `'unfiled'`). `QRCodeDetail` gains optional `destinationHost`, `folderId`, `tags` and `folder`, returned by both `list()` and `get()`.
- **Tags.** `listTags()`, `createTag({ name, color? })`, `updateTag(tagId, { name?, color? })` and `deleteTag(tagId)` for `/api/v1/tags`. Colours come from the fixed palette `TAG_COLORS` (exported, with the `TagColor` type).
- **Folders.** `listFolders()` (folders and `unfiledCount`), `createFolder(name)`, `renameFolder(folderId, name)` and `deleteFolder(folderId)` for `/api/v1/folders`. Deleting a folder leaves its codes unfiled.
- **`bulkTag(tokens, { add?, remove? })` and `bulkMove(tokens, folderId | null)`** organise up to 100 codes per call and return `BulkOrganizeResult` (`updated`, `notFound`).
- **`ConflictError`** for 409 responses, with the API's `code` in `reason` (`'name-taken'` or `'limit-reached'` for tags and folders).
- **`getHistory(token, options?)`** reads a code's edit history from `GET /api/v1/qrcodes/:token/history`, newest first, paged with `page` and `pageSize` (default 20, max 100). Each `QRCodeRevision` has its `revision` number, `kind` (`BASELINE`, `CREATED`, `UPDATED`, `RESTORED` or `REVOKED`), `createdAt`, the `changes` to the tracked fields (destination, content, style, expiry, scan mode, status) as `{ before, after }`, the `actor` (a user, an API key or QRAuth itself), the `requestId` of the change and, for `RESTORED`, `restoredFrom`.
- **`restoreDestination(token, revision)`** restores the destination (URL codes) or content (other types) a code had right after a revision, through `POST /api/v1/qrcodes/:token/history/:revision/restore`. The value must meet the current rules; the code is re-signed, and the updated code (`UpdatedQRCode`) is returned. Needs an OWNER, ADMIN or MANAGER key. Conflicts (value already current, code revoked, value no longer in the history) are status 409; a value that no longer meets the rules is status 422.
- **`requestId` on errors.** Every `QRAuthError` carries the API's `X-Request-Id` for the failed request, when the API sends one. The error constructors take an optional last `options` argument (`QRAuthErrorOptions`) for it.
- **Smart link and link list content types.** `CreateQRCodeOptions.contentType` accepts `'app-link'` and `'link-list'`, described by `AppLinkContent`, `LinkListContent` and `LinkListItem`; `QRCodeDetail.content` includes both shapes. Every link must be an absolute https URL with a public host name. An invalid link is refused with 400 (`ValidationError`), a link listed by Google Web Risk with 422 (`QRAuthError`, `statusCode` 422, the message names the link), a link that cannot be screened right now with 503 (retry later), and the Free plan gets 403 (`AuthorizationError`). `DomainWarning.url` names the link a lookalike warning is about.
- **`image(token, options?)`** downloads a code's image from `GET /api/v1/qrcodes/:token/image`: PNG or SVG at a screen size (`px`), a print-size PNG (`sizeMm` or `sizeIn`, with `dpi`), or a vector PDF (`format: 'pdf'`, `sizeMm` or `sizeIn`, optional `marginMm`). It returns `QRCodeImage` with the bytes, `contentType`, `etag`, the suggested `filename` and, for PNG, the rendered width `px`. Print-size PNG and PDF need a paid plan; the API answers the Free plan with 403 (`AuthorizationError`).
- **`SDK_VERSION`** export; requests send `User-Agent: qrauth-node/0.6.0` (it said `0.1.0` before).

New exported types: `Tag`, `QRCodeTag`, `TagColor`, `CreateTagOptions`, `UpdateTagOptions`, `Folder`, `ListFoldersResponse`, `BulkTagOptions`, `BulkOrganizeResult`, `QRCodeRevision`, `QRCodeHistory`, `RevisionKind`, `RevisionActor`, `RevisionChanges`, `FieldChange`, `TrackedField`, `GetHistoryOptions`, `UpdatedQRCode`, `QRAuthErrorOptions`, `ContentType`, `AppLinkContent`, `LinkListContent`, `LinkListItem`, `QRCodeImage`, `QRCodeImageOptions`.

### Changed

- A 409 response now throws `ConflictError` (a `QRAuthError` subclass with `statusCode` 409 and `code` `'CONFLICT'`) instead of a plain `QRAuthError` with `code` `'API_ERROR'`. Code that checks `statusCode === 409` or `instanceof QRAuthError` is unaffected.
- **`CreateQRCodeOptions.destination` is optional.** It is still required for URL codes; for other content types leave it out (`create()` sends `destinationUrl` only when `destination` is given). Previously a content-type code needed a placeholder URL.

### Tests

- Captured API responses (`src/__tests__/fixtures/wire.ts`) now cover tags and folders, edit history, and smart link and link list create, get and verify; `npm test` type-checks them against the SDK types.

## 0.5.1

### Added

- `QRCodeDetail.verification_url`: the URL the code encodes, returned by `get()`. Optional, because older API versions do not send it.

### Changed

- **`bulk()` is documented as URL codes only.** `BulkCreateItem` now states that bulk create makes URL codes; the API answers 400 (`bulk supports URL codes only`, with the item index in `details[].path`) for a bulk request whose items carry `contentType` or `content`. The SDK never sent those fields, so `bulk()` calls are unaffected. Use `create()` for other content types.

## 0.5.0

### Added

- **Scan modes.** New `ScanMode` type: `'FLASH' | 'PAGE'`.
  - `create()` and `bulk()` accept `scanMode`. With `'FLASH'` (the API default), a `VERIFIED` scan of an https URL code without a location binding shows a short trust reveal in the browser, then continues to the destination. `'PAGE'` always shows the full verification page.
  - `VerificationResult.scan_mode` reports what a browser does on that scan. It is `'FLASH'` only for `VERIFIED` results that meet the conditions above, and `'PAGE'` for everything else, including every failure response.
  - `QRCodeResponse.scan_mode` and `QRCodeDetail.scanMode` carry the code's setting.

The new response fields are optional in the types, because API versions before scan modes do not send them.

## 0.4.0

### Changed

- **`VerificationResult` follows the verify API's trust states.**
  - New `trust_state`: `'VERIFIED' | 'SIGNED_UNVERIFIED_ISSUER' | 'UNTRUSTED'` (exported as `TrustState`).
  - `verified` is now `true` only when `trust_state === 'VERIFIED'`, which requires an issuer verified by QRAuth. An authentic code from an issuer QRAuth has not verified returns `verified: false` with `trust_state: 'SIGNED_UNVERIFIED_ISSUER'`. Code that used `verified` to mean "the signature is valid" should check `trust_state !== 'UNTRUSTED'` instead.
  - `organization` is now `{ verified: true, name, verified_domain? }` for `VERIFIED` results and `{ verified: false }` otherwise (exported as `VerificationOrganization`). The previous `id`, `slug`, `trustLevel`, `kycStatus` and `domainVerified` fields are no longer returned.
  - `destination_url` is optional: it is absent from failure responses (revoked, expired, scan limit, suspended issuer, flagged destination).
  - New optional `reason`.

### Fixed

Response types corrected to match what the API sends:
- `VerificationResult.domain_warning` is `{ message, similar_to, verified_org, similarity }`. The previous `similarDomain` and `verifiedOrg` names were never sent.
- `BulkCreateResponse` counts are under `summary` (`{ total, succeeded, failed }`), not at the top level. Failed items may carry `threatTypes` (with `errorCode: 'DESTINATION_FLAGGED'`).
- `QRCodeResponse.alg_version` is always present; `merkle_batch_id` is `string | null`.
- `VerificationResult.security.merkleBatchId` and `security.algVersion` may be `null`.

These describe the response the API already returns; no client code changed. TypeScript users may need to narrow `organization` (`if (result.organization.verified)`) before reading `name`.

## 0.3.1

- `revoke()` handles the API's 204 response; validation errors are formatted.
