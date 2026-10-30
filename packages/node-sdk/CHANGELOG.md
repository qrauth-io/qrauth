# Changelog — @qrauth/node

## 0.6.0 (unreleased)

### Added

- **`image(token, options?)`** downloads a code's image from `GET /api/v1/qrcodes/:token/image`: PNG or SVG at a screen size (`px`), a print-size PNG (`sizeMm` or `sizeIn`, with `dpi`), or a vector PDF (`format: 'pdf'`, `sizeMm` or `sizeIn`, optional `marginMm`). It returns `QRCodeImage` with the bytes, `contentType`, `etag`, the suggested `filename` and, for PNG, the rendered width `px`. New exported types: `QRCodeImage`, `QRCodeImageOptions`. Print-size PNG and PDF need a paid plan; the API answers the Free plan with 403 (`AuthorizationError`).

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
