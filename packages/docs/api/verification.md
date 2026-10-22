---
title: Verification
description: Verify a QR code scan — HTML page for browsers, JSON for programmatic consumers.
---

# Verification

When a device scans a QRAuth code it is directed to the verification endpoint. The response format is determined by content negotiation.

## Verify QR Code

`GET /v/:token`

This endpoint lives outside the `/api/v1` prefix because it handles browser navigation directly. No authentication header is required — verification is always public.

**Path parameters:**

| Param | Type | Description |
|-------|------|-------------|
| `token` | string | The QR code token |

**Query parameters:**

| Param | Type | Required | Description |
|-------|------|----------|-------------|
| `clientLat` | number | No | Latitude of the scanning device (decimal degrees) |
| `clientLng` | number | No | Longitude of the scanning device (decimal degrees) |

::: tip Sending GPS coordinates
If the QR code was registered with a location and you want proximity verification, pass `clientLat` and `clientLng`. The browser will prompt for location permission if you use the Web Components SDK — it handles this automatically.
:::

**Headers:**

| Header | Value | Description |
|--------|-------|-------------|
| `Accept` | `application/json` | Returns JSON instead of the HTML verification page |
| `X-Client-Id` | any | Also selects the JSON response |

### Browser response

When accessed from a browser (no `Accept: application/json` header) the endpoint returns the full-screen Trust Reveal page — an animated verification with visual fingerprint, trust score, and fraud signals displayed to the end user.

### JSON response (200)

```json
{
  "verified": true,
  "organization": {
    "id": "clx...",
    "name": "Acme Corp",
    "slug": "acme-corp",
    "trustLevel": "BUSINESS",
    "kycStatus": "VERIFIED",
    "domainVerified": true
  },
  "destination_url": "https://example.com/product",
  "security": {
    "signatureValid": true,
    "trustScore": 100,
    "transparencyLogVerified": true,
    "algVersion": "hybrid-ecdsa-slhdsa-v1",
    "algVersionStatus": "accepted",
    "merkleProofValid": true,
    "merkleBatchId": "...",
    "pqcProtected": true
  },
  "warnings": [],
  "location_match": {
    "matched": true,
    "distanceM": 14,
    "registeredAddress": "sxk9..."
  },
  "scannedAt": "2026-04-10T12:05:00.000Z"
}
```

### Response fields

| Field | Type | Description |
|-------|------|-------------|
| `verified` | boolean | `true` when the signatures verify, the code is active and within its scan limits, its `alg_version` is accepted, the trust score is above 20, and any required proximity check passed |
| `reason` | string | Present when `verified` is `false` for a stated reason: a human-readable message (revoked, expired, scan limit, unsupported algorithm, failed MAC pre-filter, low trust score) or a geo-fence code (`GEO_PROXIMITY_REQUIRED`, `GEO_OUT_OF_FENCE`). Absent when the only failure is `security.signatureValid: false` |
| `organization` | object | Issuer: `id`, `name`, `slug`, `trustLevel` (`INDIVIDUAL` \| `BUSINESS` \| `GOVERNMENT`), `kycStatus` (`PENDING` \| `UNDER_REVIEW` \| `VERIFIED` \| `REJECTED`), `domainVerified` |
| `destination_url` | string | The code's destination URL |
| `security.signatureValid` | boolean | `true` when the ECDSA-P256 signature verifies and, for hybrid rows, the Merkle leaf recomputed from the code's canonical data and stored nonce verifies, through its inclusion proof, against an SLH-DSA-SHA2-128s-signed batch root. A hybrid row without complete Merkle data fails |
| `security.trustScore` | number | 0–100. Starts at 100; deductions for unresolved fraud incidents (once per incident type, by severity) and recent scan velocity, clamped to 30–100; then −30 (floor 0) if the destination resembles another organization's verified domain. See [Trust Levels](/guide/trust-levels#qr-code-trust-score) |
| `security.transparencyLogVerified` | boolean | `true` when the code's issuance-log entry links to the previous entry's hash (or is the first entry) |
| `security.algVersion` | string | The row's `alg_version`, e.g. `hybrid-ecdsa-slhdsa-v1` |
| `security.algVersionStatus` | string | `accepted` or `deprecated` (rejected and unknown versions fail early, see below). `hybrid-ecdsa-slhdsa-v1` is the only accepted version |
| `security.merkleProofValid` | boolean | Result of the Merkle/SLH-DSA leg |
| `security.merkleBatchId` | string \| null | The signed batch the row belongs to |
| `security.pqcProtected` | boolean | `true` when the row is `hybrid-ecdsa-slhdsa-v1` and its Merkle/SLH-DSA leg verified |
| `warnings` | array | Operator advisories. Entries with code `ALG_DEPRECATED` (with `sunsetDate`) appear when the row's `alg_version` is deprecated; empty today |
| `location_match` | object | Always present. `matched` and `distanceM` are populated when the code has a registered location and the request supplied `clientLat`/`clientLng`; otherwise `matched: false`, `distanceM: null`. Coordinates are client-supplied |
| `location_match.registeredAddress` | string \| null | The code's stored geohash, or `null` when the code has no location |
| `domain_warning` | object | Present only when the destination URL resembles a domain verified by another organization: `{ message, similar_to, verified_org, similarity }` (`similarity` 0–100). Lowers `trustScore` by 30 |
| `scannedAt` | string | ISO 8601 time of the request |

Additional fields may appear in the response for SDK compatibility. Ignore fields not documented here.

### Failure responses (200)

Revoked, expired and scan-limited codes, codes with a rejected or unknown `alg_version`, and codes that fail the MAC pre-filter return HTTP 200 with `verified: false`, a `reason` string, and the security fields zeroed:

```json
{
  "verified": false,
  "reason": "This QR code has been revoked by its issuer.",
  "organization": { "id": "clx...", "name": "Acme Corp", "slug": "acme-corp", "trustLevel": "BUSINESS", "kycStatus": "VERIFIED", "domainVerified": true },
  "destination_url": "https://example.com/product",
  "location_match": { "matched": false, "distanceM": null, "registeredAddress": null },
  "security": {
    "signatureValid": false,
    "trustScore": 0,
    "transparencyLogVerified": false
  },
  "scannedAt": "2026-04-10T12:05:00.000Z"
}
```

| Case | `reason` |
|------|----------|
| Revoked | `This QR code has been revoked by its issuer.` |
| Expired | `This QR code has expired.` |
| Total scan limit reached | `This QR code has reached its maximum number of scans.` |
| Per-device scan limit reached | `This QR code has reached its scan limit for this device.` |
| Rejected `alg_version` (e.g. `ecdsa-p256-sha256-v1`) | `This QR code uses a cryptographic algorithm that is no longer supported.` |
| Unknown `alg_version` | `This QR code uses an unrecognized cryptographic algorithm.` |
| MAC pre-filter mismatch | `This QR code failed signature verification.` |

Other failures use the full response shape above with `verified: false`: a failed signature leg (`security.signatureValid: false`), a geo-fence block (`reason` `GEO_PROXIMITY_REQUIRED` or `GEO_OUT_OF_FENCE`), or a trust score of 20 or below (`reason` `QR code has a critically low trust score due to detected fraud.`).

### Not found (404)

```json
{
  "statusCode": 404,
  "error": "Not Found",
  "message": "QR code \"abc123\" not found."
}
```
