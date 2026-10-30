---
title: Verification
description: Verify a QR code scan — HTML page for browsers, JSON for programmatic consumers.
---

# Verification

When a device scans a QRAuth code it is directed to the verification endpoint. The response format is determined by content negotiation.

## Verify QR Code

`GET /v/:token` (also served as `GET /api/v1/verify/:token`)

`/v/:token` lives outside the `/api/v1` prefix because it handles browser navigation directly. No authentication header is required — verification is always public.

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

When accessed from a browser (no `Accept: application/json` header) the endpoint returns the verification page described in [Trust Reveal](/guide/trust-reveal).

## Trust state

Every JSON response carries a `trust_state`. Integrations should branch on it.

| `trust_state` | Meaning | When |
|---|---|---|
| `VERIFIED` | Authentic code from an issuer QRAuth has verified | The signatures verify, the code is active and within its scan limits, its `alg_version` is accepted, the trust score is above 20, no geo-fence block applies, the destination is not flagged and does not resemble another organization's verified domain, **and** the issuer is verified (verified domain or approved KYC — see [Issuer verification](/guide/trust-levels#issuer-verification)) |
| `SIGNED_UNVERIFIED_ISSUER` | Authentic code; QRAuth has not verified who issued it | All of the checks above pass, but the issuer has neither a verified domain nor approved KYC |
| `UNTRUSTED` | Do not trust this code | Anything else: invalid signature, revoked, expired, scan limit reached, rejected or unknown `alg_version`, geo-fence block, trust score of 20 or below, a destination that resembles another organization's verified domain, a destination flagged as dangerous, or a suspended issuer |

`verified` is `true` exactly when `trust_state` is `VERIFIED`. It is kept for compatibility; new integrations should switch on `trust_state`.

`organization` names the issuer only in `VERIFIED` responses: `{ "verified": true, "name": "…", "verified_domain": "…" }`, where `verified_domain` is present when the issuer has a verified domain. In every other response it is `{ "verified": false }`.

## JSON responses (200)

### `VERIFIED`

```json
{
  "verified": true,
  "trust_state": "VERIFIED",
  "organization": {
    "verified": true,
    "name": "Acme Wire Ltd",
    "verified_domain": "acme-wire.example"
  },
  "destination_url": "https://acme-wire.example/pay",
  "security": {
    "signatureValid": true,
    "proxyDetected": false,
    "trustScore": 100,
    "transparencyLogVerified": true,
    "algVersion": "hybrid-ecdsa-slhdsa-v1",
    "algVersionStatus": "accepted",
    "pqcProtected": true,
    "merkleProofValid": true,
    "merkleBatchId": "66bf5be9628fb36a774adcc6dbad8608"
  },
  "warnings": [],
  "location_match": {
    "matched": false,
    "distanceM": null,
    "registeredAddress": null
  },
  "scannedAt": "2026-10-27T15:16:47.703Z"
}
```

### `SIGNED_UNVERIFIED_ISSUER`

```json
{
  "verified": false,
  "trust_state": "SIGNED_UNVERIFIED_ISSUER",
  "organization": {
    "verified": false
  },
  "destination_url": "https://example.com/pay",
  "security": {
    "signatureValid": true,
    "proxyDetected": false,
    "trustScore": 100,
    "transparencyLogVerified": true,
    "algVersion": "hybrid-ecdsa-slhdsa-v1",
    "algVersionStatus": "accepted",
    "pqcProtected": true,
    "merkleProofValid": true,
    "merkleBatchId": "0b60fd0fc00af28e9377acc9e4194bbb"
  },
  "warnings": [],
  "location_match": {
    "matched": false,
    "distanceM": null,
    "registeredAddress": null
  },
  "scannedAt": "2026-10-27T15:16:47.739Z"
}
```

### `UNTRUSTED` — destination resembles a verified domain

```json
{
  "verified": false,
  "trust_state": "UNTRUSTED",
  "domain_warning": {
    "message": "This URL looks similar to \"acme-wire.example\" which belongs to verified organization \"Acme Wire Ltd\". Proceed with caution.",
    "similar_to": "acme-wire.example",
    "verified_org": "Acme Wire Ltd",
    "similarity": 95
  },
  "organization": {
    "verified": false
  },
  "destination_url": "https://acme-wlre.example/login",
  "security": {
    "signatureValid": true,
    "proxyDetected": false,
    "trustScore": 50,
    "transparencyLogVerified": true,
    "algVersion": "hybrid-ecdsa-slhdsa-v1",
    "algVersionStatus": "accepted",
    "pqcProtected": true,
    "merkleProofValid": true,
    "merkleBatchId": "819b3c178d1e7348476764508f5b8181"
  },
  "warnings": [],
  "location_match": {
    "matched": false,
    "distanceM": null,
    "registeredAddress": null
  },
  "scannedAt": "2026-10-27T15:16:47.781Z"
}
```

### `UNTRUSTED` — revoked

Responses that fail before the signature check use a shorter shape: `reason` is set, `destination_url` and `warnings` are absent, and the security fields are zeroed.

```json
{
  "verified": false,
  "trust_state": "UNTRUSTED",
  "reason": "This QR code has been revoked by its issuer.",
  "organization": {
    "verified": false
  },
  "location_match": {
    "matched": false,
    "distanceM": null,
    "registeredAddress": null
  },
  "security": {
    "signatureValid": false,
    "proxyDetected": false,
    "trustScore": 0,
    "transparencyLogVerified": false
  },
  "scannedAt": "2026-10-27T15:16:47.816Z"
}
```

### `UNTRUSTED` — destination flagged as dangerous

```json
{
  "verified": false,
  "trust_state": "UNTRUSTED",
  "reason": "This code points to a site flagged as dangerous.",
  "organization": {
    "verified": false
  },
  "location_match": {
    "matched": false,
    "distanceM": null,
    "registeredAddress": null
  },
  "security": {
    "signatureValid": false,
    "proxyDetected": false,
    "trustScore": 0,
    "transparencyLogVerified": false
  },
  "scannedAt": "2026-10-27T15:16:47.820Z"
}
```

### Response fields

| Field | Type | Description |
|-------|------|-------------|
| `trust_state` | string | `VERIFIED` \| `SIGNED_UNVERIFIED_ISSUER` \| `UNTRUSTED`. See [Trust state](#trust-state) |
| `verified` | boolean | `true` only when `trust_state` is `VERIFIED` |
| `reason` | string | Present on the short failure responses (see [Failure responses](#failure-responses)), on geo-fence blocks (`GEO_PROXIMITY_REQUIRED`, `GEO_OUT_OF_FENCE`) and on a trust score of 20 or below (`QR code has a critically low trust score due to detected fraud.`). Absent otherwise, including when the only failure is `security.signatureValid: false` or a `domain_warning` |
| `organization` | object | `{ verified: true, name, verified_domain? }` when `trust_state` is `VERIFIED`; `{ verified: false }` otherwise |
| `destination_url` | string | The code's destination URL. Absent from the short failure responses; present otherwise (also when `trust_state` is `UNTRUSTED` because of a failed signature leg, a geo-fence block, a low trust score or a `domain_warning`) |
| `security.signatureValid` | boolean | `true` when the ECDSA-P256 signature verifies and, for hybrid rows, the Merkle leaf recomputed from the code's canonical data and stored nonce verifies, through its inclusion proof, against an SLH-DSA-SHA2-128s-signed batch root. A hybrid row without complete Merkle data fails |
| `security.proxyDetected` | boolean | Always `false` in current responses |
| `security.trustScore` | number | 0–100. Starts at 100; deductions for unresolved fraud incidents (once per incident type, by severity) and recent scan velocity, clamped to 30–100; then −30 (floor 0) if the destination resembles another organization's verified domain. See [Trust Levels](/guide/trust-levels#qr-code-trust-score) |
| `security.transparencyLogVerified` | boolean | `true` when the code's issuance-log entry links to the previous entry's hash (or is the first entry) |
| `security.algVersion` | string | The row's `alg_version`, e.g. `hybrid-ecdsa-slhdsa-v1`. Absent from the short failure responses |
| `security.algVersionStatus` | string | `accepted` or `deprecated` (rejected and unknown versions fail early, see below). `hybrid-ecdsa-slhdsa-v1` is the only accepted version |
| `security.merkleProofValid` | boolean | Result of the Merkle/SLH-DSA leg |
| `security.merkleBatchId` | string \| null | The signed batch the row belongs to |
| `security.pqcProtected` | boolean | `true` when the row is `hybrid-ecdsa-slhdsa-v1` and its Merkle/SLH-DSA leg verified |
| `warnings` | array | Operator advisories. Entries with code `ALG_DEPRECATED` (with `sunsetDate`) appear when the row's `alg_version` is deprecated; empty today. Absent from the short failure responses |
| `location_match` | object | Always present. `matched` and `distanceM` are populated when the code has a registered location and the request supplied `clientLat`/`clientLng`; otherwise `matched: false`, `distanceM: null`. Coordinates are client-supplied |
| `location_match.registeredAddress` | string \| null | The code's stored geohash, or `null` when the code has no location |
| `domain_warning` | object | Present only when the destination URL resembles a domain verified by another organization: `{ message, similar_to, verified_org, similarity }` (`similarity` 0–100). Lowers `trustScore` by 30 and makes the response `UNTRUSTED` |
| `scannedAt` | string | ISO 8601 time of the request |

Additional fields may appear in the response for SDK compatibility. Ignore fields not documented here.

### Failure responses

These cases return HTTP 200 with `trust_state: "UNTRUSTED"`, `verified: false`, a `reason`, `organization: { "verified": false }`, no `destination_url`, and the security fields zeroed (see the revoked example above):

| Case | `reason` |
|------|----------|
| Issuer organization suspended | `This code has been disabled.` |
| Destination flagged as dangerous | `This code points to a site flagged as dangerous.` |
| Revoked | `This QR code has been revoked by its issuer.` |
| Expired | `This QR code has expired.` |
| Total scan limit reached | `This QR code has reached its maximum number of scans.` |
| Per-device scan limit reached | `This QR code has reached its scan limit for this device.` |
| Rejected `alg_version` (e.g. `ecdsa-p256-sha256-v1`) | `This QR code uses a cryptographic algorithm that is no longer supported.` |
| Unknown `alg_version` | `This QR code uses an unrecognized cryptographic algorithm.` |
| MAC pre-filter mismatch | `This QR code failed signature verification.` |

The cases are checked in the order listed: a revoked code of a suspended organization reports the suspension.

Other `UNTRUSTED` results use the full response shape: a failed signature leg (`security.signatureValid: false`), a geo-fence block (`reason` `GEO_PROXIMITY_REQUIRED` or `GEO_OUT_OF_FENCE`), a trust score of 20 or below, or a `domain_warning`.

### Not found (404)

```json
{
  "statusCode": 404,
  "error": "Not Found",
  "message": "QR code \"abc123\" not found."
}
```

## Report a code

`POST /v/:token/report`

Every verification page links to a report form. The form posts here; API clients can send JSON.

**Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `reason` | string | Yes | `phishing` \| `malware` \| `impersonation` \| `spam` \| `other` |
| `comment` | string | No | Up to 500 characters |
| `reporterEmail` | string | No | Contact address for follow-up |

**Response (202):**

```json
{ "status": "received" }
```

The response is the same whether or not the token exists. Requests are limited to 10 per hour per network. A missing or invalid `reason`, a comment over 500 characters, or an invalid email returns 400.
