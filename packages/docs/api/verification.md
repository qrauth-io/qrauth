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

### Browser response

When accessed from a browser (no `Accept: application/json` header) the endpoint returns the full-screen Trust Reveal page — an animated verification with visual fingerprint, trust score, and fraud signals displayed to the end user.

### JSON response (200)

```json
{
  "verified": true,
  "token": "abc123",
  "organization": {
    "name": "Acme Corp",
    "verified": true
  },
  "qrCode": {
    "id": "qr_01HXYZ...",
    "label": "Product A — Shelf 4B",
    "contentType": "url",
    "content": { "url": "https://example.com/product" }
  },
  "security": {
    "signatureValid": true,
    "trustScore": 0.94,
    "proxyDetected": false,
    "botScore": 0.02,
    "signals": []
  },
  "location_match": {
    "checked": true,
    "matched": true,
    "distanceM": 14,
    "radiusM": 50
  },
  "domain_warning": null,
  "scannedAt": "2026-04-10T12:05:00Z"
}
```

### Response fields

| Field | Type | Description |
|-------|------|-------------|
| `verified` | boolean | `true` if the signature is valid and the code is active |
| `organization.verified` | boolean | Whether the org has completed identity verification |
| `security.signatureValid` | boolean | `true` when both the ECDSA-P256 and SLH-DSA-SHA2-128s signatures verify successfully. Either leg failing sets this to `false`. |
| `security.trustScore` | number | 0–1 composite trust score from all fraud signals |
| `security.proxyDetected` | boolean | IP is a known proxy or VPN exit node |
| `security.botScore` | number | 0–1 probability the request originates from automation |
| `security.signals` | array | List of triggered fraud signal names (empty when clean) |
| `location_match` | object \| null | Present only when QR has a registered location and GPS was provided |
| `location_match.matched` | boolean | Scanner is within `radiusM` of the QR's registered location |
| `location_match.distanceM` | number | Measured distance in metres |
| `domain_warning` | string \| null | Set if the serving domain looks similar to a known brand (typosquat signal) |

### Revoked / expired codes (200)

Revoked or expired codes still return HTTP 200 but with `verified: false` and an appropriate status field:

```json
{
  "verified": false,
  "status": "revoked",
  "revokedAt": "2026-03-01T10:00:00Z"
}
```

### Not found (404)

```json
{
  "statusCode": 404,
  "error": "Not Found",
  "message": "QR code not found"
}
```
