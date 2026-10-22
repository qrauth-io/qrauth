---
title: QR Codes
description: Create, manage, and revoke cryptographically signed QR codes.
---

# QR Codes

QR codes are the core resource of QRAuth. Every code is issued with a hybrid signature (`alg_version` `hybrid-ecdsa-slhdsa-v1`): an ECDSA-P256 signature over the canonical core `algVersion|token|tenantId|destHash|geoHash|expiresAt`, where `destHash` is the SHA3-256 of the destination URL or, for other content types, of the canonical content; and a leaf in a Merkle batch whose root is signed with SLH-DSA-SHA2-128s (post-quantum, FIPS 205). Each QR code stores its individual Merkle proof alongside the ECDSA signature. Verification via `GET /v/:token` requires both legs to pass for hybrid rows. See [Signing Architecture](/guide/signing-architecture).

## Content Types

| Value | Description |
|-------|-------------|
| `url` | Simple redirect URL |
| `vcard` | Contact card (name, phone, email, address) |
| `coupon` | Discount code with terms and expiry |
| `event` | Event details with date, location, ticket link |
| `pdf` | Hosted PDF asset |
| `feedback` | Survey / feedback form |

All content types, `vcard` and `event` included, encode the signed `/v/:token` URL in the QR image. The verification page then delivers the content, for example the native contact or calendar import, together with the Trust Reveal.

---

## Create QR Code

`POST /api/v1/qrcodes`

**Headers:** `X-API-Key: <key>`

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `label` | string | Yes | Human-readable name shown in the dashboard |
| `contentType` | string | Yes | One of the content type values above |
| `content` | object | Yes | Content payload — schema depends on `contentType` |
| `destinationUrl` | string | No | Override redirect URL (for `url` type this is set inside `content`) |
| `location` | object | No | `{ lat, lng, radiusM }` — enables proximity verification |
| `expiresAt` | string | No | ISO 8601 expiry datetime. Omit for no expiry. |

**`content` schema by type:**

::: code-group

```json [url]
{
  "url": "https://example.com/product"
}
```

```json [vcard]
{
  "firstName": "Jane",
  "lastName": "Doe",
  "email": "jane@example.com",
  "phone": "+1-555-0100",
  "organization": "Acme Corp",
  "url": "https://example.com"
}
```

```json [coupon]
{
  "code": "SAVE20",
  "discount": "20%",
  "terms": "Valid on orders over €50",
  "expiresAt": "2026-12-31T23:59:59Z"
}
```

```json [event]
{
  "title": "Annual Conference",
  "startDate": "2026-09-15T09:00:00Z",
  "endDate": "2026-09-15T18:00:00Z",
  "location": "Berlin, Germany",
  "url": "https://conference.example.com"
}
```

```json [pdf]
{
  "title": "Product Datasheet",
  "assetId": "asset_01HXYZ..."
}
```

```json [feedback]
{
  "title": "How was your experience?",
  "questions": ["Overall rating", "Comments"]
}
```

:::

**Response (201):**

```json
{
  "token": "abc123",
  "verification_url": "https://qrauth.io/v/abc123",
  "qr_image_url": "data:image/png;base64,iVBORw0KGgoAAAANSUh...",
  "signature": "MEUCIQD...",
  "organization_id": "clx...",
  "label": "Product A — Shelf 4B",
  "created_at": "2026-04-10T12:00:00.000Z",
  "expires_at": null,
  "transparency_log_index": 1042,
  "alg_version": "hybrid-ecdsa-slhdsa-v1",
  "merkle_batch_id": "..."
}
```

> `signature` is the ECDSA-P256 leg, DER-encoded and base64. `merkle_batch_id` identifies the signed Merkle batch. `transparency_log_index` is the code's position in the hash-chained issuance log. When the destination resembles a domain verified by another organization, the response also includes `domain_warnings` (`similar_to`, `verified_org`, `similarity`, `reason`).
>
> `qr_image_url` is a self-contained `data:image/png;base64,…` URL generated on our infrastructure. It previously pointed at a third-party host (`api.qrserver.com`); the field name and `string` type are unchanged.

---

## List QR Codes

`GET /api/v1/qrcodes`

**Headers:** `X-API-Key: <key>`

**Query parameters:**

| Param | Type | Description |
|-------|------|-------------|
| `page` | number | Page number (default: 1) |
| `limit` | number | Results per page (default: 20, max: 100) |
| `status` | string | Filter by `active`, `expired`, or `revoked` |
| `contentType` | string | Filter by content type |
| `search` | string | Full-text search on label |

**Response (200):**

```json
{
  "data": [
    {
      "id": "qr_01HXYZ...",
      "token": "abc123",
      "label": "Product A — Shelf 4B",
      "contentType": "url",
      "status": "active",
      "scanCount": 42,
      "createdAt": "2026-04-10T12:00:00Z"
    }
  ],
  "pagination": {
    "page": 1,
    "limit": 20,
    "total": 142,
    "totalPages": 8
  }
}
```

---

## Get QR Code

`GET /api/v1/qrcodes/:token`

**Headers:** `X-API-Key: <key>`

**Response (200):** Full QR code object (same shape as create response, plus `scanCount` and `lastScannedAt`).

---

## Update QR Code

`PATCH /api/v1/qrcodes/:token`

**Headers:** `X-API-Key: <key>`

**Request body:** Any subset of `label`, `content`, `location`, `expiresAt`. Updating `content` re-signs the code automatically.

**Response (200):** Updated QR code object.

---

## Revoke QR Code

`DELETE /api/v1/qrcodes/:token`

**Headers:** `X-API-Key: <key>`

Sets the QR code status to `revoked`. Subsequent scans return a revoked-state verification page. This action is irreversible.

**Response (204):** No content.

---

## Bulk Create

`POST /api/v1/qrcodes/bulk`

**Headers:** `X-API-Key: <key>`

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `items` | array | Yes | Array of create payloads (same schema as single create). 1–64 items. |

**Response (207):**

```json
{
  "results": [
    { "index": 0, "success": true, "label": "Shelf 4B", "data": { "token": "abc123", "verification_url": "https://qrauth.io/v/abc123", "...": "same fields as single create" } },
    { "index": 1, "success": false, "label": "Shelf 4C", "error": "...", "errorCode": "VALIDATION_ERROR" }
  ],
  "summary": { "total": 2, "succeeded": 1, "failed": 1 }
}
```

If individual items fail they are reported in `results` with `success: false`, an `error` message and an `errorCode` (`QUOTA_EXCEEDED`, `RATE_LIMIT`, `VALIDATION_ERROR`, `INTERNAL_ERROR`) rather than failing the whole batch.
