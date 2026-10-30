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
> `qr_image_url` is a self-contained `data:image/png;base64,…` URL generated on our infrastructure: a 300×300 PNG of the code drawn with its stored style (colours, the QRAuth logo or the organization's own [logo](./logos)), with a 4-module quiet zone. A code wider than 100 modules (a very long encoded URL) is drawn larger, at 3 pixels per module. For other sizes or SVG, use [Get QR Code Image](#get-qr-code-image).

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

**Response (200):** Full QR code object (same shape as create response, plus `scanCount` and `lastScannedAt`). `verification_url` is the URL the code encodes, as in the create response.

---

## Get QR Code Image

`GET /api/v1/qrcodes/:token/image`

**Headers:** `X-API-Key: <key>`

Returns the code drawn with its stored style, as PNG, SVG or a vector PDF. The image encodes the code's verification URL, the same one as in `verification_url`. A style with one of the organization's [logos](./logos) draws it; the SVG and PDF embed the logo, so they need no other file. A style with a [frame](#frames) draws it around the code, with the text as vector outlines (no fonts needed to view the SVG or PDF); sizes are then the width of the framed image, and the height follows.

There are two ways to size an image, and they cannot be combined:

- **Screen size:** `px`, the width in pixels, for PNG and SVG.
- **Print size:** `size_mm` (or `size_in`), the width of the whole artwork (code, quiet zone and frame), with `dpi` for PNG and `margin_mm` for PDF.

**Query parameters:**

| Param | Type | Description |
|-------|------|-------------|
| `format` | string | `png` (default), `svg` or `pdf` |
| `px` | number | Screen width in pixels, 64–1024. Default 300 for PNG; SVG without a size is scalable. A width below 3 pixels per module (quiet zone included) is raised to that minimum. Not with `pdf` or the print parameters |
| `size_mm` | number | Print width in mm, 10–1000, kept to 0.1 mm. PNG: the pixel width is `round(size_mm / 25.4 × dpi)`. PDF: the page is this width plus the margin. SVG: written as `width`/`height` in mm. Default 50 for `pdf`, and for PNG when only `dpi` is given |
| `size_in` | number | Print width in inches, 0.4–39.37, converted to mm (to 0.1 mm). Instead of `size_mm` |
| `dpi` | integer | PNG resolution for a print size, 72–1200. Default 300. Written to the PNG's `pHYs` chunk. PNG only |
| `margin_mm` | number | PDF only: blank space on every side of the page, 0–50 mm. Default 0 |
| `download` | string | `1` to send `Content-Disposition: attachment` (default `inline`) |

**Print limits:**

- Every module must print at least **0.4 mm** wide. A smaller size returns `422` with `code` `print-size-too-small` and a message giving the smallest width for this code (about 15 to 18 mm for a typical code). A print PNG must also have at least 3 pixels per module; the message then gives the lowest `dpi` for that size.
- A print PNG is at most **12,000 pixels per side** and **100 megapixels**: 846.6 mm at 300 dpi, 423.3 mm at 600 dpi or 211.6 mm at 1200 dpi for a square code (less with a frame, which makes the image taller). A larger request returns `400` with `code` `print-raster-too-large` and a message giving the largest width at that `dpi`. PDF and SVG are vector and have no pixel limit.
- Print-size PNG (`size_mm`, `size_in` or `dpi`) and PDF are included in paid plans. On the Free plan they return `403`; Free keeps SVG (also at a print size) and PNG up to 1024 pixels.

**Response (200):** the image, `Content-Type: image/png`, `image/svg+xml` or `application/pdf`, with `X-Content-Type-Options: nosniff`.

- The PDF is vector: the code, the frame and its text are paths in the code's colours (sRGB); only a logo is embedded as an image. Its page is the artwork plus the margin, and its metadata names QRAuth (with the renderer version) as producer and creator, and the token in the title.
- `ETag` identifies the exact image, size and format included; equal requests give byte-identical files, PDF included. Send it back in `If-None-Match` to get `304 Not Modified` when nothing changed. Responses are `Cache-Control: private, no-cache`. A `badge` frame's wording depends on the organization's verification (see [Frames](#frames)), so a change in verification changes the image and its `ETag`.
- `X-QRAuth-Image-Px` gives the PNG width actually rendered (and the SVG width with `px`).
- File names: `qrauth-{token}-{px}px.png` (or `.svg`) for screen sizes, `qrauth-{token}-{size}mm-{dpi}dpi.png` for a print PNG, and `qrauth-{token}-{size}mm.pdf` (or `.svg`) for a PDF or an SVG at a print size. A size given in inches is named by its mm value.
- A token that does not exist or belongs to another organization returns `404`. Unknown query parameters, values outside the ranges above and combinations that mean nothing (`px` with a print size, `size_mm` with `size_in`, `dpi` without PNG, `margin_mm` without PDF) return `400`.
- When rendering is busy, `503` with `Retry-After`.
- Rate limit: 60 requests per minute per organization.

```bash
curl -H "X-API-Key: $QRAUTH_API_KEY" \
  "https://qrauth.io/api/v1/qrcodes/abc123/image?format=png&px=600" -o code.png

# 50 mm at 300 dpi for print (591 x 591 px), and a 50 mm vector PDF with a 3 mm margin
curl -H "X-API-Key: $QRAUTH_API_KEY" \
  "https://qrauth.io/api/v1/qrcodes/abc123/image?format=png&size_mm=50&dpi=300" -o code-50mm.png
curl -H "X-API-Key: $QRAUTH_API_KEY" \
  "https://qrauth.io/api/v1/qrcodes/abc123/image?format=pdf&size_mm=50&margin_mm=3" -o code-50mm.pdf
```

---

## Update QR Code

`PATCH /api/v1/qrcodes/:token`

**Headers:** `X-API-Key: <key>`

**Request body:** Any subset of `label`, `content`, `location`, `expiresAt`, `qrStyle`. Updating `content` re-signs the code automatically. A style that draws one of the organization's [logos](./logos#using-a-logo-in-a-code-s-style) or a [frame](#frames) has its own rules and errors. Leave `qrStyle` out to keep the stored style unchanged. A `qrStyle` equal to the stored one (same values, in any key order) is accepted without the plan and logo checks, so resending a code's unchanged version 2 style always works. `qrStyle` must be a version 2 style (`"version": 2`); the earlier shape without `version` (`templateId`, `fgColor`, `bgColor`, `showLogo`, `captionText`) returns `400`. Codes styled before version 2 still render, and [Get QR Code](#get-qr-code) may return their `style` in the earlier shape; send it back as version 2.

**Response (200):** Updated QR code object.

### Frames

A style can draw a frame with a call to action around the code. Frames sit outside the code's quiet zone, so they never affect scanning:

```json
{ "frame": { "template": "banner-bottom", "text": "Scan me", "color": "#000000", "textColor": "#FFFFFF" } }
```

| `template` | Drawn as |
|------------|----------|
| `none` | No frame (the same as leaving `frame` out) |
| `caption` | The text below the code, in `textColor` on the code's background (`color` is not used) |
| `banner-bottom`, `banner-top` | A frame in `color` with a bar below or above the code holding the text |
| `rounded-label` | A border in `color` with a tab above the code holding the text |
| `badge` | A frame in `color` with the text and a QRAuth mark below the code: "Verified by QRAuth" when the organization is verified (verified domain or completed verification), "Signed with QRAuth" otherwise |

- `text` is one line of up to 40 characters. Latin (including accented letters), Greek and Cyrillic letters, digits and common punctuation are supported; the text is drawn with a bundled font and shrinks to fit.
- The badge's mark follows the organization's verification when the image is drawn: the image endpoint, `qr_image_url` and exports show "Verified by QRAuth" once the domain is verified or verification is completed, and "Signed with QRAuth" before that. The stored style does not change.
- Frames are included in paid plans. On the Free plan, saving a style with a frame other than `none` returns `403`. A code keeps its stored frame after a move to the Free plan.
- A code whose stored frame is a `caption` (including the `captionText` of older styles) keeps it on the Free plan, and its caption text can still be edited: send the same `caption` template and colours with new `text`. Changing the template or colours returns `403`; removing the frame (`none`, or leaving `frame` out) is allowed.

| Status | `code` | When |
|--------|--------|------|
| `403` | — | The plan does not include frames (Free), or a Free plan changes a stored caption's template or colours |
| `422` | `frame-contrast-too-low` | The text is below 4.5:1 contrast against the frame colour (against the background for `caption`), or the frame colour is below 3:1 against the background |
| `422` | `frame-glyph-unsupported` | The text has a character the font cannot draw: "This character is not supported in frame text yet" |
| `400` | — | The text is longer than 40 characters, or has a line break, control or bidirectional-control character |

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
| `items` | array | Yes | 1–64 URL code items. |

Bulk create makes URL codes only. Each item takes the URL fields of single create: `destinationUrl` (required), `label`, `location`, `expiresAt`, `maxScans`, `maxScansPerDevice` and `scanMode`. To create a `vcard`, `coupon`, `event`, `pdf` or `feedback` code, use [Create QR Code](#create-qr-code) once per code.

The whole request is validated before any item is processed. If any item is invalid, including an item that carries `contentType` or `content`, the response is `400` with the standard validation body, and no code is created. `details[].path` names the item, for example `["body", "items", "1", "contentType"]` with the message `bulk supports URL codes only`.

Bulk codes use the default style. An item that carries `qrStyle` is refused the same way, with the message `bulk does not accept qrStyle; set a style per code with PATCH`. To style a code, send `qrStyle` with [Update QR Code](#update-qr-code) after it is created.

**Response (207):**

```json
{
  "results": [
    { "index": 0, "success": true, "label": "Shelf 4B", "data": { "token": "abc123", "verification_url": "https://qrauth.io/v/abc123", "...": "same fields as single create" } },
    { "index": 1, "success": false, "label": "Shelf 4C", "error": "...", "errorCode": "DESTINATION_FLAGGED", "threatTypes": ["SOCIAL_ENGINEERING"] }
  ],
  "summary": { "total": 2, "succeeded": 1, "failed": 1 }
}
```

Items that pass validation but cannot be created are reported in `results` with `success: false`, an `error` message and an `errorCode`, rather than failing the whole batch:

| `errorCode` | Meaning |
|-------------|---------|
| `DESTINATION_FLAGGED` | The destination is on a threat list. `threatTypes` lists the matches. |
| `RENDER_UNAVAILABLE` | The QR image could not be rendered. The item was not stored; retry it. |
| `QUOTA_EXCEEDED` | The organization's QR code limit was reached. |
| `RATE_LIMIT` | The item was rate limited. |
| `VALIDATION_ERROR` | The item was rejected while it was being created. |
| `INTERNAL_ERROR` | Any other failure. |
