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
| `app-link` | Smart link to an app: App Store, Google Play and a website, chosen by the scanner's device |
| `link-list` | A titled list of up to 20 links |

All content types, `vcard` and `event` included, encode the signed `/v/:token` URL in the QR image. The verification page then delivers the content, for example the native contact or calendar import, together with the Trust Reveal.

`url` and `vcard` are included in every plan. The other types need a paid plan: on the Free plan, creating one, or changing the content of an existing one, answers `403`. See [Smart link and link list](#smart-link-and-link-list) for how those two types are screened and shown.

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
| `destinationUrl` | string | No | Override redirect URL (for `url` type this is set inside `content`). http(s) with a public host name: IP addresses, `localhost`, single-label names and `.local`, `.internal` and `.home.arpa` names are refused (`400`). |
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

```json [app-link]
{
  "iosUrl": "https://apps.apple.com/app/id000000000",
  "androidUrl": "https://play.google.com/store/apps/details?id=com.example.app",
  "fallbackUrl": "https://example.com/app"
}
```

```json [link-list]
{
  "title": "Example Bistro",
  "description": "Menu, bookings and opening hours",
  "links": [
    { "label": "Menu", "url": "https://example.com/menu" },
    { "label": "Book a table", "url": "https://bookings.example.com/bistro" }
  ]
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

> `signature` is the ECDSA-P256 leg, DER-encoded and base64. `merkle_batch_id` identifies the signed Merkle batch. `transparency_log_index` is the code's position in the hash-chained issuance log. When the destination resembles a domain verified by another organization, the response also includes `domain_warnings` (`similar_to`, `verified_org`, `similarity`, `reason`). For `app-link` and `link-list` codes every link is checked, and each warning also names its `url`.
>
> `qr_image_url` is a self-contained `data:image/png;base64,…` URL generated on our infrastructure: a 300×300 PNG of the code drawn with its stored style (colours, the QRAuth logo or the organization's own [logo](./logos)), with a 4-module quiet zone. A code wider than 100 modules (a very long encoded URL) is drawn larger, at 3 pixels per module. For other sizes or SVG, use [Get QR Code Image](#get-qr-code-image).

---

## Smart link and link list

Two content types hold outbound links instead of a single destination. Their QR code encodes the `/v/:token` verification page, like every other non-URL type, and the links are part of the signed content.

### Content rules

| Type | Field | Rule |
|------|-------|------|
| `app-link` | `iosUrl`, `androidUrl`, `fallbackUrl` | Required. Absolute `https` URLs, up to 2048 characters, without a user name or password, with a public host name (no IP address, `localhost`, single-label or private network name). |
| `link-list` | `title` | Required, 1–60 characters. |
| `link-list` | `description` | Optional, up to 200 characters. |
| `link-list` | `links` | 1–20 entries of `{ "label", "url" }`: `label` 1–40 characters, `url` as above. |

Any other scheme, including `http:`, `javascript:`, `data:` and `intent:`, is refused, as are unknown fields. URLs may not contain spaces or control characters, and are stored in normalized form (lowercase scheme and host, punycode, default port dropped), as are destinations of URL codes. Titles, descriptions and labels may not contain control characters or text-direction overrides. A refused payload answers `400` with the field in the message, for example `links.2.url: Must be an absolute https URL without a user name or password`. Text is stored as given and always shown as text: HTML in a title or label is displayed, never interpreted.

### Screening

Every link is screened like a URL code's destination:

- **Create and content changes.** Each link is checked with Google Web Risk. A listed link refuses the request with `422`; the body names the link:

  ```json
  {
    "statusCode": 422,
    "error": "DestinationFlagged",
    "message": "A link in this content (https://listed.example/) is listed as dangerous by Google Web Risk and cannot be used.",
    "threatType": "SOCIAL_ENGINEERING",
    "threatTypes": ["SOCIAL_ENGINEERING"],
    "url": "https://listed.example/"
  }
  ```

  If a link cannot be screened right now, the request answers `503` with `Retry-After` and nothing is stored or changed, so no link goes live unscreened. A save that resends the stored content unchanged (for example a label edit from the dashboard) is not screened again.
- **Daily re-scan.** Links of active codes are screened again every day. A link that becomes listed is hidden on the verification page with a note saying it was removed; the other links keep working, and the organization's owners are emailed once. Removing the link, or replacing it with one that screens clean, clears the note.
- **Lookalike check.** Each link is compared with the domains of verified organizations. A link that resembles one makes the scan `UNTRUSTED`: the page warns the scanner and marks that link.

### On the verification page

Links are shown after the Trust Reveal. They open with `rel="noopener noreferrer nofollow"`.

- **`app-link`** detects the scanner's platform from the browser's User-Agent: iPhone, iPad and iPod get `iosUrl`, Android gets `androidUrl`, every other device gets `fallbackUrl`. With scan mode `FLASH`, a `VERIFIED` scan continues to that link after the short trust confirmation. Otherwise the page lists the three choices, the scanner's platform first. A scan never continues to a link that is hidden, and never continues for an unverified issuer, an `UNTRUSTED` scan or a code with a location. An iPad set to request desktop websites reports itself as a Mac and gets `fallbackUrl`; the App Store link is still listed.
- **`link-list`** always shows the page and never continues on its own, whatever the scan mode.

The JSON response of `GET /v/:token` keeps the verification page as `destination_url` for both types, and reports `scan_mode` `PAGE`.

Bulk create does not accept these types; create them one at a time. `destinationUrl` cannot be set on them with [Update QR Code](#update-qr-code) (`400`); change the links in `content` instead.

---

## List QR Codes

`GET /api/v1/qrcodes`

**Headers:** `X-API-Key: <key>`

Returns the organization's codes, newest first. The search and filter parameters combine: a code is returned when it matches all of them. Every role can list codes.

**Query parameters:**

| Param | Type | Description |
|-------|------|-------------|
| `page` | number | Page number (default: 1) |
| `pageSize` | number | Results per page (default: 20, max: 100) |
| `status` | string | `ACTIVE`, `EXPIRED` or `REVOKED` |
| `q` | string | Search, up to 100 characters. See below |
| `contentType` | string | Content type, e.g. `vcard`. Exact match, ignoring case |
| `tagIds` | string | Comma-separated [tag](./tags-folders#tags) ids, up to 20. Returns codes that carry **any** of the tags |
| `folderId` | string | A [folder](./tags-folders#folders) id, or `unfiled` for codes without a folder |
| `outsidePolicy` | string | `true`: only codes marked outside the organization's [allowlist](./policies#codes-outside-the-list); `false`: only codes not marked |

`q` matches a code when any of these holds:

- the label contains it, ignoring case;
- for a `url` code, the destination's host contains it, ignoring case. Only the host is searched, not the path or query string: `q=menu` finds `https://menu.example.com/` but not `https://example.com/menu`. Codes of other content types are not matched by host;
- the token starts with it. Tokens are case-sensitive, so this match is too;
- it is a content type key, ignoring case (`q=vcard` returns the vCard codes).

`%` and `_` in `q` are matched literally.

**Response (200):**

```json
{
  "data": [
    {
      "token": "abc123",
      "label": "Summer menu",
      "destinationUrl": "https://menu.example.com/summer",
      "destinationHost": "menu.example.com",
      "contentType": "url",
      "status": "ACTIVE",
      "createdAt": "2026-04-10T12:00:00.000Z",
      "_count": { "scans": 42 },
      "folderId": "cmf...",
      "folder": { "id": "cmf...", "name": "Lobby" },
      "tags": [{ "id": "cmt...", "name": "Summer", "color": "teal" }],
      "...": "other stored fields of the code"
    }
  ],
  "total": 142,
  "page": 1,
  "pageSize": 20,
  "totalPages": 8
}
```

Each item carries its `tags` (sorted by name) and its `folder` (`null` when unfiled). `destinationHost` is the lowercased host of `destinationUrl`. `outsidePolicy` is `true` when the destination or a link is outside the organization's enforced [allowlist](./policies); the code keeps working.

| Status | When |
|--------|------|
| `400` | A parameter is out of range, for example `q` over 100 characters or more than 20 `tagIds` |
| `404` | A `tagIds` or `folderId` value is not a tag or folder of the caller's organization |

---

## Get QR Code

`GET /api/v1/qrcodes/:token`

**Headers:** `X-API-Key: <key>`

**Response (200):** Full QR code object (same shape as create response, plus `_count.scans`, the total number of scans, and `scans`, the five most recent). `verification_url` is the URL the code encodes, as in the create response. `tags` and `folder` have the same shapes as in [List QR Codes](#list-qr-codes).

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

A new `destinationUrl` follows the same host rules as on create (`400` for an IP address, `localhost`, a single-label or a private network name); resending a code's current destination is always accepted.

The organization's [policy](./policies) applies to a change of the destination or content: below its minimum role the request is refused with `403` and `code` `destination-edit-role-required`, and with the allowlist enforced a destination or link outside it is refused with `422` and `code` `destination-not-allowed`. Resending the current destination or content is not a change.

**Response (200):** Updated QR code object.

A change to a tracked field (destination, content, style, expiry, scan mode) is recorded in the code's [edit history](#edit-history).

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

## Edit History

Every change to a code's tracked fields is recorded as a numbered revision: who made it, when, which request, and each changed field's value before and after.

**Tracked fields:**

| Field | Value in `changes` |
|-------|--------------------|
| `destinationUrl` | string |
| `content` | object, or `null` for URL codes |
| `style` | object, or `null` for the default style |
| `expiresAt` | ISO 8601 string, or `null` for no expiry |
| `scanMode` | `FLASH` or `PAGE` |
| `status` | `ACTIVE`, `EXPIRED` or `REVOKED` |

Label, location and scan-limit changes are not tracked fields and record no revision. A change that leaves every tracked field as it was records no revision either.

A revision is recorded when a code is created (single, bulk or demo), updated with [Update QR Code](#update-qr-code), restored with [Restore a Destination](#restore-a-destination), or revoked (single, bulk, or by QRAuth). The revision is written in the same database transaction as the change itself.

**Revision kinds:**

| `kind` | Meaning |
|--------|---------|
| `BASELINE` | Where history begins for a code issued before edit history was available. Carries every tracked field, with `before` set to `null`. |
| `CREATED` | The code was created. Carries every tracked field, with `before` set to `null`. |
| `UPDATED` | One or more tracked fields were changed. |
| `RESTORED` | An earlier destination or content was restored; `restoredFrom` gives the revision it came from. |
| `REVOKED` | The code was revoked (`status` from its previous value to `REVOKED`). |

**Actors:** `actor` says who made the change.

| `actor.type` | Fields | Meaning |
|--------------|--------|---------|
| `USER` | `id`, `name`, `email` | A signed-in dashboard user |
| `API_KEY` | `id`, `label`, `prefix` | A request authenticated with an API key |
| `SYSTEM` | `id` | QRAuth itself; `id` names the process, for example `migration` for `BASELINE` revisions, or `qrauth-admin` when QRAuth support revoked the code |

A user or API key that no longer exists keeps its `id`; `name` and `email`, or `label` and `prefix`, are then `null`.

**Retention:** revisions are append-only. They are never edited or deleted, except that revisions older than **730 days** are removed (a code's latest revision is always kept), and a code's revisions are removed with the code when its account is deleted. Revision numbers count up from 1 per code; after retention removes old revisions, the oldest remaining revision may be higher than 1.

### Get Edit History

`GET /api/v1/qrcodes/:token/history`

**Headers:** `X-API-Key: <key>`

Every role can read a code's history. A token that does not exist or belongs to another organization returns `404`.

**Query parameters:**

| Param | Type | Description |
|-------|------|-------------|
| `page` | number | Page number (default: 1) |
| `pageSize` | number | Revisions per page (default: 20, max: 100) |

**Response (200):** revisions newest first.

```json
{
  "data": [
    {
      "revision": 3,
      "kind": "RESTORED",
      "createdAt": "2026-11-02T10:04:00.000Z",
      "changes": {
        "destinationUrl": { "before": "https://example.com/menu-v2", "after": "https://example.com/menu" }
      },
      "actor": { "type": "API_KEY", "id": "cm...", "label": "CI", "prefix": "qrauth_ab12" },
      "requestId": "0f8e1c2d-3b4a-4c5d-8e6f-7a8b9c0d1e2f",
      "restoredFrom": 1
    },
    {
      "revision": 2,
      "kind": "UPDATED",
      "createdAt": "2026-11-02T10:02:00.000Z",
      "changes": {
        "destinationUrl": { "before": "https://example.com/menu", "after": "https://example.com/menu-v2" }
      },
      "actor": { "type": "USER", "id": "cm...", "name": "Jane Doe", "email": "jane@example.com" },
      "requestId": "1b2c3d4e-5f6a-4b7c-8d9e-0f1a2b3c4d5e",
      "restoredFrom": null
    },
    {
      "revision": 1,
      "kind": "CREATED",
      "createdAt": "2026-11-02T09:00:00.000Z",
      "changes": {
        "destinationUrl": { "before": null, "after": "https://example.com/menu" },
        "content": { "before": null, "after": null },
        "style": { "before": null, "after": null },
        "expiresAt": { "before": null, "after": null },
        "scanMode": { "before": null, "after": "FLASH" },
        "status": { "before": null, "after": "ACTIVE" }
      },
      "actor": { "type": "USER", "id": "cm...", "name": "Jane Doe", "email": "jane@example.com" },
      "requestId": "9c8b7a6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
      "restoredFrom": null
    }
  ],
  "total": 3,
  "page": 1,
  "pageSize": 20,
  "totalPages": 1
}
```

| Field | Type | Description |
|-------|------|-------------|
| `revision` | number | 1, 2, 3 … per code |
| `kind` | string | See revision kinds above |
| `createdAt` | string | ISO 8601 |
| `changes` | object | The changed tracked fields, each `{ before, after }` |
| `actor` | object | See actors above |
| `requestId` | string \| null | The [`X-Request-Id`](./overview#request-ids) of the request that made the change; `null` when no API request made it (for example `BASELINE`) |
| `restoredFrom` | number \| null | For `RESTORED`: the revision whose value was restored |

Rate limit: 60 requests per minute per organization.

### Restore a Destination

`POST /api/v1/qrcodes/:token/history/:revision/restore`

**Headers:** `X-API-Key: <key>`

Restores what a code pointed to right after `revision`: its `destinationUrl` for URL codes, or its `content` for other content types. Other fields (style, expiry, scan mode, label) are not changed. No request body.

The restored value goes through the same rules as [Update QR Code](#update-qr-code) today: an `http`/`https` destination, Web Risk screening, the content type's schema, and a verified email behind the request. The code is re-signed, and a `RESTORED` revision is recorded with `restoredFrom` set to `revision`. A value that was accepted when it was first set but does not meet the current rules cannot be restored.

Needs the OWNER, ADMIN or MANAGER role; an API key needs one of those roles too. An organization [policy](./policies#the-destination-edit-role) with the minimum role `ADMIN` raises this to OWNER or ADMIN, and an enforced allowlist applies to the restored destination.

**Response (200):** the updated QR code, the same shape as the [Update QR Code](#update-qr-code) response, including `domain_warnings` when the restored destination resembles a domain verified by another organization.

**Errors:**

| Status | `code` | When |
|--------|--------|------|
| `404` | — | The token does not exist or belongs to another organization, or the revision does not exist (or was removed by retention) |
| `409` | `already-current` | The value at that revision is the code's current value |
| `409` | `revoked` | The code is revoked; a revoked code cannot be changed |
| `409` | `concurrent-change` | The code was changed by another request while the restore was checked; reload the history and try again |
| `409` | `history-incomplete` | The value at that revision is no longer in the history (the revision that set it was removed by retention) |
| `422` | `restore-not-allowed` | The value does not meet the current rules, for example a destination that is not `http`/`https`, or content that no longer matches its content type's schema |
| `422` | — | Web Risk lists the destination as dangerous (`error` `DestinationFlagged`, with `threatTypes`) |
| `422` | `destination-not-allowed` | The organization's allowlist is enforced and the destination is not on it |
| `403` | — | The role cannot restore, or no verified email is behind the request (`error` `EmailNotVerified`) |
| `403` | `destination-edit-role-required` | The organization's policy requires a higher role |

A code whose current destination is flagged follows the same rules as an update: it can only be pointed to a destination that passes screening.

Rate limit: 30 requests per minute per organization.

```bash
# The history, then restore revision 1
curl -H "X-API-Key: $QRAUTH_API_KEY" \
  "https://qrauth.io/api/v1/qrcodes/abc123/history?pageSize=50"
curl -X POST -H "X-API-Key: $QRAUTH_API_KEY" \
  "https://qrauth.io/api/v1/qrcodes/abc123/history/1/restore"
```

---

## Revoke QR Code

`DELETE /api/v1/qrcodes/:token`

**Headers:** `X-API-Key: <key>`

Sets the QR code status to `revoked`. Subsequent scans return a revoked-state verification page. This action is irreversible. The revocation is recorded in the code's [edit history](#edit-history).

**Response (204):** No content.

---

## Bulk Create

`POST /api/v1/qrcodes/bulk`

Up to 64 URL codes in one request. To create up to 1,000 from a CSV file, with a dry run first, see [Bulk Import and Export](./bulk).

**Headers:** `X-API-Key: <key>`

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `items` | array | Yes | 1–64 URL code items. |

Bulk create makes URL codes only. Each item takes the URL fields of single create: `destinationUrl` (required), `label`, `location`, `expiresAt`, `maxScans`, `maxScansPerDevice` and `scanMode`. To create a `vcard`, `coupon`, `event`, `pdf`, `feedback`, `app-link` or `link-list` code, use [Create QR Code](#create-qr-code) once per code.

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
| `DESTINATION_NOT_ALLOWED` | The organization's [allowlist](./policies) is enforced and the destination is not on it. |
| `RENDER_UNAVAILABLE` | The QR image could not be rendered. The item was not stored; retry it. |
| `QUOTA_EXCEEDED` | The organization's QR code limit was reached. |
| `RATE_LIMIT` | The item was rate limited. |
| `VALIDATION_ERROR` | The item was rejected while it was being created. |
| `INTERNAL_ERROR` | Any other failure. |

---

## Bulk Tag and Move

`POST /api/v1/qrcodes/bulk-tag` adds and removes tags on up to 100 codes, and `POST /api/v1/qrcodes/bulk-move` moves up to 100 codes into a folder or out of any folder. See [Tags and Folders](./tags-folders#bulk-tag).
