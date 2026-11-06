# Logos

An organization keeps a library of its own logos, which QR code styles can draw in the centre of the code.

## Who can use logos

Uploading a logo, and saving a style that draws one, needs both:

- the Pro, Business or Enterprise plan, and
- a verified issuer: a [verified domain](../guide/domain-verification) or a completed verification review.

A printed code that carries a brand's logo is trusted at a glance, so logos are limited to organizations whose identity QRAuth confirms when the code is scanned.

If the organization later moves to the Free plan or is no longer verified, its codes keep their logo: they still render and export with it, and the logos can still be listed, downloaded and deleted. Saving a changed style with a logo is refused until both conditions are met again. A request that does not change the style (for example, renaming a code without sending `qrStyle`, or sending the stored style unchanged) is not affected.

Every upload is checked and re-encoded on our infrastructure. Only the re-encoded PNG is kept, and it is never served publicly: each request needs the organization's credentials. Uploads and deletions made by a signed-in user are recorded in the organization's audit log.

---

## Upload a Logo

`POST /api/v1/assets/logos`

**Headers:** `X-API-Key: <key>`, `Content-Type: image/png`, `image/jpeg` or `image/webp`

**Query parameters:**

| Param | Type | Description |
|-------|------|-------------|
| `name` | string | Display name, up to 100 characters (optional; default `logo.png`) |

**Request body:** the image file itself (not JSON or multipart), at most 1 MiB.

The file type is read from the file's contents, not from `Content-Type`. The image:

- must be PNG, JPEG or WebP. SVG is not accepted;
- must not be animated or have several pages;
- must be from 64 to 2048 pixels on each side.

The stored logo is the image turned upright (EXIF orientation), converted to sRGB, with all metadata removed, fitted inside 512×512 pixels and saved as PNG.

**Response (201):**

```json
{
  "id": "cmlogo01hxyz",
  "name": "brand-mark.png",
  "width": 512,
  "height": 341,
  "sizeBytes": 18234,
  "sha256": "9f2c…",
  "createdAt": "2026-10-29T12:00:00.000Z"
}
```

| Status | `code` | When |
|--------|--------|------|
| `401` | — | No valid credentials. This is checked before the body is read |
| `403` | — | The plan does not include logos (Free), or the request comes from a role that cannot create QR codes (Viewer), or the email address is not verified |
| `403` | `logo-verification-required` | The plan includes logos but the issuer is not verified. The message is `Custom logos require a verified domain or completed verification` |
| `409` | — | The organization already has 50 logos |
| `413` | — | The body is larger than 1 MiB |
| `415` | `unsupported-type`, `svg-not-accepted` | The file is not PNG, JPEG or WebP; SVG and other markup get `svg-not-accepted` |
| `422` | `animated`, `dimensions`, `unreadable`, `too-complex` | The image is animated or has several pages, is outside 64–2048 pixels, cannot be read, or is too detailed to keep under 1 MiB at 512 pixels |

The `name` is stored without control characters, invisible characters (such as zero-width spaces) and text-direction characters.

```bash
curl -X POST -H "X-API-Key: $QRAUTH_API_KEY" -H "Content-Type: image/png" \
  --data-binary @brand-mark.png \
  "https://qrauth.io/api/v1/assets/logos?name=brand-mark.png"
```

---

## List Logos

`GET /api/v1/assets/logos`

**Response (200):** `{ "data": [ …logos, newest first ] }`, each as in the upload response.

---

## Get a Logo

`GET /api/v1/assets/logos/:id`

**Response (200):** the stored PNG, `Content-Type: image/png`, `Cache-Control: private, max-age=86400` (a logo's bytes never change, but a cached copy expires after a day, so it does not long outlive a deleted logo). An id of another organization returns `404`, the same as an id that does not exist.

---

## Delete a Logo

`DELETE /api/v1/assets/logos/:id`

Owners, admins and managers can delete logos, on any plan.

**Response (204):** No content.

While any QR code of the organization uses the logo, deletion is refused with `409`, and `count` gives the number of codes:

```json
{
  "statusCode": 409,
  "error": "Conflict",
  "message": "2 QR codes use this logo. Choose another logo for them before deleting.",
  "count": 2
}
```

Images already exported keep the logo: exports embed it.

---

## Using a Logo in a Code's Style

A style draws a logo from the library with:

```json
{ "logo": { "kind": "asset", "assetId": "cmlogo01hxyz", "scale": 1 } }
```

`scale` is from `0.5` to `1`: the share of the largest logo the code can hold while it stays readable. The other logo kinds are `{ "kind": "qrauth" }` (the QRAuth logo, on every plan) and `null` (no logo).

When a style with a logo is saved (creating a code, or changing its style), the code is drawn with the logo and read back at 300, 512 and 1024 pixels wide and at every whole size from 3 to 16 pixels per module, plus a slightly blurred small size. If any of these cannot be read back, the style is refused. The responses are:

| Status | `code` | When |
|--------|--------|------|
| `403` | — | The plan does not include logos (Free) |
| `403` | `logo-verification-required` | The issuer is not verified (see [Who can use logos](#who-can-use-logos)) |
| `422` | `logo-not-found` | The organization has no logo with this `assetId`, including a logo deleted while the style was being saved |
| `422` | `logo-unreadable` | The code could not be read back with this logo. The message names the size that failed, for example `at 300 px wide`. Use a smaller `scale`, a simpler logo or higher contrast |

[Bulk Create](./qrcodes#bulk-create) does not accept `qrStyle`; style each code afterwards with [Update QR Code](./qrcodes#update-qr-code).

[Get QR Code Image](./qrcodes#get-qr-code-image) and `qr_image_url` draw the logo.
