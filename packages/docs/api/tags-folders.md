---
title: Tags and Folders
description: Organize an organization's QR codes with tags and folders, and tag or move many codes at once.
---

# Tags and Folders

Tags and folders organize an organization's QR codes. They are for the organization's own use: they are not part of the signed payload, are never shown to people who scan a code, and changing them does not re-sign anything.

- **Tags** are labels. A code can carry many tags, and a tag can be on any number of codes.
- **Folders** are flat (no nesting). A code is in at most one folder; a code without a folder is **unfiled**.

Both belong to the organization and are shared by all its members. Filter the code list by them with `tagIds` and `folderId` on [List QR Codes](./qrcodes#list-qr-codes).

## Permissions

| Role | Read | Create, change, delete, bulk tag and move |
|------|------|-------------------------------------------|
| `OWNER`, `ADMIN`, `MANAGER`, `MEMBER` | Yes | Yes |
| `VIEWER` | Yes | No (`403`) |

An API key acts with its role. A tag or folder id that does not belong to the caller's organization returns `404`, the same as an id that does not exist.

## Errors

| Status | `code` | When |
|--------|--------|------|
| `400` | — | A field is missing or out of range, or the body has an unknown field |
| `403` | — | The caller's role is `VIEWER` |
| `404` | — | The tag or folder does not exist in the caller's organization |
| `409` | `name-taken` | Another tag (or folder) of the organization has this name, ignoring case |
| `409` | `limit-reached` | The organization already has 100 tags (or 200 folders) |

```json
{ "statusCode": 409, "error": "Conflict", "code": "name-taken", "message": "A tag named \"Summer\" already exists." }
```

---

## Tags

### Colours

A tag's `color` is one of a fixed palette: `grey` (the default), `blue`, `teal`, `green`, `yellow`, `orange`, `red`, `pink` or `purple`. Clients map each key to a colour of their own theme.

### List Tags

`GET /api/v1/tags`

**Headers:** `X-API-Key: <key>`

**Response (200):** the organization's tags, sorted by name. `codeCount` counts the codes that carry the tag, in any status.

```json
{
  "data": [
    { "id": "cmt...", "name": "Summer", "color": "teal", "codeCount": 12, "createdAt": "2026-11-01T18:02:11.412Z" }
  ]
}
```

### Create Tag

`POST /api/v1/tags`

**Headers:** `X-API-Key: <key>`

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | 1–32 characters, trimmed. Unique in the organization, ignoring case |
| `color` | string | No | A palette key (default `grey`) |

An organization can have up to 100 tags.

**Response (201):** the tag, in the shape of a [List Tags](#list-tags) item.

### Update Tag

`PATCH /api/v1/tags/:id`

**Headers:** `X-API-Key: <key>`

**Request body:** `name`, `color` or both, with the same rules as [Create Tag](#create-tag).

**Response (200):** the updated tag.

### Delete Tag

`DELETE /api/v1/tags/:id`

**Headers:** `X-API-Key: <key>`

Deletes the tag and removes it from every code that carries it. The codes themselves are not changed.

**Response (204):** No content.

---

## Folders

### List Folders

`GET /api/v1/folders`

**Headers:** `X-API-Key: <key>`

**Response (200):** the organization's folders, sorted by name, and the number of unfiled codes. Both counts include codes in any status.

```json
{
  "data": [
    { "id": "cmf...", "name": "Lobby", "codeCount": 8, "createdAt": "2026-11-01T18:02:14.077Z" }
  ],
  "unfiledCount": 134
}
```

### Create Folder

`POST /api/v1/folders`

**Headers:** `X-API-Key: <key>`

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | 1–64 characters, trimmed. Unique in the organization, ignoring case |

An organization can have up to 200 folders.

**Response (201):** the folder, in the shape of a [List Folders](#list-folders) item.

### Rename Folder

`PATCH /api/v1/folders/:id`

**Headers:** `X-API-Key: <key>`

**Request body:** `{ "name": "..." }`, with the same rules as [Create Folder](#create-folder).

**Response (200):** the renamed folder.

### Delete Folder

`DELETE /api/v1/folders/:id`

**Headers:** `X-API-Key: <key>`

Deletes the folder. Its codes become unfiled; they are not deleted or revoked.

**Response (204):** No content.

---

## Bulk Tag

`POST /api/v1/qrcodes/bulk-tag`

**Headers:** `X-API-Key: <key>`

Adds and removes tags on up to 100 codes in one request.

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `tokens` | string[] | Yes | 1–100 code tokens |
| `add` | string[] | No | Tag ids to add, up to 20 |
| `remove` | string[] | No | Tag ids to remove, up to 20 |

At least one of `add` and `remove` must list a tag, and a tag cannot be in both (`400`). Adding a tag a code already carries, or removing one it does not carry, is not an error.

Every tag id must belong to the caller's organization; otherwise the response is `404` and no code is changed. Tokens that do not exist or belong to another organization do not fail the request: they are listed in `notFound`, and the other codes are updated.

```json
{ "tokens": ["abc123", "def456"], "add": ["cmt..."] }
```

**Response (200):**

```json
{ "updated": ["abc123"], "notFound": ["def456"] }
```

Repeated tokens are reported once. `updated` is not guaranteed to follow the order of `tokens`.

## Bulk Move

`POST /api/v1/qrcodes/bulk-move`

**Headers:** `X-API-Key: <key>`

Moves up to 100 codes into a folder, or out of any folder.

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `tokens` | string[] | Yes | 1–100 code tokens |
| `folderId` | string \| null | Yes | The target folder id, or `null` to make the codes unfiled |

A `folderId` that does not belong to the caller's organization returns `404` and no code is changed. Tokens are handled as in [Bulk Tag](#bulk-tag).

**Response (200):** `{ "updated": [...], "notFound": [...] }`, as for Bulk Tag.

```bash
curl -X POST -H "X-API-Key: $QRAUTH_API_KEY" -H "Content-Type: application/json" \
  -d '{"tokens":["abc123","def456"],"folderId":null}' \
  https://qrauth.io/api/v1/qrcodes/bulk-move
```
