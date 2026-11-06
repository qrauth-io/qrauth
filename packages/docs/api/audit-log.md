---
title: Audit Log
description: Read and export an organization's audit log of changes to settings, members, credentials and QR codes.
---

# Audit Log

The audit log lists what was changed in an organization, by whom and when: organization settings and plan, members and invitations, API keys, sign-in clients and apps, QR codes and their tags and folders, fraud incident handling, members' account security actions (sessions, devices, passkeys, sign-in consents), and actions QRAuth staff took on the organization.

Entries come from two sources:

- **Audit entries** (`source: "audit"`), one per action, with details of the action in `metadata`.
- **QR code changes** (`source: "qr_revision"`), read from each code's [edit history](./qrcodes#edit-history). Their actions are `qr.created`, `qr.updated`, `qr.restored`, `qr.revoked` and `qr.baseline`, and `changes` holds each changed field as `{ before, after }`.

The log is read-only: entries cannot be edited or deleted through the API. Entries are kept for 730 days.

## Access

| | |
|---|---|
| Plan | Business and above. Activity is recorded on every plan and becomes visible after an upgrade |
| Role | `OWNER` or `ADMIN`. An API key acts with its role |
| Scope | The caller's organization only |

**Headers:** `X-API-Key: <key>`

## Errors

| Status | `code` | When |
|--------|--------|------|
| `400` | — | An unknown or invalid parameter, `from` after `to`, or an invalid `cursor` |
| `403` | `audit-role-required` | The caller's role is not `OWNER` or `ADMIN` |
| `403` | `governance-plan-required` | The organization's plan is below Business |

```json
{ "statusCode": 403, "error": "Forbidden", "code": "governance-plan-required", "message": "The audit log is included in the Business plan and above. ..." }
```

## Filters

Both endpoints take the same filters. All are optional and combine with each other.

| Parameter | Type | Description |
|-----------|------|-------------|
| `actor` | string | A user id, API key id or system process id |
| `actorType` | string | `USER`, `API_KEY`, `SYSTEM` or `SUPERADMIN` (QRAuth staff) |
| `action` | string | An exact action, e.g. `apiKey.revoke` or `qr.updated` |
| `resourceType` | string | e.g. `QRCode`, `ApiKey`, `Membership`, `Organization` |
| `resourceId` | string | The id of the resource |
| `from` | string | ISO 8601 date-time with offset; entries at or after it |
| `to` | string | ISO 8601 date-time with offset; entries at or before it |

---

## List Entries

`GET /api/v1/audit`

Takes the [filters](#filters), plus:

| Parameter | Type | Description |
|-----------|------|-------------|
| `cursor` | string | `nextCursor` from the previous page |
| `limit` | integer | 1–100, default 50 |

**Response (200):** entries newest first. `nextCursor` is opaque; pass it as `cursor` for the next (older) page. It is `null` on the last page.

```json
{
  "data": [
    {
      "id": "log:cmaudit0001",
      "source": "audit",
      "action": "apiKey.create",
      "label": "API key created",
      "resourceType": "ApiKey",
      "resourceId": "cmkey0001",
      "resourceName": null,
      "actor": { "type": "USER", "id": "cmuser0001", "name": "Jane Doe", "email": "jane@example.com" },
      "createdAt": "2026-11-03T09:00:00.000Z",
      "requestId": "7d2f6b1e-0c4a-4f7e-9a51-2b8f3c6d9e10",
      "ipAddress": "203.0.113.7",
      "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15",
      "metadata": { "prefix": "qra_live_ab12", "label": "CI deploy" },
      "changes": null
    },
    {
      "id": "qr:cmrev0002",
      "source": "qr_revision",
      "action": "qr.updated",
      "label": "QR code updated",
      "resourceType": "QRCode",
      "resourceId": "cmqr0001",
      "resourceName": "RKcPf9kv",
      "actor": { "type": "API_KEY", "id": "cmkey0001", "label": "CI deploy", "prefix": "qra_live_ab12" },
      "createdAt": "2026-11-03T08:55:00.000Z",
      "requestId": "8f1d2c3b-4a5e-4b6c-9d7e-1a2b3c4d5e6f",
      "ipAddress": null,
      "userAgent": null,
      "metadata": { "revision": 2 },
      "changes": { "destinationUrl": { "before": "https://example.com/menu", "after": "https://example.com/menu-autumn" } }
    }
  ],
  "nextCursor": "eyJ0IjoiMjAyNi0xMS0wM1QwODo1NTowMC4wMDBaIiwiaWQiOiJxcjpjbXJldjAwMDIifQ"
}
```

| Field | Description |
|-------|-------------|
| `id` | `log:<id>` for audit entries, `qr:<id>` for QR code changes |
| `action`, `label` | The action and its readable description |
| `resourceType`, `resourceId` | What was acted on |
| `resourceName` | For QR code events, the code's token while the code exists; otherwise `null` |
| `actor` | Who acted; see [Actors](#actors) |
| `requestId` | The [`X-Request-Id`](./overview#request-ids) of the request that made the change, when there was one |
| `ipAddress`, `userAgent` | The client's address and user agent when recorded. `null` for QR code changes and QRAuth staff actions |
| `metadata` | Details of the action. For QR code changes, `{ revision, restoredFrom? }` |
| `changes` | For QR code changes, each changed field as `{ before, after }`; otherwise `null` |

### Actors

| `type` | Shape | Notes |
|--------|-------|-------|
| `USER` | `{ id, name, email }` | `name` and `email` are `null` once the user no longer exists |
| `API_KEY` | `{ id, label, prefix }` | `label` and `prefix` are `null` once the key no longer exists |
| `SYSTEM` | `{ id }` | QRAuth itself; `id` names the process |
| `SUPERADMIN` | `{ id: null, name: "QRAuth" }` | A QRAuth staff member. The person is not named, and no IP address or user agent is shown |

---

## CSV Export

`GET /api/v1/audit/export.csv`

Takes the [filters](#filters) (not `cursor` or `limit`); `from` and `to` are required. One export holds at most 100,000 entries: a larger result is refused with `422` and code `audit-export-too-large` (choose a shorter range or add filters). Returns the matching entries, newest first, as `text/csv` (UTF-8, CRLF line ends), streamed as an attachment named `qrauth-audit-log-<date>.csv`:

```
time,action,description,actor_type,actor_id,actor,resource_type,resource_id,resource_name,request_id,ip_address,user_agent,details
2026-11-03T09:00:00.000Z,apiKey.create,API key created,USER,cmuser0001,jane@example.com,ApiKey,cmkey0001,,7d2f6b1e-0c4a-4f7e-9a51-2b8f3c6d9e10,203.0.113.7,Mozilla/5.0 ...,"{""prefix"":""qra_live_ab12"",""label"":""CI deploy""}"
```

`actor` is the user's email (or name), the API key's label (or prefix), the system process id, or `QRAuth`. `details` is `changes` for QR code changes and `metadata` otherwise, as JSON. Cells that a spreadsheet would read as a formula (starting with `=`, `+`, `-`, `@`, a tab or a carriage return) are prefixed with `'`.

## SDK

The [Node.js SDK](/sdk/node#audit-log) has `listAuditEntries()`, `iterateAuditEntries()` and `exportAuditCsv()`.
