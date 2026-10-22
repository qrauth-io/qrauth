---
title: API Overview
description: QRAuth REST API reference — base URL, authentication, rate limits, and error handling.
---

# API Overview

The QRAuth REST API is available at:

```
https://qrauth.io/api/v1
```

All requests and responses use JSON. Dates are ISO 8601 strings. IDs use ULID format (`qr_01HXYZ...`).

## Authentication

QRAuth uses three authentication schemes depending on the context.

### API Key (server-side)

Pass your API key in the `X-API-Key` header. Use this for QR code management, device trust, and webhook configuration from your backend.

```http
GET /api/v1/qrcodes HTTP/1.1
X-API-Key: qrauth_...
```

### Basic Auth (auth sessions — server-to-server)

Server-side auth-session calls (create, poll, `verify-result`) authenticate with HTTP Basic using your app's `clientId` and `clientSecret`. Auth sessions are the legacy sign-in surface; new sign-in integrations should use the [OIDC provider](/guide/oidc) at `https://id.qrauth.io` ([ADR-0004](https://github.com/qrauth-io/qrauth/blob/main/docs/adr/0004-signin-surface-consolidation.md)).

```http
POST /api/v1/auth-sessions HTTP/1.1
Authorization: Basic base64(clientId:clientSecret)
```

### PKCE / Client ID only (browser SDKs)

Browser-based flows (Web Components, `<qrauth-login>`) send only the `X-Client-Id` header and never expose a secret. The server validates the PKCE `code_verifier` before releasing the approved result.

```http
POST /api/v1/auth-sessions HTTP/1.1
X-Client-Id: app_01HXYZ...
```

## Rate Limits

| Context | Limit | Counted per |
|---------|-------|-------------|
| Public endpoints (default) | 100 requests / minute | network |
| Authenticated endpoints | 60 requests / minute | organization (network when no credential is recognised) |
| QR code generation | 30 requests / minute | organization |
| Bulk generation | 5 requests / minute | organization |
| Signup, login, password reset | 10 requests / minute | network |

The OIDC provider endpoints at `https://id.qrauth.io` have their own limits.

When a limit is exceeded the API returns `429 Too Many Requests`. The response includes a `Retry-After` header indicating how many seconds to wait.

## Content Negotiation

The verification endpoint (`GET /v/:token`) serves different responses depending on the `Accept` header:

- **Browser** — full HTML verification page with animated trust reveal
- **`Accept: application/json`** — structured JSON response for programmatic consumption

All other API endpoints always return JSON.

## Error Format

All errors follow a consistent envelope:

```json
{
  "statusCode": 400,
  "error": "Bad Request",
  "message": "contentType must be one of: url, vcard, coupon, event, pdf, feedback"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `statusCode` | number | HTTP status code |
| `error` | string | Short error category |
| `message` | string | Human-readable explanation |

### Common Status Codes

| Code | Meaning |
|------|---------|
| `400` | Validation error — check `message` for field details |
| `401` | Missing or invalid credentials |
| `403` | Valid credentials but insufficient permissions |
| `404` | Resource not found |
| `409` | Conflict — e.g. duplicate label or already-claimed session |
| `422` | Unprocessable entity — business logic rejection |
| `429` | Rate limit exceeded |
| `500` | Internal server error |

## Pagination

List endpoints return a consistent pagination envelope:

```json
{
  "data": [...],
  "pagination": {
    "page": 1,
    "limit": 20,
    "total": 142,
    "totalPages": 8
  }
}
```

Pass `?page=2&limit=50` to navigate pages. Maximum `limit` is `100`.

## Versioning

The current API version is `v1`. Breaking changes will be introduced under a new version prefix (`/api/v2`). The previous version is supported for at least 12 months after a new version ships.
