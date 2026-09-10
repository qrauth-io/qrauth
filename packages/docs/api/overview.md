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
X-API-Key: sk_live_...
```

### Basic Auth (auth sessions — server-to-server)

Exchange authorization codes for tokens using HTTP Basic authentication with your `clientId` and `clientSecret`.

```http
POST /api/v1/auth-sessions HTTP/1.1
Authorization: Basic base64(clientId:clientSecret)
```

### PKCE / Client ID only (browser SDKs)

Browser-based flows (Web Components, `<qrauth-login>`) send only the `X-Client-Id` header and never expose a secret. The server validates the PKCE `code_verifier` to complete the exchange.

```http
POST /api/v1/auth-sessions HTTP/1.1
X-Client-Id: app_01HXYZ...
```

## Rate Limits

| Context | Limit |
|---------|-------|
| Unauthenticated / public endpoints | 60 requests / minute |
| Authenticated endpoints | 300 requests / minute |

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
