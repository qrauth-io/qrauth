---
title: Python SDK
description: Official Python SDK for the QRAuth API.
---

# Python SDK

The `qrauth` package is the official Python SDK for QRAuth. It has full API parity with the Node.js SDK and uses snake_case naming conventions throughout.

## Installation

```bash
pip install qrauth
```

Requires Python 3.9+. The package has no dependencies beyond the standard library and `httpx`.

## Initialization

```python
import os
import qrauth

# API key only
client = qrauth.QRAuth(api_key=os.environ["QRAUTH_API_KEY"])

# API key + OAuth2 client credentials
client = qrauth.QRAuth(
    api_key=os.environ["QRAUTH_API_KEY"],
    client_id=os.environ["QRAUTH_CLIENT_ID"],
    client_secret=os.environ["QRAUTH_CLIENT_SECRET"],
)
```

### Context manager

The client implements the context manager protocol to ensure the underlying HTTP session is closed properly:

```python
with qrauth.QRAuth(api_key=os.environ["QRAUTH_API_KEY"]) as client:
    qr = client.qrcodes.create(
        label="Product A",
        content_type="url",
        content={"url": "https://example.com"},
    )
```

---

## QR Codes

All methods return `TypedDict` objects so your IDE can provide autocompletion.

### `qrcodes.create(**params)`

```python
qr = client.qrcodes.create(
    label="Product A — Shelf 4B",
    content_type="url",
    content={"url": "https://example.com/product"},
    location={"lat": 52.52, "lng": 13.405, "radius_m": 50},
    expires_at="2027-01-01T00:00:00Z",
)

print(qr["id"])            # qr_01HXYZ...
print(qr["qr_image_url"])  # PNG image URL
print(qr["token"])         # short token
```

### `qrcodes.list(**params)`

```python
result = client.qrcodes.list(status="active", content_type="url", page=1, limit=50)

for qr in result["data"]:
    print(qr["label"], qr["scan_count"])
```

### `qrcodes.get(token)`

```python
qr = client.qrcodes.get("abc123")
```

### `qrcodes.update(token, **params)`

```python
updated = client.qrcodes.update(
    "abc123",
    label="Updated label",
    content={"url": "https://example.com/new-url"},
)
```

### `qrcodes.revoke(token)`

```python
client.qrcodes.revoke("abc123")
```

### `qrcodes.bulk_create(codes)`

```python
result = client.qrcodes.bulk_create([
    {"label": "Code 1", "content_type": "url", "content": {"url": "https://example.com/1"}},
    {"label": "Code 2", "content_type": "url", "content": {"url": "https://example.com/2"}},
])

print(result["created"])  # 2
```

---

## Verification

### `verify(token, **options)`

```python
result = client.verify("abc123", client_lat=52.52, client_lng=13.405)

if result["verified"] and result["security"]["trust_score"] >= 0.8:
    print("Trusted scan")
else:
    print("Suspicious:", result["security"]["signals"])
```

---

## Auth Sessions

### `auth_sessions.create(**params)`

```python
session = client.auth_sessions.create(
    scopes=["openid", "profile", "email"],
    code_challenge=challenge,
    code_challenge_method="S256",
)
# Display session["qr_code"]["qr_image_url"] and poll
```

### `auth_sessions.get(session_id, **options)`

```python
session = client.auth_sessions.get(
    "as_01HXYZ...",
    code_verifier=verifier,  # PKCE
)

if session["status"] == "APPROVED":
    tokens = client.auth_sessions.exchange(
        code=session["code"],
        redirect_uri="https://yourapp.com/callback",
        code_verifier=verifier,
    )
```

---

## Ephemeral Sessions

### `ephemeral.create(**params)`

```python
session = client.ephemeral.create(
    scopes=["door:unlock"],
    ttl="1h",
    max_uses=1,
    device_binding=False,
    metadata={"zone": "B2"},
)
```

### `ephemeral.list(**params)`

```python
result = client.ephemeral.list(status="PENDING")
```

### `ephemeral.get(session_id)`

```python
session = client.ephemeral.get("es_01HXYZ...")
```

### `ephemeral.claim(token, **params)`

```python
claim = client.ephemeral.claim(
    "eph_tok_...",
    device_fingerprint="fp_abc...",
)

print(claim["jwt"])  # Bearer token
```

### `ephemeral.revoke(session_id)`

```python
client.ephemeral.revoke("es_01HXYZ...")
```

---

## Proximity

### `proximity.get_attestation(token, client_lat, client_lng)`

```python
attestation = client.proximity.get_attestation("abc123", 52.52, 13.405)

print(attestation["claims"]["proximity"]["matched"])    # True
print(attestation["claims"]["proximity"]["distance_m"]) # 14
```

### `proximity.verify_attestation(jwt, public_key=None)`

```python
result = client.proximity.verify_attestation(
    jwt=attestation["jwt"],
    public_key=attestation["public_key"],
)

print(result["valid"])  # True
```

---

## Error Handling

```python
from qrauth.exceptions import (
    QRAuthError,
    AuthenticationError,
    NotFoundError,
    RateLimitError,
    ValidationError,
)

try:
    qr = client.qrcodes.get("unknown-token")
except NotFoundError:
    print("QR code not found")
except RateLimitError as e:
    print(f"Rate limited, retry after {e.retry_after}s")
except AuthenticationError:
    print("Invalid API key")
except ValidationError as e:
    print(f"Validation failed: {e}")
except QRAuthError as e:
    print(f"API error {e.status_code}: {e}")
```

| Exception | HTTP status | Description |
|-----------|-------------|-------------|
| `AuthenticationError` | 401 | Missing or invalid credentials |
| `ForbiddenError` | 403 | Insufficient permissions |
| `NotFoundError` | 404 | Resource not found |
| `ConflictError` | 409 | Duplicate or already-claimed |
| `ValidationError` | 400 / 422 | Request body failed validation |
| `RateLimitError` | 429 | Rate limit exceeded — check `.retry_after` |
| `QRAuthError` | any | Base class for all SDK exceptions |

---

## Async Support

An async client is available for use with `asyncio`:

```python
import asyncio
from qrauth.async_client import AsyncQRAuth

async def main():
    async with AsyncQRAuth(api_key="sk_live_...") as client:
        qr = await client.qrcodes.create(
            label="Async QR",
            content_type="url",
            content={"url": "https://example.com"},
        )
        print(qr["id"])

asyncio.run(main())
```

All methods on `AsyncQRAuth` are coroutines with identical signatures to their synchronous counterparts.
