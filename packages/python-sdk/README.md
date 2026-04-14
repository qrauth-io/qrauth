# qrauth

Official Python SDK for [QRAuth](https://qrauth.io) -- cryptographic QR code verification and anti-fraud infrastructure.

## Install

```bash
pip install qrauth
```

## Quick Start

```python
from qrauth import QRAuth

qr = QRAuth(api_key="qrauth_xxx")

# Generate a verified QR code
code = qr.create(
    "https://municipal-parking.com/pay",
    location={"lat": 40.63, "lng": 22.94},
    expires_in="1y",
)

print(code["verification_url"])
# -> https://qrauth.io/v/xK9m2pQ7

# Verify a scanned QR code
result = qr.verify("xK9m2pQ7")
print(result["verified"])              # True
print(result["security"]["trustScore"])  # 94
```

## API

### `QRAuth(api_key=None, *, client_id=None, client_secret=None, base_url="https://qrauth.io")`

At least one of `api_key` or `client_id` must be provided.

| Parameter       | Type  | Description                                                        |
|-----------------|-------|--------------------------------------------------------------------|
| `api_key`       | `str` | API key (starts with `qrauth_`). Required for QR management calls |
| `client_id`     | `str` | App client ID (starts with `qrauth_app_`). Required for auth sessions |
| `client_secret` | `str` | App client secret. Required alongside `client_id`                 |
| `base_url`      | `str` | API base URL. Defaults to `https://qrauth.io`                     |

### `qr.create(destination, **kwargs)`

Generate a cryptographically signed QR code.

```python
code = qr.create(
    "https://example.com/pay",
    label="Parking Meter #42",
    location={"lat": 40.63, "lng": 22.94, "radiusM": 100},
    expires_in="30d",
)
```

| Parameter      | Type   | Description                                            |
|----------------|--------|--------------------------------------------------------|
| `destination`  | `str`  | Target URL                                             |
| `label`        | `str`  | Human-readable label                                   |
| `location`     | `dict` | `{"lat": ..., "lng": ..., "radiusM": ...}` geo-fence   |
| `expires_in`   | `str`  | Duration (`30s`, `5m`, `6h`, `30d`, `1y`) or ISO date  |
| `content_type` | `str`  | Content type: `url`, `event`, `coupon`, `vcard`, etc.  |
| `content`      | `dict` | Structured content (for non-URL types)                 |

### `qr.verify(token, *, client_lat=None, client_lng=None)`

Verify a QR code and get its trust score.

```python
result = qr.verify("xK9m2pQ7", client_lat=40.63, client_lng=22.94)
```

### `qr.list(*, page=1, page_size=20, status=None)`

List QR codes for your organization.

```python
response = qr.list(page=1, page_size=20, status="ACTIVE")
for item in response["data"]:
    print(item["token"], item["status"])
```

### `qr.get(token)`

Get details of a specific QR code.

### `qr.revoke(token)`

Revoke a QR code so it no longer verifies.

### `qr.bulk(items)`

Create up to 64 QR codes in a single request.

```python
result = qr.bulk([
    {"destination": "https://example.com/1", "label": "Meter 1"},
    {"destination": "https://example.com/2", "label": "Meter 2"},
])
```

## QR-Based Authentication (Auth Sessions)

Use auth sessions to let users authenticate on your site by scanning a QR code with the QRAuth app.

Requires an App `client_id` and `client_secret` (configured in your QRAuth dashboard).

### `QRAuth(client_id, client_secret, *, base_url="https://qrauth.io")`

```python
from qrauth import QRAuth

qr = QRAuth(client_id="qrauth_app_xxx", client_secret="your_secret")
```

You can combine both modes in a single instance:

```python
qr = QRAuth(
    api_key="qrauth_xxx",
    client_id="qrauth_app_xxx",
    client_secret="your_secret",
)
```

### `qr.create_auth_session(**kwargs)` → `AuthSessionResponse`

Create a new auth session. Display `session["qr_url"]` as a QR code for the user to scan.

```python
session = qr.create_auth_session(scopes=["identity", "email"])
print(session["qr_url"])      # encode this as a QR code
print(session["session_id"])  # use to poll status
```

| Parameter               | Type        | Description                                             |
|-------------------------|-------------|---------------------------------------------------------|
| `scopes`                | `list[str]` | Requested scopes (e.g. `["identity", "email"]`)         |
| `redirect_url`          | `str`       | URL to redirect after approval (deep-link flows)        |
| `metadata`              | `dict`      | Arbitrary metadata attached to the session              |
| `code_challenge`        | `str`       | PKCE code challenge (S256). Required for public clients |
| `code_challenge_method` | `str`       | Code challenge method. Only `"S256"` is supported       |

### `qr.get_auth_session(session_id, *, code_verifier=None)` → `AuthSessionStatus`

Poll the session status. Call this on an interval (e.g. every 2 seconds) until
`status` is `"APPROVED"`, `"DENIED"`, or `"EXPIRED"`.

```python
import time

while True:
    status = qr.get_auth_session(session["session_id"])
    if status["status"] == "APPROVED":
        print(status["user"])   # {"id": "...", "name": "...", "email": "..."}
        break
    if status["status"] in ("DENIED", "EXPIRED"):
        break
    time.sleep(2)
```

### `qr.verify_auth_result(session_id, signature)` → `AuthSessionVerifyResult`

Verify the approved session on your backend. Call this after your frontend
receives `onSuccess` from the browser SDK to confirm the session is genuine
before issuing your own session or JWT.

```python
result = qr.verify_auth_result(session_id, signature)
if result["valid"]:
    user = result["session"]["user"]
    # issue your own session for the user
```

### Full flow example

```python
from qrauth import QRAuth
import time

qr = QRAuth(client_id="qrauth_app_xxx", client_secret="your_secret")

# 1. Create session and show QR code to user
session = qr.create_auth_session(scopes=["identity", "email"])
print(f"Scan this URL: {session['qr_url']}")

# 2. Poll until resolved
while True:
    s = qr.get_auth_session(session["session_id"])
    if s["status"] == "APPROVED":
        break
    if s["status"] in ("DENIED", "EXPIRED"):
        raise Exception("Auth failed")
    time.sleep(2)

# 3. Verify on the backend
result = qr.verify_auth_result(session["session_id"], s["signature"])
if result["valid"]:
    print(result["session"]["user"])  # log in the user
```

## Context Manager

The client can be used as a context manager to ensure the HTTP connection pool is properly closed:

```python
with QRAuth(api_key="qrauth_xxx") as qr:
    code = qr.create("https://example.com")
```

## Error Handling

```python
from qrauth import QRAuth, AuthenticationError, RateLimitError

try:
    qr.create("https://example.com")
except AuthenticationError:
    print("Bad API key")
except RateLimitError as err:
    print(f"Rate limited. Retry after {err.retry_after}s")
```

| Exception              | HTTP Status | Description                |
|------------------------|-------------|----------------------------|
| `ValidationError`      | 400         | Request validation failed  |
| `AuthenticationError`  | 401         | Invalid or missing API key |
| `AuthorizationError`   | 403         | Insufficient permissions   |
| `NotFoundError`        | 404         | Resource not found         |
| `RateLimitError`       | 429         | Rate limit exceeded        |
| `QuotaExceededError`   | 429         | Plan quota exceeded        |
| `QRAuthError`          | *           | Base class for all errors  |

## License

MIT
