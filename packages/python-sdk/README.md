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
    "https://parking.gr/pay",
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

### `QRAuth(api_key, *, base_url="https://qrauth.io")`

| Parameter  | Type   | Required | Description                                   |
|------------|--------|----------|-----------------------------------------------|
| `api_key`  | `str`  | Yes      | Your API key (starts with `qrauth_`)          |
| `base_url` | `str`  | No       | API base URL. Defaults to `https://qrauth.io` |

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

Create up to 100 QR codes in a single request.

```python
result = qr.bulk([
    {"destination": "https://example.com/1", "label": "Meter 1"},
    {"destination": "https://example.com/2", "label": "Meter 2"},
])
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
