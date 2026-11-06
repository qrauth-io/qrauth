---
title: Webhooks
description: Receive signed event notifications from QRAuth and verify them.
---

# Webhooks

QRAuth sends two kinds of webhooks. They are configured, keyed and signed differently.

| | App webhooks | Signing-key webhooks |
|---|---|---|
| Purpose | Product events (QR codes, scans, auth sessions, ephemeral sessions) | Security signal: a new signing key was created for your organization |
| Configured on | An App (`webhookUrl`) | The organization (security webhook endpoint) |
| Signature | HMAC-SHA-256 over the raw body | HMAC-SHA3-256 over the raw body |
| Header | `X-QRAuth-Signature: sha256=<hex>` | `X-QRAuth-Signature: sha3-256=<hex>` |
| Key | Lowercase hex SHA-256 of the app's client secret, used as an ASCII string | Base64-decoded security-webhook secret (32 bytes) |
| User-Agent | `QRAuth-Webhooks/1.0` | `QRAuth-Security-Webhook/1` |

Both kinds also send `Content-Type: application/json` and `X-QRAuth-Event: <event name>`. Always verify the signature over the exact bytes you received, before parsing the JSON.

---

## App webhooks

### Configuration

Set `webhookUrl` on an App when you create it (`POST /api/v1/apps`) or later (`PATCH /api/v1/apps/:id`). The URL must be an absolute `http` or `https` URL; use `https` in production. URLs that point to loopback, private, link-local, reserved or cloud-metadata addresses are rejected at registration and again at delivery time. Deliveries do not follow redirects and time out after 10 seconds.

### Events

| Event | Sent when |
|-------|-----------|
| `qr.created` | A QR code is issued |
| `qr.scanned` | A scan of one of your QR codes has been recorded and analysed |
| `qrcode.revoked` | A QR code was revoked automatically because its signing did not complete |
| `auth.approved` | A user approved an auth session for your app |
| `auth.denied` | A user denied an auth session for your app |
| `ephemeral.claimed` | An ephemeral session was claimed |
| `ephemeral.expired` | An ephemeral session was found expired |

### Payload

Every app webhook body has the same envelope:

```json
{
  "event": "qr.scanned",
  "timestamp": "2026-10-20T12:05:00.000Z",
  "data": { }
}
```

Examples of `data`:

```jsonc
// qr.scanned
{
  "qrCodeId": "clx...",
  "scanId": "clx...",
  "token": "aB3dE5fG",
  "trustScore": 100,
  "securityContext": {
    "algVersion": "hybrid-ecdsa-slhdsa-v1",
    "algVersionStatus": "accepted",
    "pqcProtected": true,
    "merkleBatchId": "9f2c..."
  },
  "payloadVersion": "v2"
}

// auth.approved, auth.denied
{ "sessionId": "clx...", "appId": "clx..." }

// ephemeral.claimed, ephemeral.expired
{ "sessionId": "clx..." }
```

`securityContext.pqcProtected` is `true` for a hybrid row (`hybrid-ecdsa-slhdsa-v1`) that has its Merkle data. `qr.created` carries the same `securityContext`. The verify response is authoritative for whether a given scan passed both legs.

Payloads may contain fields not shown here. Ignore fields you do not recognise.

### Signing key

The HMAC key for app webhooks is the lowercase hexadecimal SHA-256 digest of your app's client secret, used as an ASCII string (64 characters), not as 32 raw bytes. Rotating the client secret (`POST /api/v1/apps/:id/rotate-secret`) changes the webhook signing key for all subsequent deliveries.

### Delivery and retries

A delivery succeeds when your endpoint returns any `2xx` status within 10 seconds. Return quickly and process asynchronously if your handler is slow.

Failed deliveries are retried up to 5 attempts in total, with exponential backoff starting at 2 seconds (2 s, 4 s, 8 s, 16 s). Deliveries to a single destination origin are capped at 100 per minute per app; deliveries over the cap are retried with the same backoff. Each attempt is recorded in the dashboard under **Webhook Logs**.

Retries resend the same body byte for byte. Payloads do not carry a unique event ID; to deduplicate, key on a hash of the raw body.

---

## Signing-key webhooks

Every time a signing key is created for your organization, QRAuth sends a `signing-key.created` event to your organization's security webhook endpoint. An event you cannot match to a key creation or rotation you expected is a signal to investigate.

### Configuration

Register or rotate the endpoint (OWNER or ADMIN):

```http
POST /api/v1/organizations/:id/security-webhook
Content-Type: application/json

{ "url": "https://example.com/qrauth/security" }
```

The URL must use `https`. The response contains `secret`, a base64-encoded 32-byte value. It is returned only once; store it securely. Calling the endpoint again replaces the URL and issues a new secret. `DELETE /api/v1/organizations/:id/security-webhook` removes the endpoint.

### Payload

```json
{
  "eventId": "6f1c2b9e-...",
  "eventType": "signing-key.created",
  "occurredAt": "2026-10-20T12:00:00.000Z",
  "organizationId": "clx...",
  "signingKey": {
    "kid": "...",
    "algorithm": "ES256",
    "slhdsaAlgorithm": "slh-dsa-sha2-128s",
    "status": "ACTIVE",
    "createdAt": "2026-10-20T12:00:00.000Z"
  },
  "operatorIdentity": null
}
```

### Delivery and retries

Up to 4 attempts in total, with retries after 1 s, 5 s and 30 s. Use `eventId` to deduplicate.

---

## Verifying signatures

Each example below verifies both kinds of webhook. We tested every snippet against deliveries produced by the QRAuth signing code.

::: danger Always verify signatures
Verify the signature before parsing or acting on the payload. Compute it over the raw request body, not over re-serialised JSON, and compare in constant time.
:::

### Node.js

```javascript
import { createHash, createHmac, timingSafeEqual } from 'node:crypto';

// App webhooks: HMAC-SHA-256. The key is the lowercase hex SHA-256 of your
// app's client secret, used as an ASCII string.
export function verifyAppWebhook(rawBody, signatureHeader, clientSecret) {
  const key = createHash('sha256').update(clientSecret, 'utf8').digest('hex');
  const expected = 'sha256=' + createHmac('sha256', key).update(rawBody).digest('hex');
  return safeEqual(signatureHeader, expected);
}

// Signing-key webhooks: HMAC-SHA3-256. The key is the base64-decoded
// security-webhook secret returned when you registered the endpoint.
export function verifySigningKeyWebhook(rawBody, signatureHeader, base64Secret) {
  const key = Buffer.from(base64Secret, 'base64');
  const expected = 'sha3-256=' + createHmac('sha3-256', key).update(rawBody).digest('hex');
  return safeEqual(signatureHeader, expected);
}

function safeEqual(received, expected) {
  if (typeof received !== 'string') return false;
  const a = Buffer.from(received, 'utf8');
  const b = Buffer.from(expected, 'utf8');
  return a.length === b.length && timingSafeEqual(a, b);
}
```

Express handler for app webhooks:

```javascript
import express from 'express';
import { verifyAppWebhook } from './verify.mjs';

const app = express();

// Use the raw body: the signature covers the exact bytes QRAuth sent.
app.post('/webhooks/qrauth', express.raw({ type: 'application/json' }), (req, res) => {
  const signature = req.get('X-QRAuth-Signature');
  if (!verifyAppWebhook(req.body, signature, process.env.QRAUTH_CLIENT_SECRET)) {
    return res.status(401).send('Invalid signature');
  }
  const event = JSON.parse(req.body.toString('utf8'));
  // handle event.event / event.data ...
  res.sendStatus(200);
});

app.listen(3000);
```

### Python

```python
import base64
import hashlib
import hmac


def verify_app_webhook(raw_body: bytes, signature_header: str, client_secret: str) -> bool:
    # HMAC-SHA-256; key = lowercase hex SHA-256 of the client secret, as ASCII bytes.
    key = hashlib.sha256(client_secret.encode("utf-8")).hexdigest().encode("ascii")
    expected = "sha256=" + hmac.new(key, raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest((signature_header or "").encode("utf-8"), expected.encode("ascii"))


def verify_signing_key_webhook(raw_body: bytes, signature_header: str, base64_secret: str) -> bool:
    # HMAC-SHA3-256; key = base64-decoded security-webhook secret.
    key = base64.b64decode(base64_secret)
    expected = "sha3-256=" + hmac.new(key, raw_body, hashlib.sha3_256).hexdigest()
    return hmac.compare_digest((signature_header or "").encode("utf-8"), expected.encode("ascii"))
```

With Flask, pass `request.get_data()` as `raw_body` and `request.headers.get("X-QRAuth-Signature")` as `signature_header`.

### PHP

```php
// HMAC-SHA-256; key = lowercase hex SHA-256 of the client secret (as a string).
function qrauth_verify_app_webhook(string $rawBody, string $signatureHeader, string $clientSecret): bool
{
    $key = hash('sha256', $clientSecret);
    $expected = 'sha256=' . hash_hmac('sha256', $rawBody, $key);
    return hash_equals($expected, $signatureHeader);
}

// HMAC-SHA3-256; key = base64-decoded security-webhook secret.
function qrauth_verify_signing_key_webhook(string $rawBody, string $signatureHeader, string $base64Secret): bool
{
    $key = base64_decode($base64Secret, true);
    if ($key === false) {
        return false;
    }
    $expected = 'sha3-256=' . hash_hmac('sha3-256', $rawBody, $key);
    return hash_equals($expected, $signatureHeader);
}
```

Read the body with `file_get_contents('php://input')` and the header with `$_SERVER['HTTP_X_QRAUTH_SIGNATURE'] ?? ''`.

### Go

Requires Go 1.24 or later for `crypto/sha3`.

```go
package webhooks

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha3" // Go 1.24+
	"encoding/base64"
	"encoding/hex"
	"hash"
)

// VerifyAppWebhook checks an app webhook (HMAC-SHA-256). The key is the
// lowercase hex SHA-256 of the client secret, used as ASCII bytes.
func VerifyAppWebhook(rawBody []byte, signatureHeader, clientSecret string) bool {
	sum := sha256.Sum256([]byte(clientSecret))
	key := []byte(hex.EncodeToString(sum[:]))
	mac := hmac.New(sha256.New, key)
	mac.Write(rawBody)
	expected := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(signatureHeader), []byte(expected))
}

// VerifySigningKeyWebhook checks a signing-key webhook (HMAC-SHA3-256). The
// key is the base64-decoded security-webhook secret.
func VerifySigningKeyWebhook(rawBody []byte, signatureHeader, base64Secret string) bool {
	key, err := base64.StdEncoding.DecodeString(base64Secret)
	if err != nil {
		return false
	}
	mac := hmac.New(func() hash.Hash { return sha3.New256() }, key)
	mac.Write(rawBody)
	expected := "sha3-256=" + hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(signatureHeader), []byte(expected))
}
```

Read the body with `io.ReadAll(r.Body)` and the header with `r.Header.Get("X-QRAuth-Signature")`.
