---
title: Webhooks
description: Receive real-time event notifications for scans, ephemeral claims, and more.
---

# Webhooks

QRAuth can push event notifications to your server over HTTPS. Configure a webhook URL on your App and QRAuth will POST a signed payload every time a relevant event occurs.

## Configuration

In the dashboard go to **Apps → your App → Webhooks** and enter your endpoint URL. The URL must be publicly reachable over HTTPS; localhost addresses are rejected.

::: warning SSRF protection
QRAuth validates webhook URLs against a blocklist of private IP ranges (RFC 1918, loopback, link-local) and cloud metadata endpoints before making any delivery attempt.
:::

---

## Events

| Event | Description |
|-------|-------------|
| `qr.scanned` | A QR code was scanned and a verification was performed |
| `ephemeral.claimed` | An ephemeral session was successfully claimed |
| `ephemeral.expired` | An ephemeral session expired without being claimed |

More events coming soon: `auth.approved`, `device.revoked`, `fraud.detected`.

---

## Payload Envelope

Every webhook POST has the same top-level envelope:

```json
{
  "id": "evt_01HXYZ...",
  "type": "qr.scanned",
  "createdAt": "2026-04-10T12:05:00Z",
  "data": { ... }
}
```

### `qr.scanned` data

```json
{
  "qrCodeId": "qr_01HXYZ...",
  "token": "abc123",
  "label": "Product A — Shelf 4B",
  "trustScore": 0.94,
  "proxyDetected": false,
  "signals": [],
  "location": { "lat": 52.5200, "lng": 13.4050 },
  "scannedAt": "2026-04-10T12:05:00Z"
}
```

### `ephemeral.claimed` data

```json
{
  "sessionId": "es_01HXYZ...",
  "token": "eph_tok_...",
  "scopes": ["door:unlock"],
  "deviceFingerprint": "fp_abc...",
  "metadata": { "zone": "B2" },
  "claimedAt": "2026-04-10T12:07:22Z"
}
```

### `ephemeral.expired` data

```json
{
  "sessionId": "es_01HXYZ...",
  "token": "eph_tok_...",
  "scopes": ["door:unlock"],
  "expiredAt": "2026-04-10T13:05:00Z"
}
```

---

## Signature Verification

Every webhook request includes an `X-QRAuth-Signature` header. Verify it to confirm the payload came from QRAuth and was not tampered with.

The signature is an HMAC-SHA256 of the raw request body using your **webhook secret** (available in the dashboard under **Apps → Webhooks**).

```typescript
import crypto from 'crypto'

function verifyWebhookSignature(
  rawBody: string,
  signature: string,
  secret: string,
): boolean {
  const expected = crypto
    .createHmac('sha256', secret)
    .update(rawBody, 'utf8')
    .digest('hex')

  return crypto.timingSafeEqual(
    Buffer.from(signature),
    Buffer.from(expected),
  )
}

// Express example
app.post('/webhooks/qrauth', express.raw({ type: '*/*' }), (req, res) => {
  const sig = req.headers['x-qrauth-signature'] as string

  if (!verifyWebhookSignature(req.body.toString(), sig, process.env.WEBHOOK_SECRET!)) {
    return res.status(401).send('Invalid signature')
  }

  const event = JSON.parse(req.body.toString())
  // handle event...
  res.sendStatus(200)
})
```

::: danger Always verify signatures
Never process a webhook payload without verifying the signature first. Use `crypto.timingSafeEqual` to prevent timing attacks.
:::

---

## Delivery & Retries

Webhook delivery is handled by a BullMQ queue with automatic retries on failure:

| Attempt | Delay |
|---------|-------|
| 1st | Immediate |
| 2nd | 30 seconds |
| 3rd | 5 minutes |
| 4th | 30 minutes |
| 5th | 2 hours |

After 5 failed attempts the event is marked as `dead` and no further delivery is attempted. Dead events are visible in the dashboard under **Apps → Webhooks → Delivery Log**.

### Success criteria

QRAuth considers a delivery successful when your endpoint returns any `2xx` HTTP status within 10 seconds. Return `200` immediately and process the payload asynchronously if your handler is slow.

### Idempotency

Retries will re-deliver the same event with the same `id`. Use the event `id` as an idempotency key in your handler to avoid processing the same event twice.
