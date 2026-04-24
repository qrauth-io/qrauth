---
title: Proximity API
description: Create and verify signed JWT attestations proving a device was physically near a QR code.
---

# Proximity API

The Proximity API issues signed JWT attestations that cryptographically prove a scanning device was within a specified radius of a registered QR code location at a specific time. Attestations are signed with domain-separated ECDSA P-256 and verifiable offline using the org's public key and the QRAuth SDK (or manual domain-prefix reconstruction — see [Offline Verification](#offline-verification)).

## How It Works

1. A device scans a QR code and sends its GPS coordinates.
2. The API computes the distance to the QR code's registered location.
3. If the device is within the allowed radius, a signed JWT attestation is returned.
4. The attestation can be forwarded to any service and verified independently — no round-trip to QRAuth is needed.

## JWT Claims

Proximity attestation JWTs contain the following claims:

| Claim | Type | Description |
|-------|------|-------------|
| `sub` | string | QR code token |
| `iss` | string | `"qrauth.io"` |
| `iat` | number | Issued-at timestamp (Unix) |
| `exp` | number | Expiry timestamp (Unix, 5 minutes after `iat`) |
| `loc` | object | `{ lat, lng }` of the scanning device |
| `proximity` | object | Proximity result (see below) |

**`proximity` object:**

| Field | Type | Description |
|-------|------|-------------|
| `matched` | boolean | Device was within `radiusM` of the QR code location |
| `distanceM` | number | Measured distance in metres |
| `radiusM` | number | Configured allowed radius in metres |

---

## Create Proximity Attestation

`POST /api/v1/proximity/:token`

**Headers:** `X-API-Key: <key>` or no auth for public QR codes

**Path parameters:**

| Param | Type | Description |
|-------|------|-------------|
| `token` | string | QR code token |

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `clientLat` | number | Yes | Latitude of the scanning device (decimal degrees) |
| `clientLng` | number | Yes | Longitude of the scanning device (decimal degrees) |

**Response (200):**

```json
{
  "jwt": "eyJhbGciOiJFUzI1NiIsImtpZCI6ImtleV8wMSJ9...",
  "claims": {
    "sub": "abc123",
    "iss": "qrauth.io",
    "iat": 1744286700,
    "exp": 1744287000,
    "loc": { "lat": 52.5200, "lng": 13.4050 },
    "proximity": {
      "matched": true,
      "distanceM": 14,
      "radiusM": 50
    }
  },
  "publicKey": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQY...\n-----END PUBLIC KEY-----",
  "keyId": "key_01HXYZ..."
}
```

The `publicKey` is the PEM-encoded ECDSA P-256 public key that signed this JWT. Cache it by `keyId` — keys rotate infrequently.

**Error (422) — QR code has no location:**

```json
{
  "statusCode": 422,
  "error": "Unprocessable Entity",
  "message": "QR code does not have a registered location"
}
```

---

## Verify Proximity Attestation

`POST /api/v1/proximity/verify`

Verify a proximity JWT server-side. You can optionally supply the public key directly; otherwise the API resolves it by `keyId` from the JWT header.

**Headers:** None required (public endpoint)

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `jwt` | string | Yes | The proximity attestation JWT |
| `publicKey` | string | No | PEM-encoded public key. If omitted the API resolves the key by `kid`. |

**Response (200) — valid:**

```json
{
  "valid": true,
  "claims": {
    "sub": "abc123",
    "iss": "qrauth.io",
    "iat": 1744286700,
    "exp": 1744287000,
    "loc": { "lat": 52.5200, "lng": 13.4050 },
    "proximity": {
      "matched": true,
      "distanceM": 14,
      "radiusM": 50
    }
  },
  "error": null
}
```

**Response (200) — invalid:**

```json
{
  "valid": false,
  "claims": null,
  "error": "jwt expired"
}
```

Possible `error` values: `"jwt expired"`, `"invalid signature"`, `"malformed jwt"`, `"unknown key"`.

---

## Offline Verification

Proximity attestation JWTs use **domain-separated signing** — the ECDSA signature
covers `qrauth:ecdsa-canonical:v1:header.payload`, not the standard `header.payload`.
Standard JWT libraries (`jose`, `PyJWT`) will reject these tokens.

**Recommended:** Use the QRAuth SDK's `verifyProximityAttestation()` method, which
handles the domain prefix automatically. See the
[Proximity Guide](/guide/proximity#offline-verification-without-the-sdk) for SDK
examples and manual verification code.

```typescript
import { QRAuth } from '@qrauth/node';

const qrauth = new QRAuth({ apiKey: process.env.QRAUTH_API_KEY! });
const result = await qrauth.verifyProximityAttestation({
  jwt: attestationJwt,
  publicKey: pemPublicKey, // optional — omit for server-side key resolution
});

console.log('Proximity matched:', result.claims?.proximity?.matched);
```

::: warning
Do **not** use `jose.jwtVerify()` or `jwt.decode()` — these verify over un-prefixed
bytes and will always fail on QRAuth proximity JWTs.
:::
