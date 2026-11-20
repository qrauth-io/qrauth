---
title: Proximity API
description: Create and verify signed proximity attestations for client-reported locations near a QR code.
---

# Proximity API

A proximity attestation states that the device reported a location within Y metres of the QR code's registered location at time T, signed by the issuing organization. The location is reported by the client; the attestation is not proof of physical presence.

Attestations are signed with domain-separated ECDSA-P256 (see [Signature Format](#signature-format)). Verify them with `POST /api/v1/proximity/verify` or the Node SDK, which calls that endpoint.

## How It Works

1. The client sends its reported coordinates, the relying-party ID (`rpId`) and a device identifier (`deviceFingerprint`).
2. The API computes the distance to the QR code's registered location.
3. A signed JWT attestation is returned; `proximity.matched` records whether the reported location is within the registered radius.
4. The relying party verifies the attestation with the verify endpoint and checks the claims it relies on.

## JWT Claims

Header: `{ "alg": "ES256", "typ": "JWT", "kid": "<signing key ID>" }`.

Proximity attestation JWTs contain the following claims:

| Claim | Type | Description |
|-------|------|-------------|
| `iss` | string | ID of the organization that owns the QR code |
| `sub` | string | SHA3-256 hex of `qrauth:proximity-sub:v1:` + QR token (the raw token is not included) |
| `aud` | string | The `rpId` supplied in the request |
| `device` | string | SHA3-256 hex of `qrauth:proximity-device:v1:` + the supplied `deviceFingerprint` |
| `loc` | string | The QR code's stored location hash (`geoHash`) for its registered location; the device's coordinates are not included |
| `proximity` | object | Proximity result (see below) |
| `alg_version` | string | `proximity-es256-v1` |
| `iat` | number | Issued-at timestamp (Unix seconds) |
| `exp` | number | Expiry timestamp (Unix seconds, `iat` + 300) |

**`proximity` object:**

| Field | Type | Description |
|-------|------|-------------|
| `matched` | boolean | The reported coordinates are within `radiusM` of the QR code location |
| `distanceM` | number | Computed distance in metres (rounded) |
| `radiusM` | number | Configured allowed radius in metres |

---

## Create Proximity Attestation

`POST /api/v1/proximity/:token`

**Headers:** None required (public endpoint, rate-limited)

**Path parameters:**

| Param | Type | Description |
|-------|------|-------------|
| `token` | string | QR code token |

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `clientLat` | number | Yes | Reported latitude (decimal degrees, -90 to 90) |
| `clientLng` | number | Yes | Reported longitude (decimal degrees, -180 to 180) |
| `rpId` | string | Yes | Relying-party identifier (1-255 chars). Becomes the `aud` claim. |
| `deviceFingerprint` | string | Yes | Caller-supplied device identifier (1-1024 chars). Hashed into the `device` claim. |

**Response (200):**

```json
{
  "jwt": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleV8wMSJ9...",
  "claims": {
    "sub": "5d2c...e91a",
    "iss": "org_01HX...",
    "aud": "app.example.com",
    "device": "9b1e...04aa",
    "alg_version": "proximity-es256-v1",
    "loc": "5c0e...71f2",
    "proximity": {
      "matched": true,
      "distanceM": 14,
      "radiusM": 50
    },
    "iat": 1744286700,
    "exp": 1744287000
  },
  "publicKey": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQY...\n-----END PUBLIC KEY-----",
  "keyId": "key_01HXYZ..."
}
```

The `publicKey` is the PEM-encoded ECDSA-P256 public key that signed this JWT.

**Errors:**

| Status | Cause |
|--------|-------|
| `400` | Invalid body, or the QR code has no registered location |
| `404` | QR code not found |
| `410` | QR code is not active |

```json
{
  "statusCode": 400,
  "error": "Error",
  "message": "QR code has no registered location — proximity attestation requires a geo-enabled QR code"
}
```

---

## Verify Proximity Attestation

`POST /api/v1/proximity/verify`

Verify a proximity JWT server-side. If you supply `publicKey`, the API verifies against that key; otherwise it resolves the key from the `iss` claim and the header `kid` (active or rotated keys).

**Headers:** None required (public endpoint, rate-limited)

**Request body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `jwt` | string | Yes | The proximity attestation JWT |
| `publicKey` | string | No | PEM-encoded public key. If omitted the API resolves the key by `iss` and `kid`. |

**Response (200) — valid:**

```json
{
  "valid": true,
  "claims": {
    "sub": "5d2c...e91a",
    "iss": "org_01HX...",
    "aud": "app.example.com",
    "device": "9b1e...04aa",
    "alg_version": "proximity-es256-v1",
    "loc": "5c0e...71f2",
    "proximity": {
      "matched": true,
      "distanceM": 14,
      "radiusM": 50
    },
    "iat": 1744286700,
    "exp": 1744287000
  }
}
```

`valid: true` means the signature, expiry, `iat` and `alg_version` checks passed. Your application decides what to accept based on the claims, for example `iss`, `aud` and `proximity.matched`.

**Response (200) — invalid:**

```json
{
  "valid": false,
  "error": "INVALID_ATTESTATION"
}
```

Every verification failure returns the single `error` value `INVALID_ATTESTATION`.

---

## Signature Format

Proximity attestation JWTs use **domain-separated signing**. The ECDSA-P256 signature
is computed with SHA-256 over `qrauth:ecdsa-canonical:v1:` + `header.payload`, not over the
standard `header.payload`. The signature is DER-encoded and base64url-encoded in the third
JWT segment. Standard JWT libraries (`jose`, `jsonwebtoken`, `PyJWT`, `jwt-go`) will reject
these tokens.

Use the verify endpoint, or the Node SDK's `verifyProximityAttestation(jwt, publicKey?)`,
which sends the request to `POST /api/v1/proximity/verify`. See the
[Proximity Guide](/guide/proximity) for examples.

```typescript
import { QRAuth } from '@qrauth/node';

const qrauth = new QRAuth({ apiKey: process.env.QRAUTH_API_KEY! });
const result = await qrauth.verifyProximityAttestation(
  attestationJwt,
  pemPublicKey, // optional — omit for server-side key resolution
);

console.log('Proximity matched:', result.claims?.proximity);
```

::: warning
Do **not** use `jose.jwtVerify()` or `jwt.decode()` — these verify over un-prefixed
bytes and will always fail on QRAuth proximity JWTs.
:::
