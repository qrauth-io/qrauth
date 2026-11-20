# Proximity Verification

A proximity attestation states that the device reported a location within Y metres of the QR code's registered location at time T, signed by the issuing organization. The location is reported by the client; the attestation is not proof of physical presence.

Attestations are ES256-style JWTs with a domain-separated signature, so standard JWT libraries (`jose`, `jsonwebtoken`, `PyJWT`, `jwt-go`) cannot verify them directly. Verify them with the QRAuth verify endpoint or the Node SDK (see [Signature Format](#signature-format) below).

## How it works

1. The client submits its reported coordinates (`clientLat`, `clientLng`), the relying-party ID (`rpId`) and a device identifier (`deviceFingerprint`).
2. The server computes the Haversine distance between the reported location and the QR code's registered location.
3. If the QR has no registered location, attestation is rejected with `400`.
4. The server issues a domain-separated ES256 JWT signed with the organization's ECDSA-P256 signing key (see [Signature Format](#signature-format) below).
5. The JWT contains proximity claims, including whether the reported coordinates fall inside the registered radius.
6. The relying party verifies the JWT with `POST /api/v1/proximity/verify` (or the Node SDK, which calls that endpoint).

---

## API reference

### Create attestation

```
POST /api/v1/proximity/:token
```

**Request body:**

```json
{
  "clientLat": 37.9838,
  "clientLng": 23.7275,
  "rpId": "app.example.com",
  "deviceFingerprint": "<stable device identifier>"
}
```

| Field | Required | Description |
|---|---|---|
| `clientLat` | Yes | Reported latitude (-90 to 90) |
| `clientLng` | Yes | Reported longitude (-180 to 180) |
| `rpId` | Yes | Relying-party identifier (1-255 chars). Becomes the `aud` claim. |
| `deviceFingerprint` | Yes | Caller-supplied device identifier (1-1024 chars). Hashed into the `device` claim. |

**Response:**

```json
{
  "jwt": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Ii4uLiJ9...",
  "claims": {
    "sub": "a3f2...c8d1",
    "iss": "org_8Hkj2x",
    "aud": "app.example.com",
    "device": "9b1e...04aa",
    "alg_version": "proximity-es256-v1",
    "loc": "5c0e...71f2",
    "proximity": {
      "matched": true,
      "distanceM": 12,
      "radiusM": 50
    },
    "iat": 1744281600,
    "exp": 1744281900
  },
  "publicKey": "-----BEGIN PUBLIC KEY-----\n...",
  "keyId": "key_abc123"
}
```

### Verify attestation

```
POST /api/v1/proximity/verify
```

**Request body:**

```json
{
  "jwt": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Ii4uLiJ9...",
  "publicKey": "-----BEGIN PUBLIC KEY-----\n..."
}
```

Omit `publicKey` to have the server resolve the key from the `iss` claim and the header `kid` (active or rotated keys). If you supply `publicKey`, the server verifies against that key.

**Response:**

```json
{
  "valid": true,
  "claims": { ... }
}
```

`valid: true` means the signature, expiry, `iat` and `alg_version` checks passed. Your application decides what to accept based on the claims, for example `iss`, `aud` and `proximity.matched`. On failure the response is `{ "valid": false, "error": "INVALID_ATTESTATION" }`.

---

## JWT claims

Header: `{ "alg": "ES256", "typ": "JWT", "kid": "<signing key ID>" }`.

| Claim | Type | Description |
|---|---|---|
| `iss` | `string` | Organization ID that owns the QR code |
| `sub` | `string` | SHA3-256 hex of `qrauth:proximity-sub:v1:` + QR token (not the token itself) |
| `aud` | `string` | The `rpId` supplied in the request |
| `device` | `string` | SHA3-256 hex of `qrauth:proximity-device:v1:` + the supplied `deviceFingerprint` |
| `loc` | `string` | The QR code's stored location hash (`geoHash`) for its registered location; the device's coordinates are not included |
| `proximity.matched` | `boolean` | Whether the reported coordinates fall inside the registered radius |
| `proximity.distanceM` | `number` | Computed Haversine distance in metres (rounded) |
| `proximity.radiusM` | `number` | The QR code's registered geo-fence radius |
| `alg_version` | `string` | `proximity-es256-v1` |
| `iat` | `number` | Issued-at (Unix seconds) |
| `exp` | `number` | Expires-at — issued-at + 300 seconds (5-minute TTL) |

::: info TTL
Attestations expire after **5 minutes**. For long-running workflows, request a fresh attestation at the point of use rather than storing the JWT.
:::

---

## SDK

### Get proximity attestation

```ts
import { QRAuth } from '@qrauth/node';

const qrauth = new QRAuth({ apiKey: process.env.QRAUTH_API_KEY! });

const attestation = await qrauth.getProximityAttestation('AbCdEfGh', {
  clientLat: 37.9838,
  clientLng: 23.7275,
  rpId: 'app.example.com',
  deviceFingerprint: deviceId,
});

// attestation.jwt        — signed JWT to pass to the verifying party
// attestation.claims     — decoded claims (convenience, not authoritative)
// attestation.publicKey  — PEM public key of the signing key
// attestation.keyId      — identifies the signing key
```

### Verify attestation

`verifyProximityAttestation(jwt, publicKey?)` sends the JWT (and the optional key) to `POST /api/v1/proximity/verify`.

```ts
// Server resolves the public key from iss + kid
const result = await qrauth.verifyProximityAttestation(attestation.jwt);

if (
  result.valid &&
  result.claims?.aud === 'app.example.com' &&
  (result.claims?.proximity as { matched?: boolean })?.matched
) {
  grantAccess();
}
```

---

## Signature Format

QRAuth proximity JWTs use **domain-separated ECDSA-P256 signing**. The signature is
computed with SHA-256 over `qrauth:ecdsa-canonical:v1:` + `header.payload` (UTF-8), not over the
standard `header.payload` that RFC 7515 specifies. The signature is DER-encoded (not the
raw `r || s` form of RFC 7518) and base64url-encoded in the third JWT segment. The prefix
separates proximity signatures from other uses of ES256 keys.

**Consequence:** Standard JWT libraries (`jose`, `jsonwebtoken`, `PyJWT`, `jwt-go`) will reject
these tokens with "invalid signature". Verify them with `POST /api/v1/proximity/verify` or the
Node SDK.

---

## Use cases

### Attendance verification

Generate an attestation when the student's phone scans the classroom QR. Submit the JWT to your LMS, which verifies it with the verify endpoint.

```ts
// In your attendance handler (server)
const attestation = await qrauth.getProximityAttestation(token, {
  clientLat: req.body.lat,
  clientLng: req.body.lng,
  rpId: 'lms.example.edu',
  deviceFingerprint: req.body.deviceId,
});

// Send attestation.jwt to the LMS
await lms.recordAttendance(studentId, attestation.jwt);
```

### Location-gated transactions

Gate a payment flow on a fresh attestation whose reported location is inside the till's radius. Treat it as one risk signal among others, since the location is reported by the client.

```ts
const attestation = await qrauth.getProximityAttestation(posQrToken, {
  clientLat: coords.latitude,
  clientLng: coords.longitude,
  rpId: 'pay.example.com',
  deviceFingerprint: deviceId,
});

if (!attestation.claims.proximity.matched) {
  throw new Error('You must be at the till to complete this payment');
}

await initiatePayment({ proximityJwt: attestation.jwt });
```

### Visit stamps

Issue a souvenir NFT or loyalty stamp when the user's reported location is at the venue.

```ts
// Client scans QR at the museum entrance
const attestation = await qrauth.getProximityAttestation(entranceToken, {
  clientLat: gps.lat,
  clientLng: gps.lng,
  rpId: 'stamps.example.com',
  deviceFingerprint: deviceId,
});

// Backend mints the stamp
await mintVisitStamp({
  userId,
  locationId: 'museum-athens',
  attestation: attestation.jwt,
});
```

---

## Notes

- The QR code must have a registered location (`lat`, `lng`, `radiusM`) when created. Codes without location data return `400`.
- Distance is computed using the **Haversine formula** (spherical Earth, accurate to within ~0.3% at typical geo-fence scales).
- `proximity.matched` is `true` when `distanceM <= radiusM`.
- A `distanceM` of `0` is valid — it means the client reported GPS coordinates identical to the registered point.
