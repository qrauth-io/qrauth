# Proximity Verification

Scanning a QR code is an inherently physical act — the scanner must be within camera range of the code. QRAuth's Proximity API converts that implicit physical fact into a cryptographically verifiable claim: a signed JWT attestation that says "device X was within Y metres of QR token Z at time T."

Third parties can verify this JWT offline using the org's public key. No API call is required at verify time.

## How it works

1. Client submits GPS coordinates alongside the scan (`clientLat`, `clientLng`).
2. The server computes the Haversine distance between the client location and the QR code's registered location.
3. If the QR has no registered location, attestation is rejected with `400`.
4. The server issues a compact ES256 JWT signed with the org's ECDSA-P256 signing key.
5. The JWT contains proximity claims including whether the device was inside the registered radius.
6. Any party holding the org's public key can verify the JWT without a network round-trip.

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
  "clientLng": 23.7275
}
```

**Response:**

```json
{
  "jwt": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9...",
  "claims": {
    "sub": "a3f2...c8d1",
    "iss": "org_8Hkj2x",
    "loc": "sw7b24",
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
  "jwt": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9...",
  "publicKey": "-----BEGIN PUBLIC KEY-----\n..."
}
```

Omit `publicKey` to have the server resolve it from the `iss` claim. Supply it for fully offline verification.

**Response:**

```json
{
  "valid": true,
  "claims": { ... }
}
```

---

## JWT claims

| Claim | Type | Description |
|---|---|---|
| `sub` | `string` | SHA-256 hash of the QR token (not the token itself) |
| `iss` | `string` | Organization ID that owns the QR code |
| `loc` | `string` | Geohash of the QR code's registered location |
| `proximity.matched` | `boolean` | Whether the device was inside the registered radius |
| `proximity.distanceM` | `number` | Computed Haversine distance in metres |
| `proximity.radiusM` | `number` | The QR code's registered geo-fence radius |
| `iat` | `number` | Issued-at (Unix seconds) |
| `exp` | `number` | Expires-at — issued-at + 300 seconds (5-minute TTL) |

::: info TTL
Attestations expire after **5 minutes**. For long-running workflows, request a fresh attestation at the point of use rather than storing the JWT.
:::

---

## SDK

### Get proximity attestation

::: code-group

```ts [Node.js]
import { QRAuth } from '@qrauth/node';

const qrauth = new QRAuth({ apiKey: process.env.QRAUTH_API_KEY! });

const attestation = await qrauth.getProximityAttestation('AbCdEfGh', {
  clientLat: 37.9838,
  clientLng: 23.7275,
});

// attestation.jwt        — signed JWT to pass to the verifying party
// attestation.claims     — decoded claims (convenience, not authoritative)
// attestation.publicKey  — PEM public key for offline verification
// attestation.keyId      — identifies the signing key
```

```python [Python]
from qrauth import QRAuth

qrauth = QRAuth(api_key=os.environ["QRAUTH_API_KEY"])

attestation = qrauth.get_proximity_attestation(
    "AbCdEfGh",
    client_lat=37.9838,
    client_lng=23.7275,
)
```

:::

### Verify attestation

::: code-group

```ts [Node.js]
// Online — server resolves the public key from the iss claim
const result = await qrauth.verifyProximityAttestation({
  jwt: attestation.jwt,
});

// Offline — provide the public key you received at attestation time
const result = await qrauth.verifyProximityAttestation({
  jwt: attestation.jwt,
  publicKey: attestation.publicKey,
});

if (result.valid && result.claims?.proximity?.matched) {
  grantAccess();
}
```

```python [Python]
# Offline verification — no API call needed
result = qrauth.verify_proximity_attestation(
    jwt=attestation["jwt"],
    public_key=attestation["publicKey"],
)

if result["valid"] and result["claims"]["proximity"]["matched"]:
    grant_access()
```

:::

---

## Offline verification without the SDK

The JWT is standard ES256. Any JWT library can verify it.

::: code-group

```ts [Node.js (jose)]
import { jwtVerify, importSPKI } from 'jose';

const publicKey = await importSPKI(pemPublicKey, 'ES256');

const { payload } = await jwtVerify(jwt, publicKey);

const withinRadius = payload.proximity.matched;
const distanceM    = payload.proximity.distanceM;
```

```python [Python (PyJWT)]
import jwt

decoded = jwt.decode(
    token,
    public_key_pem,
    algorithms=["ES256"],
)

within_radius = decoded["proximity"]["matched"]
distance_m    = decoded["proximity"]["distanceM"]
```

:::

---

## Use cases

### Attendance verification

Generate an attestation when the student's phone scans the classroom QR. Submit the JWT to your LMS. The LMS verifies it offline — no QRAuth dependency at verify time.

```ts
// In your attendance handler (server)
const attestation = await qrauth.getProximityAttestation(token, {
  clientLat: req.body.lat,
  clientLng: req.body.lng,
});

// Send attestation.jwt to the LMS
await lms.recordAttendance(studentId, attestation.jwt);
```

### Location-gated transactions

Unlock a payment flow only after proving the device is at the point of sale.

```ts
const attestation = await qrauth.getProximityAttestation(posQrToken, {
  clientLat: coords.latitude,
  clientLng: coords.longitude,
});

if (!attestation.claims.proximity.matched) {
  throw new Error('You must be at the till to complete this payment');
}

await initiatePayment({ proximityJwt: attestation.jwt });
```

### Proof of visit

Issue a souvenir NFT or loyalty stamp only when the user physically visits a location.

```ts
// Client scans QR at the museum entrance
const attestation = await qrauth.getProximityAttestation(entranceToken, {
  clientLat: gps.lat,
  clientLng: gps.lng,
});

// Backend mints the stamp
await mintVisitStamp({
  userId,
  locationId: 'museum-athens',
  proof: attestation.jwt,
});
```

---

## Notes

- The QR code must have a registered location (`lat`, `lng`, `radiusM`) when created. Codes without location data return `400`.
- Distance is computed using the **Haversine formula** (spherical Earth, accurate to within ~0.3% at typical geo-fence scales).
- `proximity.matched` is `true` when `distanceM <= radiusM`.
- A `distanceM` of `0` is valid — it means the client reported GPS coordinates identical to the registered point.
