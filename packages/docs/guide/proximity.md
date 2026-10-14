# Proximity Verification

Scanning a QR code is an inherently physical act — the scanner must be within camera range of the code. QRAuth's Proximity API converts that implicit physical fact into a cryptographically verifiable claim: a signed JWT attestation that says "device X was within Y metres of QR token Z at time T."

Third parties can verify this JWT offline using the org's public key and QRAuth's domain-separated verification procedure. No API call is required at verify time — but standard JWT libraries (`jose`, `PyJWT`) cannot verify the signature directly; use the QRAuth SDK or replicate the domain-separation prefix (see [Offline Verification](#offline-verification-without-the-sdk) below).

## How it works

1. Client submits GPS coordinates alongside the scan (`clientLat`, `clientLng`).
2. The server computes the Haversine distance between the client location and the QR code's registered location.
3. If the QR has no registered location, attestation is rejected with `400`.
4. The server issues a domain-separated ES256 JWT signed with the org's ECDSA-P256 signing key (see [Signature Format](#signature-format) below).
5. The JWT contains proximity claims including whether the device was inside the registered radius.
6. Any party holding the org's public key can verify the JWT using the QRAuth SDK or the domain-separated verification procedure — no network round-trip required.

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

## Signature Format

QRAuth proximity JWTs use **domain-separated ECDSA-P256 signing**. The signature is
computed over `qrauth:ecdsa-canonical:v1:` + `header.payload` (UTF-8), not over the
standard `header.payload` that RFC 7515 specifies. This is a deliberate security
hardening ([Audit-2 N-2](./security.md)) that prevents cross-protocol signature
confusion — a signature produced for a QRAuth proximity attestation cannot be replayed
against any other ES256 verifier, and vice versa.

**Consequence:** Standard JWT libraries (`jose`, `jsonwebtoken`, `PyJWT`) will reject
these tokens with "invalid signature" because they verify over the un-prefixed bytes.
Use the QRAuth SDK for verification, or replicate the prefix manually (see below).

---

## Offline verification without the SDK

QRAuth proximity JWTs use domain-separated signing — the ECDSA signature covers
`qrauth:ecdsa-canonical:v1:` prepended to the standard `header.payload` signing input.
Standard JWT libraries will reject these tokens. You have two options:

### Option A: Use the QRAuth SDK (recommended)

::: code-group

```ts [Node.js]
import { QRAuth } from '@qrauth/node';

const qrauth = new QRAuth({ apiKey: process.env.QRAUTH_API_KEY! });

// Online — server resolves the public key from the iss claim
const result = await qrauth.verifyProximityAttestation({ jwt: attestationJwt });

// Offline — provide the public key you received at attestation time
const result = await qrauth.verifyProximityAttestation({
  jwt: attestationJwt,
  publicKey: pemPublicKey,
});

if (result.valid && result.claims?.proximity?.matched) {
  grantAccess();
}
```

```python [Python]
result = qrauth.verify_proximity_attestation(
    jwt=attestation["jwt"],
    public_key=attestation["publicKey"],
)

if result["valid"] and result["claims"]["proximity"]["matched"]:
    grant_access()
```

:::

### Option B: Manual domain-separated verification

If you cannot use the SDK, replicate the domain prefix before verifying:

::: code-group

```ts [Node.js (crypto)]
import { createVerify } from 'node:crypto';

// Split the JWT
const [headerB64, payloadB64, signatureB64] = jwt.split('.');

// Domain-separated signing input — this is what was actually signed
const DOMAIN_PREFIX = 'qrauth:ecdsa-canonical:v1:';
const signingInput = DOMAIN_PREFIX + headerB64 + '.' + payloadB64;

// Verify with Node's crypto module (NOT jose — jose doesn't support custom prefixes)
const verifier = createVerify('SHA256');
verifier.update(signingInput, 'utf8');
verifier.end();
const valid = verifier.verify(pemPublicKey, signatureB64, 'base64url');

// Decode claims
const claims = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));
const withinRadius = claims.proximity.matched;
const distanceM = claims.proximity.distanceM;
```

```python [Python (cryptography)]
import base64, json
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes, serialization

# Split the JWT
header_b64, payload_b64, signature_b64 = jwt_string.split('.')

# Domain-separated signing input
DOMAIN_PREFIX = 'qrauth:ecdsa-canonical:v1:'
signing_input = (DOMAIN_PREFIX + header_b64 + '.' + payload_b64).encode('utf-8')

# Load the public key
public_key = serialization.load_pem_public_key(pem_public_key.encode())

# Verify (raises InvalidSignature on failure)
# Note: the signature is base64url-encoded DER
sig_bytes = base64.urlsafe_b64decode(signature_b64 + '==')
public_key.verify(sig_bytes, signing_input, ec.ECDSA(hashes.SHA256()))

# Decode claims
claims = json.loads(base64.urlsafe_b64decode(payload_b64 + '=='))
within_radius = claims['proximity']['matched']
distance_m = claims['proximity']['distanceM']
```

:::

::: warning
Do **not** use `jose.jwtVerify()` or `PyJWT`'s `jwt.decode()` for QRAuth proximity
JWTs. These libraries verify over the standard `header.payload` bytes and will always
return "invalid signature" for domain-separated tokens.
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
