# QRAuth Signer Service

Standalone signing service for QRAuth. In production all signing operations run here
(`ECDSA_SIGNER=http`, `SLH_DSA_SIGNER=http`): the API sends canonical bytes and receives
signatures over a narrow HTTP API.

Tenant ECDSA-P256 and SLH-DSA-SHA2-128s private keys are generated on the API host,
encrypted at rest (AES-256-GCM envelope `qrauth-kek-v1`, key `SIGNER_MASTER_KEY`), and
provisioned to the signer host.

## Architecture

Deploy the signer on a separate host reachable only over the private network (it binds
to `127.0.0.1` unless `SIGNER_HOST` is set). The API server communicates with it over
that network using bearer token authentication.

Endpoints:

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/healthz` | Health check (unauthenticated) |
| `GET` | `/internal/stats` | Key-cache and MAC-session counters |
| `POST` | `/v1/sign` | SLH-DSA-SHA2-128s signature |
| `POST` | `/v1/sign-ecdsa` | ECDSA-P256 signature over a domain-prefixed canonical payload |
| `POST` | `/v1/sign-ecdsa-jws` | ES256 signature over a compact JWS signing input |
| `POST` | `/v1/sign-rsa-jws` | RS256 signature over a compact JWS signing input |
| `POST` | `/v1/mac/session` | Register a Living Codes MAC session (frame secret derived via HKDF from `ANIMATED_QR_SECRET`) |
| `POST` | `/v1/mac/sign` | HMAC-SHA-256 frame tag (8 bytes, 16 hex chars) for a session |
| `POST` | `/v1/mac/verify` | Constant-time frame tag check for a session |
| `POST` | `/v1/keys/:keyId` | Receive encrypted key envelopes |
| `GET` | `/v1/keys/:keyId/public` | Retrieve public key |

All endpoints except `/healthz` require the bearer token.

## Configuration

| Variable | Required | Description |
|----------|----------|-------------|
| `SIGNER_HOST` | No | Listen address (default: `127.0.0.1`; in production the private network IP, e.g. `10.0.0.2`) |
| `SIGNER_PORT` | No | Listen port (default: `7788`) |
| `SIGNER_TOKEN` | Yes | Bearer token (min 32 chars). Generate: `openssl rand -hex 32` |
| `SIGNER_TOKEN_NEXT` | No | Second accepted bearer token (min 32 chars) for zero-downtime token rotation |
| `ANIMATED_QR_SECRET` | Yes | HKDF input for Living Codes frame secrets (min 32 chars); the service refuses to start without it |
| `SIGNER_MASTER_KEY` | Yes | AES-256-GCM key for at-rest decryption. Generate: `openssl rand -base64 32` |
| `SIGNER_KEYS_DIR` | No | Key file directory (default: `./keys`) |
| `LOG_LEVEL` | No | `info` (default) or `debug` |

## Deployment

See `deploy/qrauth-signer.service` for the systemd unit file.

### Quick start (development)

    cd packages/signer-service
    export SIGNER_TOKEN=$(openssl rand -hex 32)
    export SIGNER_MASTER_KEY=$(openssl rand -base64 32)
    export ANIMATED_QR_SECRET=$(openssl rand -hex 32)
    npm run dev

### Production

1. Deploy on a host with private-network-only access.
2. Set `SIGNER_HOST` to the private IP.
3. Configure the API server with matching `*_SIGNER_URL` and `*_SIGNER_TOKEN` env vars.
4. Both hosts must share the same `SIGNER_MASTER_KEY`.

## Wire Protocol

### POST /v1/sign

Signs a message with SLH-DSA-SHA2-128s. The signer prepends a domain-separation tag
before signing.

    Authorization: Bearer {token}
    Content-Type: application/json

    { "keyId": "6bff6071-...", "message": "<base64>" }

    → 200 { "signature": "<base64>" }
    → 404 { "error": "key_not_found" }

### POST /v1/sign-ecdsa

Signs a UTF-8 canonical payload with ECDSA-P256. Domain-separation prefix
`qrauth:ecdsa-canonical:v1:` is prepended by the signer.

    Authorization: Bearer {token}
    Content-Type: application/json

    { "keyId": "6bff6071-...", "message": "<utf-8 canonical>" }

    → 200 { "signature": "<base64 DER>" }
    → 404 { "error": "key_not_found" }

### POST /v1/keys/:keyId

Provision encrypted key envelopes. Used by the API server's `createKeyPair()` to push
newly generated keys. Files must not already exist (409 if they do).

    Authorization: Bearer {token}
    Content-Type: application/json

    { "ecdsa": "<encrypted envelope>", "slhdsa": "<encrypted envelope>" }

    → 201 { "provisioned": ["ecdsa", "slhdsa"] }
    → 409 { "error": "key_exists" }

### Key File Format

Encrypted envelopes use the format:

    qrauth-kek-v1\0{base64(iv)}\0{base64(ciphertext)}\0{base64(authTag)}

AES-256-GCM with 12-byte IV, authenticated with the shared `SIGNER_MASTER_KEY`.

## Security

- Deployed on a host reachable only over the private network
- Bearer token authentication on all endpoints (except /healthz)
- Constant-time token comparison, with dual-token rotation (`SIGNER_TOKEN_NEXT`)
- At-rest encryption for all key material
- Atomic file writes (temp + rename) prevent partial key corruption
- Key ID validation rejects path traversal attempts
- Provisioning rejects a key ID whose key file already exists (409)
