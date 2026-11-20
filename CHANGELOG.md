# Changelog

Notable changes to the QRAuth platform API, its verification responses and its webhook payloads. SDK packages keep their own changelogs.

## Unreleased

### Changed

- **Verify response trust states** (`GET /v/:token` and `/api/v1/verify/:token` with `Accept: application/json`).
  - New `trust_state`: `VERIFIED` (every check passed and the issuer is verified by QRAuth), `SIGNED_UNVERIFIED_ISSUER` (every check passed, issuer not verified) or `UNTRUSTED`.
  - `verified` is `true` only when `trust_state` is `VERIFIED`.
  - `organization` is `{ verified: true, name, verified_domain? }` for `VERIFIED` and `{ verified: false }` otherwise.
  - `destination_url` is absent from failure responses (revoked, expired, scan limit, suspended issuer, flagged destination).
  - `@qrauth/node` 0.4.0 carries the matching types.
- **Living Codes frame secret** (`POST /api/v1/animated-qr/session`).
  - Public clients (client ID only) send `frameChallenge = base64url(SHA-256(frameVerifier))` in `POST /api/v1/auth-sessions` when creating the auth session. `POST /api/v1/animated-qr/session` returns no `frameSecret` to them; the new `POST /api/v1/animated-qr/session/secret` releases it on presenting `frameVerifier` in the JSON body. A public client whose auth session was created without `frameChallenge` receives 401.
  - Confidential clients (client secret) still receive `frameSecret` from `POST /session`, and can rotate it with `POST /session/secret`.
  - Every issuance starts a new secret generation; frames signed with an earlier secret no longer verify. A reload fetches a new secret and starts again at frame 0.
- **`pqcProtected` semantics** (verify response `security.pqcProtected`; `securityContext.pqcProtected` in the `qr.scanned` and `qr.created` webhooks).
  - Previously: `true` whenever the row had any `alg_version`.
  - Now, in the verify response: `true` only when the row is `hybrid-ecdsa-slhdsa-v1` and its Merkle/SLH-DSA leg verified for this request.
  - Now, in webhooks: `true` when the row is `hybrid-ecdsa-slhdsa-v1` and carries its Merkle data. Webhooks do not re-run verification; use the verify response for a per-scan result.
  - Integrations that treat the field as always `true` should read it as reported.
- **Accepted algorithm versions.** `hybrid-ecdsa-slhdsa-v1` is the only accepted `alg_version`. `ecdsa-pending-slhdsa-v1` and the reserved, never-issued `slhdsa-sha2-128s-v1` and `slhdsa-sha2-256s-v1` are rejected. A reserved version becomes accepted in the release that ships its verifier.
- **Hybrid verification** recomputes the Merkle leaf from the QR's canonical data and stored nonce; a hybrid QR without complete Merkle data fails verification. See ALGORITHM.md §6.3.
- **`security.merkleProofValid`** reports the Merkle/SLH-DSA leg result; it is no longer `true` for rows to which the leg does not apply.

### Removed

- Asynchronous QR issuance (the `ecdsa-pending-slhdsa-v1` state) and its reconcile worker. Issuance writes the ECDSA signature and Merkle data together.
