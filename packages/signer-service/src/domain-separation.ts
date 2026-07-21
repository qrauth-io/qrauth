/**
 * Domain-separation prefix constants the signer service prepends before
 * invoking the underlying primitives. Extracted to their own module so
 * that tests (notably the AUDIT-2 N-7 ECDSA round-trip test in
 * packages/protocol-tests) can import the exact byte strings without
 * triggering server.ts's top-level boot side effects (env validation,
 * app.listen, SIGTERM handlers).
 *
 * These literals are pinned in `ALGORITHM.md §12`. Changing either
 * string is a protocol-version bump because every verifier reconstructs
 * it byte-for-byte.
 */

export const SIGNER_MERKLE_ROOT_PREFIX = Buffer.from(
  'qrauth:merkle-root:v1:',
  'utf8',
);

export const SIGNER_ECDSA_CANONICAL_PREFIX = 'qrauth:ecdsa-canonical:v1:';

/**
 * HKDF salt for animated-QR frame secret derivation (Audit-4 A4-M2).
 * MUST match `AnimatedQRService.deriveFrameSecret` in
 * `packages/api/src/services/animated-qr.ts` byte-for-byte — a parity
 * test in `packages/signer-service/src/__tests__/mac-parity.test.ts`
 * locks both sides to a pinned HKDF output so a drift in either
 * literal surfaces immediately in CI.
 */
export const MAC_HKDF_SALT = 'qrauth:animated-qr:v1';

/**
 * HKDF info prefix. Concatenated with sessionId at call time to bind
 * the derived secret to a specific session. Same parity lock as above.
 */
export const MAC_HKDF_INFO_PREFIX = 'frame_secret:';
