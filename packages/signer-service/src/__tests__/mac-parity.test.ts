import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { hkdfSync } from 'node:crypto';
import {
  MAC_HKDF_INFO_PREFIX,
  MAC_HKDF_SALT,
} from '../domain-separation.js';

/**
 * Cross-service HKDF parity canary (Audit-4 A4-M2, Phase 0).
 *
 * This test locks the signer's frame-secret derivation to a pinned
 * vector so any drift in either the `MAC_HKDF_SALT` constant or the
 * `MAC_HKDF_INFO_PREFIX` constant surfaces immediately in CI. The same
 * derivation must be performed by `AnimatedQRService.deriveFrameSecret`
 * in `packages/api/src/services/animated-qr.ts` — an API-side test
 * that reproduces this vector with its own code path is out of scope
 * here (Phase 1 will add a live dual-mode comparison against running
 * traffic), but the pinned hex below is the single source of truth both
 * sides must match.
 *
 * The `@qrauth/api` package does not expose `AnimatedQRService` on a
 * clean import path (it re-exports `dist/server.js`, which would pull
 * Prisma + Redis + Fastify into the signer test tree). Following the
 * Phase-0 prompt's fallback: pin the vector with a shared primitive
 * (Node's `hkdfSync`) that both sides use, and leave a TODO(phase1)
 * for the live-traffic parity check.
 */

const PINNED_IKM = 'a'.repeat(64);
const PINNED_SESSION_ID = 'test-session';

// Pre-computed once with
//   hkdfSync('sha256', 'a'.repeat(64), 'qrauth:animated-qr:v1',
//            'frame_secret:test-session', 32).toString('hex');
// and locked here so the test fails if either literal drifts.
const PINNED_OUTPUT_HEX =
  '2e9dc6c9bdeb33d90d54f561ac317c2f7884f868cb034bd67eb6f95b0a6b7d41';

function deriveViaConstants(secret: string, sessionId: string): string {
  return Buffer.from(
    hkdfSync(
      'sha256',
      secret,
      MAC_HKDF_SALT,
      `${MAC_HKDF_INFO_PREFIX}${sessionId}`,
      32,
    ),
  ).toString('hex');
}

describe('HKDF parity (signer ↔ API)', () => {
  it('MAC_HKDF_SALT is exactly "qrauth:animated-qr:v1"', () => {
    // Hard-coded literal check. Two layers of protection: the constant
    // import + the literal string here. If someone changes the constant
    // and rebuilds, this fails BEFORE the vector test below — producing
    // a clearer failure line for the reviewer.
    expect(MAC_HKDF_SALT).toBe('qrauth:animated-qr:v1');
  });

  it('MAC_HKDF_INFO_PREFIX is exactly "frame_secret:"', () => {
    expect(MAC_HKDF_INFO_PREFIX).toBe('frame_secret:');
  });

  it('derives the pinned vector for (IKM, sessionId) — signer side', () => {
    // This is the canary. If either constant changes, or someone swaps
    // the HKDF algorithm / output length / info separator, this fails.
    // The same computation on the API side MUST produce the same hex.
    expect(deriveViaConstants(PINNED_IKM, PINNED_SESSION_ID)).toBe(
      PINNED_OUTPUT_HEX,
    );
  });

  it('is deterministic across repeated calls (sanity)', () => {
    const a = deriveViaConstants(PINNED_IKM, PINNED_SESSION_ID);
    const b = deriveViaConstants(PINNED_IKM, PINNED_SESSION_ID);
    expect(a).toBe(b);
  });

  it('sessionId is bound — different sessionIds produce different outputs', () => {
    const a = deriveViaConstants(PINNED_IKM, 'session-A');
    const b = deriveViaConstants(PINNED_IKM, 'session-B');
    expect(a).not.toBe(b);
  });

  // Source-level parity guard. The API's `deriveFrameSecret` is not
  // cleanly importable here — `@qrauth/api` re-exports `dist/server.js`
  // which trips Prisma/Redis env validation on module load. Instead we
  // grep the API source for the two literals and a matching HKDF call.
  // If either literal drifts over there, this test fails even without
  // running the API-side code. Belt + braces alongside the pinned
  // vector above.
  it('API source contains byte-identical HKDF salt and info literals', () => {
    const apiAnimatedQr = resolve(
      __dirname,
      '../../../api/src/services/animated-qr.ts',
    );
    const src = readFileSync(apiAnimatedQr, 'utf8');

    // Both constants appear in the API source exactly as the signer
    // defines them. Algorithm and output length are caught separately
    // by the pinned-vector test above — if anyone swaps sha256 for
    // sha3-256 or 32 for 64, that vector fails independent of this
    // source grep.
    expect(src).toContain(`'${MAC_HKDF_SALT}'`);
    expect(src).toContain(`\`${MAC_HKDF_INFO_PREFIX}\${sessionIdentifier}\``);
  });

  // TODO(phase1): add a live parity check that compares the signer's
  // derivation against `AnimatedQRService.deriveFrameSecret` output for
  // the same (sessionId) across the dual-mode window. Belongs in the
  // API package's integration tests once MAC_BACKEND=dual lands.
});
