import { describe, it, expect } from 'vitest';

// config.ts validates env at import time — set throwaways before loading.
process.env.DATABASE_URL ??= 'postgresql://test:test@localhost:5432/test';
process.env.REDIS_URL ??= 'redis://localhost:6379';
process.env.JWT_SECRET ??= 'unit-test-secret-0123456789abcdef';

const { assertJwksWindowAboveFloor, JWKS_CLOCK_SKEW_ALLOWANCE_SECONDS } = await import(
  '../config.js'
);
const { ID_TOKEN_EXPIRES_IN_SECONDS } = await import('../oidc-id-token.js');

/**
 * Boot validation of the JWKS publication window
 * (docs/ops/signing-key-rotation-loop.md, 2026-09-08 design note): a window
 * below ID-token lifetime + clock skew breaks verification intermittently
 * after every rotation and looks like an RP bug. The floor is DERIVED from
 * the token TTL, never hardcoded, so the two cannot silently drift apart.
 */
describe('assertJwksWindowAboveFloor', () => {
  it('rejects a window below the ID-token-TTL + skew floor', () => {
    // Floor with the real TTL: 3600 + 300 = 3900 s ≈ 1.083 h.
    expect(() => assertJwksWindowAboveFloor(1)).toThrow(/below the derived floor/);
    expect(() => assertJwksWindowAboveFloor(1)).toThrow(String(ID_TOKEN_EXPIRES_IN_SECONDS));
  });

  it('accepts the default 24 h window and a just-above-floor window', () => {
    expect(() => assertJwksWindowAboveFloor(24)).not.toThrow();
    // Floor is 3900 s (1.0833… h); 1.1 h = 3960 s clears it. (The exact
    // float boundary is deliberately not asserted — hours*3600 rounding.)
    expect(() => assertJwksWindowAboveFloor(1.1)).not.toThrow();
  });

  it('derives the floor from the token TTL — a longer TTL moves the floor with it', () => {
    // With a hypothetical 2 h token TTL the floor becomes 7500 s ≈ 2.083 h:
    // a 2 h window (fine under the real TTL) must now be rejected, and a
    // 2.5 h window accepted. This is the anti-drift property: whoever
    // changes ID_TOKEN_EXPIRES_IN_SECONDS moves this floor automatically.
    expect(() => assertJwksWindowAboveFloor(2, 7200)).toThrow(/below the derived floor/);
    expect(() => assertJwksWindowAboveFloor(2.5, 7200)).not.toThrow();
  });
});
