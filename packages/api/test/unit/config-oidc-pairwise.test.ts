/**
 * Regression test for the OIDC_PAIRWISE_SECRET boot landmine (ADR-0003
 * Slice 3b). #142/#143 made the secret boot-required in production, so the
 * next vqr-api restart would crash unless an operator set it first — even
 * though nothing consumed it yet. The fix moves validation to the call site
 * (computePairwiseSub) and leaves only a FORMAT check at boot, gated on the
 * value being present. This pins that behavior.
 *
 * Like config-webauthn-origin.test.ts, we pre-stub the other required env
 * vars before importing the config module (which runs parseEnv at load),
 * then exercise the pure `assertPairwiseSecretFormat` helper directly.
 */
import { describe, it, expect, beforeAll } from 'vitest';

let assertPairwiseSecretFormat: (raw: string | undefined) => void;
let config: typeof import('../../src/lib/config.js').config;

beforeAll(async () => {
  process.env.DATABASE_URL ??= 'postgresql://test:test@localhost:5432/test';
  process.env.REDIS_URL ??= 'redis://localhost:6379';
  process.env.JWT_SECRET ??= 'test-jwt-secret-not-for-production-use-only-xx';
  process.env.NODE_ENV ??= 'test';
  // Intentionally do NOT set OIDC_PAIRWISE_SECRET — the module must still load.
  delete process.env.OIDC_PAIRWISE_SECRET;

  const mod = await import('../../src/lib/config.js');
  assertPairwiseSecretFormat = mod.assertPairwiseSecretFormat;
  config = mod.config;
});

describe('OIDC_PAIRWISE_SECRET boot behavior (ADR-0003 Slice 3b — landmine fix)', () => {
  it('config loaded without OIDC_PAIRWISE_SECRET set — boot does NOT crash', () => {
    // Reaching here at all proves parseEnv() did not throw at import time
    // with the secret unset. The exposed value is undefined.
    expect(config.oidc.pairwiseSecret).toBeUndefined();
  });

  it('assertPairwiseSecretFormat: unset is allowed (no throw) — the regression', () => {
    expect(() => assertPairwiseSecretFormat(undefined)).not.toThrow();
    expect(() => assertPairwiseSecretFormat('')).not.toThrow();
  });

  it('assertPairwiseSecretFormat: a present, valid 32-byte base64 value passes', () => {
    const valid = Buffer.alloc(32, 7).toString('base64');
    expect(() => assertPairwiseSecretFormat(valid)).not.toThrow();
  });

  it('assertPairwiseSecretFormat: a present but too-short value fails fast (typo guard)', () => {
    const tooShort = Buffer.alloc(16).toString('base64');
    expect(() => assertPairwiseSecretFormat(tooShort)).toThrow(/at least 32 bytes/);
  });
});
