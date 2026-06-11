/**
 * Unit tests for the production WebAuthn-origin boot-time check
 * (AUDIT-2 N-5). The config module is imported for its `parseEnv`
 * side effect at module-load time, so we pre-stub the other required
 * env vars before dynamically importing it and then exercise the
 * validator function directly.
 */
import { describe, it, expect, beforeAll } from 'vitest';

type AssertFn = (env: {
  NODE_ENV: 'development' | 'test' | 'production';
  WEBAUTHN_ORIGIN?: string;
}) => void;

let assertProductionWebAuthnOrigin: AssertFn;

beforeAll(async () => {
  // Stub the other required env vars before the config module runs its
  // top-level `parseEnv()`. These values are never touched — the tests
  // below only exercise the pure `assertProductionWebAuthnOrigin`
  // helper, not the module-level parse result.
  process.env.DATABASE_URL ??= 'postgresql://test:test@localhost:5432/test';
  process.env.REDIS_URL ??= 'redis://localhost:6379';
  process.env.JWT_SECRET ??= 'test-jwt-secret-not-for-production-use-only-xx';
  process.env.NODE_ENV ??= 'test';

  const mod = await import('../../src/lib/config.js');
  assertProductionWebAuthnOrigin = mod.assertProductionWebAuthnOrigin;
});

describe('assertProductionWebAuthnOrigin (AUDIT-2 N-5)', () => {
  it('no-ops in development regardless of WEBAUTHN_ORIGIN', () => {
    expect(() =>
      assertProductionWebAuthnOrigin({ NODE_ENV: 'development' }),
    ).not.toThrow();
    expect(() =>
      assertProductionWebAuthnOrigin({ NODE_ENV: 'development', WEBAUTHN_ORIGIN: '' }),
    ).not.toThrow();
  });

  it('no-ops in test regardless of WEBAUTHN_ORIGIN', () => {
    expect(() => assertProductionWebAuthnOrigin({ NODE_ENV: 'test' })).not.toThrow();
  });

  it('throws in production when WEBAUTHN_ORIGIN is unset', () => {
    expect(() => assertProductionWebAuthnOrigin({ NODE_ENV: 'production' })).toThrow(
      /WEBAUTHN_ORIGIN.*required in production/,
    );
  });

  it('throws in production when WEBAUTHN_ORIGIN is empty', () => {
    expect(() =>
      assertProductionWebAuthnOrigin({ NODE_ENV: 'production', WEBAUTHN_ORIGIN: '' }),
    ).toThrow(/WEBAUTHN_ORIGIN.*required in production/);
  });

  it('throws in production when WEBAUTHN_ORIGIN is whitespace only', () => {
    expect(() =>
      assertProductionWebAuthnOrigin({ NODE_ENV: 'production', WEBAUTHN_ORIGIN: '   ' }),
    ).toThrow(/WEBAUTHN_ORIGIN.*required in production/);
  });

  it('throws in production when WEBAUTHN_ORIGIN is not a valid URL', () => {
    expect(() =>
      assertProductionWebAuthnOrigin({ NODE_ENV: 'production', WEBAUTHN_ORIGIN: 'qrauth.io' }),
    ).toThrow(/valid absolute URL/);
  });

  it('throws in production when WEBAUTHN_ORIGIN uses http:// instead of https://', () => {
    expect(() =>
      assertProductionWebAuthnOrigin({
        NODE_ENV: 'production',
        WEBAUTHN_ORIGIN: 'http://qrauth.io',
      }),
    ).toThrow(/https: scheme/);
  });

  it('accepts a valid HTTPS origin in production', () => {
    expect(() =>
      assertProductionWebAuthnOrigin({
        NODE_ENV: 'production',
        WEBAUTHN_ORIGIN: 'https://qrauth.io',
      }),
    ).not.toThrow();
  });

  it('accepts an HTTPS origin with explicit port in production', () => {
    expect(() =>
      assertProductionWebAuthnOrigin({
        NODE_ENV: 'production',
        WEBAUTHN_ORIGIN: 'https://staging.qrauth.io:8443',
      }),
    ).not.toThrow();
  });

  it('names the variable in the error message so operators know what to set', () => {
    try {
      assertProductionWebAuthnOrigin({ NODE_ENV: 'production' });
      throw new Error('should have thrown');
    } catch (err) {
      expect((err as Error).message).toContain('WEBAUTHN_ORIGIN');
      expect((err as Error).message).toContain('SECURITY.md');
    }
  });
});
