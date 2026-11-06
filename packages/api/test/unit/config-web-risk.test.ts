/**
 * Production must screen QR destinations and links (assertProductionWebRisk):
 * WEB_RISK_API_KEY is required, and the development-only
 * WEB_RISK_ALLOW_UNSCREENED_LINKS is refused.
 */
import { describe, it, expect, beforeAll } from 'vitest';

let assertProductionWebRisk: typeof import('../../src/lib/config.js').assertProductionWebRisk;

beforeAll(async () => {
  process.env.DATABASE_URL ??= 'postgresql://test:test@localhost:5432/test';
  process.env.REDIS_URL ??= 'redis://localhost:6379';
  process.env.JWT_SECRET ??= 'test-jwt-secret-not-for-production-use-only-xx';
  process.env.NODE_ENV ??= 'test';
  ({ assertProductionWebRisk } = await import('../../src/lib/config.js'));
});

describe('assertProductionWebRisk', () => {
  it('refuses to start in production without WEB_RISK_API_KEY, with a clear message', () => {
    expect(() => assertProductionWebRisk({ NODE_ENV: 'production' })).toThrow(/WEB_RISK_API_KEY is required in production/);
  });

  it('refuses the unscreened-links flag in production', () => {
    expect(() => assertProductionWebRisk({ NODE_ENV: 'production', WEB_RISK_API_KEY: 'k', WEB_RISK_ALLOW_UNSCREENED_LINKS: true }))
      .toThrow(/development and test only/);
  });

  it('accepts production with a key', () => {
    expect(() => assertProductionWebRisk({ NODE_ENV: 'production', WEB_RISK_API_KEY: 'k' })).not.toThrow();
  });

  it.each(['development', 'test'] as const)('%s runs without a key, with or without the flag', (NODE_ENV) => {
    expect(() => assertProductionWebRisk({ NODE_ENV })).not.toThrow();
    expect(() => assertProductionWebRisk({ NODE_ENV, WEB_RISK_ALLOW_UNSCREENED_LINKS: true })).not.toThrow();
  });
});
