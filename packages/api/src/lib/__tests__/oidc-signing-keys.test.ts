import { describe, it, expect } from 'vitest';
import { FakeSigningKeyPrisma } from '../../services/__tests__/fake-signing-key-prisma.js';

// oidc-signing-keys.ts imports config (for the JWKS publication window),
// which validates env at import time — set throwaways before loading.
process.env.DATABASE_URL ??= 'postgresql://test:test@localhost:5432/test';
process.env.REDIS_URL ??= 'redis://localhost:6379';
process.env.JWT_SECRET ??= 'unit-test-secret-0123456789abcdef';

const {
  QRAUTH_PLATFORM_ORG_SLUG,
  OIDC_ID_TOKEN_SIGNING_ALGS,
  platformSigningKeyWhere,
  platformJwksKeyWhere,
  jwksPublicationCutoff,
  checkPlatformSigningKeyHealth,
  checkOidcRuntimeSecrets,
} = await import('../oidc-signing-keys.js');

/**
 * OP keystore health + shared signing/publishing filters
 * (docs/ops/signing-key-rotation-loop.md, fixes 8 and 9; time-bounded
 * publication per the 2026-09-08 design note).
 */

const DAY_MS = 24 * 60 * 60 * 1000;
const daysAgo = (n: number) => new Date(Date.now() - n * DAY_MS);

const PLATFORM_ORG = 'org-platform';

function platformDb(): FakeSigningKeyPrisma {
  const db = new FakeSigningKeyPrisma();
  db.seedOrg(PLATFORM_ORG, QRAUTH_PLATFORM_ORG_SLUG);
  db.seedOrg('org-other', 'some-customer');
  return db;
}

describe('checkPlatformSigningKeyHealth', () => {
  it('is healthy with one ACTIVE key per advertised algorithm', async () => {
    const db = platformDb();
    db.seedKey({ organizationId: PLATFORM_ORG, algorithm: 'ES256' });
    db.seedKey({ organizationId: PLATFORM_ORG, algorithm: 'RS256' });

    const health = await checkPlatformSigningKeyHealth(db.asPrisma(), {
      requireProvisioned: true,
    });

    expect(health).toEqual({
      healthy: true,
      missing: [],
      unprovisioned: [],
      published: 2,
      retained: 0,
      overdue: [],
    });
  });

  it('flags an ACTIVE key past rotationDays + overdue grace as rotation-overdue (pure DB-age check)', async () => {
    const db = platformDb();
    // 93 days > 90 + 2-day grace — the abort-loop / trigger-regression shape.
    const stale = db.seedKey({
      organizationId: PLATFORM_ORG,
      algorithm: 'ES256',
      createdAt: daysAgo(93),
    });
    db.seedKey({ organizationId: PLATFORM_ORG, algorithm: 'RS256', createdAt: daysAgo(91) });

    const health = await checkPlatformSigningKeyHealth(db.asPrisma(), {
      requireProvisioned: true,
    });

    expect(health.healthy).toBe(false);
    expect(health.overdue).toEqual([
      { keyId: stale.keyId, algorithm: 'ES256', ageDays: 93 },
    ]);
    // 91 days is inside the grace window — present-and-active is fine.
    expect(health.missing).toEqual([]);
  });

  it('published is time-bounded, retained is not: rotated-yesterday counts as published, rotated-31-days-ago only as retained', async () => {
    const db = platformDb();
    db.seedKey({ organizationId: PLATFORM_ORG, algorithm: 'ES256' });
    db.seedKey({ organizationId: PLATFORM_ORG, algorithm: 'RS256' });
    const insideWindow = db.seedKey({
      organizationId: PLATFORM_ORG,
      algorithm: 'ES256',
      status: 'ROTATED',
      rotatedAt: new Date(Date.now() - 23 * 60 * 60 * 1000), // 23 h ago — inside the 24 h window
    });
    const outsideWindow = db.seedKey({
      organizationId: PLATFORM_ORG,
      algorithm: 'ES256',
      status: 'ROTATED',
      rotatedAt: daysAgo(31),
    });
    db.seedKey({
      organizationId: PLATFORM_ORG,
      algorithm: 'ES256',
      status: 'REVOKED',
      revokedAt: new Date(),
    });
    db.seedKey({ organizationId: 'org-other', algorithm: 'ES256' });

    const health = await checkPlatformSigningKeyHealth(db.asPrisma(), {
      requireProvisioned: true,
    });

    // published: 2 ACTIVE + the 23h-old ROTATED key; the 31-day-old ROTATED
    // key and the REVOKED key are NOT served; other orgs never counted.
    expect(health.published).toBe(3);
    // retained: BOTH rotated rows, regardless of publication window.
    expect(health.retained).toBe(2);
    expect(health.healthy).toBe(true);

    // The same rule through the actual JWKS where-clause: rotated-yesterday
    // present, rotated-31-days-ago absent.
    const served = await db.signingKey.findMany({ where: platformJwksKeyWhere() as never });
    const servedKids = served.map((k) => k.keyId);
    expect(servedKids).toContain(insideWindow.keyId);
    expect(servedKids).not.toContain(outsideWindow.keyId);
    expect(served).toHaveLength(3);
  });

  it('fails when the only RS256 key is ROTATED (the incident shape)', async () => {
    const db = platformDb();
    db.seedKey({ organizationId: PLATFORM_ORG, algorithm: 'ES256' });
    db.seedKey({
      organizationId: PLATFORM_ORG,
      algorithm: 'RS256',
      status: 'ROTATED',
      rotatedAt: new Date(),
    });

    const health = await checkPlatformSigningKeyHealth(db.asPrisma(), {
      requireProvisioned: false,
    });

    expect(health.healthy).toBe(false);
    expect(health.missing).toEqual(['RS256']);
  });

  it('does not count another org\'s ACTIVE keys toward platform health', async () => {
    const db = platformDb();
    db.seedKey({ organizationId: PLATFORM_ORG, algorithm: 'ES256' });
    db.seedKey({
      organizationId: PLATFORM_ORG,
      algorithm: 'RS256',
      status: 'ROTATED',
      rotatedAt: new Date(),
    });
    db.seedKey({ organizationId: 'org-other', algorithm: 'RS256' });

    const health = await checkPlatformSigningKeyHealth(db.asPrisma(), {
      requireProvisioned: false,
    });

    expect(health.healthy).toBe(false);
    expect(health.missing).toEqual(['RS256']);
  });

  it('treats a never-provisioned algorithm as informational in dev/test and failing in production', async () => {
    const db = platformDb();
    db.seedKey({ organizationId: PLATFORM_ORG, algorithm: 'ES256' });
    // No RS256 rows at all.

    const dev = await checkPlatformSigningKeyHealth(db.asPrisma(), { requireProvisioned: false });
    const prod = await checkPlatformSigningKeyHealth(db.asPrisma(), { requireProvisioned: true });

    expect(dev.healthy).toBe(true);
    expect(dev.unprovisioned).toEqual(['RS256']);
    expect(prod.healthy).toBe(false);
    expect(prod.unprovisioned).toEqual(['RS256']);
  });
});

describe('checkOidcRuntimeSecrets — the coverage-gap guard', () => {
  const secret = Buffer.from('a'.repeat(32));

  it('reports a missing pairwise secret in every environment', () => {
    expect(
      checkOidcRuntimeSecrets({
        pairwiseSecret: undefined,
        signerMasterKey: 'set',
        requireSignerMasterKey: false,
      }),
    ).toEqual(['OIDC_PAIRWISE_SECRET']);
  });

  it('requires the signer master key only when asked (production)', () => {
    const prod = checkOidcRuntimeSecrets({
      pairwiseSecret: secret,
      signerMasterKey: undefined,
      requireSignerMasterKey: true,
    });
    const dev = checkOidcRuntimeSecrets({
      pairwiseSecret: secret,
      signerMasterKey: undefined,
      requireSignerMasterKey: false,
    });
    expect(prod).toEqual(['SIGNER_MASTER_KEY']);
    expect(dev).toEqual([]);
  });

  it('is empty when everything required is present', () => {
    expect(
      checkOidcRuntimeSecrets({
        pairwiseSecret: secret,
        signerMasterKey: 'set',
        requireSignerMasterKey: true,
      }),
    ).toEqual([]);
  });
});

describe('signing vs publishing filters — deliberate divergence', () => {
  it('the signing filter selects ACTIVE keys only, per algorithm', () => {
    expect(platformSigningKeyWhere('RS256')).toEqual({
      organization: { slug: QRAUTH_PLATFORM_ORG_SLUG },
      algorithm: 'RS256',
      status: 'ACTIVE',
    });
  });

  it('the JWKS filter publishes ACTIVE keys plus ROTATED keys inside the time window (never REVOKED, never long-rotated)', () => {
    const now = new Date('2026-09-08T12:00:00Z');
    expect(platformJwksKeyWhere(now)).toEqual({
      organization: { slug: QRAUTH_PLATFORM_ORG_SLUG },
      algorithm: { in: [...OIDC_ID_TOKEN_SIGNING_ALGS] },
      OR: [
        { status: 'ACTIVE' },
        { status: 'ROTATED', rotatedAt: { gte: jwksPublicationCutoff(now) } },
      ],
    });
    // Default window: 24 h before `now`.
    expect(jwksPublicationCutoff(now)).toEqual(new Date('2026-09-07T12:00:00Z'));
  });

  it('every alg the signing path can request is advertised (no orphan signer algs)', () => {
    for (const alg of OIDC_ID_TOKEN_SIGNING_ALGS) {
      expect(platformSigningKeyWhere(alg).algorithm).toBe(alg);
    }
  });
});
