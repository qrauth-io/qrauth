import { describe, it, expect } from 'vitest';
import { resolveRefreshGrant, REFRESH_FAMILY_MAX_AGE_SECONDS } from '../oidc-refresh-policy.js';

/** Audit 2026-10 FINDING-011: what a refresh grant may still do. */

const DAY = 24 * 60 * 60 * 1000;
const NOW = new Date('2026-10-13T12:00:00Z');

function db(opts: {
  familyStartedAt: Date;
  consent?: { grantedScopes: string[]; revokedAt: Date | null } | null;
}) {
  return {
    oidcRefreshToken: { findFirst: async () => ({ createdAt: opts.familyStartedAt }) },
    oidcConsent: { findUnique: async () => opts.consent ?? null },
  } as never;
}

const customer = {
  id: 'c1',
  tier: 'CUSTOMER' as const,
  allowedScopes: ['openid', 'email', 'offline_access'],
  consentRequired: true,
};
const firstParty = { ...customer, tier: 'FIRST_PARTY' as const };
const presented = { familyId: 'fam', userId: 'u1', createdAt: new Date(NOW.getTime() - DAY) };
const liveConsent = { grantedScopes: ['openid', 'email', 'offline_access'], revokedAt: null };

describe('resolveRefreshGrant', () => {
  it('keeps the scope when client and consent still cover it', async () => {
    const result = await resolveRefreshGrant(db({ familyStartedAt: new Date(NOW.getTime() - DAY), consent: liveConsent }), {
      client: customer, presented, scope: 'openid email offline_access', now: NOW,
    });
    expect(result).toMatchObject({ ok: true, scope: 'openid email offline_access', ttlSeconds: 1_209_600 });
  });

  it('refuses once the family is 90 days old', async () => {
    const started = new Date(NOW.getTime() - REFRESH_FAMILY_MAX_AGE_SECONDS * 1000);
    const result = await resolveRefreshGrant(db({ familyStartedAt: started, consent: liveConsent }), {
      client: customer, presented, scope: 'openid', now: NOW,
    });
    expect(result.ok).toBe(false);
  });

  it('never issues a successor that outlives the family', async () => {
    const started = new Date(NOW.getTime() - 88 * DAY);
    const result = await resolveRefreshGrant(db({ familyStartedAt: started, consent: liveConsent }), {
      client: customer, presented, scope: 'openid', now: NOW,
    });
    expect(result).toMatchObject({ ok: true, ttlSeconds: 2 * 24 * 60 * 60 });
  });

  it('drops a scope the client is no longer allowed', async () => {
    const result = await resolveRefreshGrant(db({ familyStartedAt: new Date(NOW.getTime() - DAY), consent: liveConsent }), {
      client: { ...customer, allowedScopes: ['openid', 'offline_access'] }, presented, scope: 'openid email offline_access', now: NOW,
    });
    expect(result).toMatchObject({ ok: true, scope: 'openid offline_access' });
  });

  it('drops a scope the consent no longer covers', async () => {
    const consent = { grantedScopes: ['openid', 'offline_access'], revokedAt: null };
    const result = await resolveRefreshGrant(db({ familyStartedAt: new Date(NOW.getTime() - DAY), consent }), {
      client: customer, presented, scope: 'openid email offline_access', now: NOW,
    });
    expect(result).toMatchObject({ ok: true, scope: 'openid offline_access' });
  });

  it('refuses when the consent was revoked', async () => {
    const consent = { ...liveConsent, revokedAt: new Date() };
    const result = await resolveRefreshGrant(db({ familyStartedAt: new Date(NOW.getTime() - DAY), consent }), {
      client: customer, presented, scope: 'openid', now: NOW,
    });
    expect(result.ok).toBe(false);
  });

  it('refuses when there is no consent row at all', async () => {
    const result = await resolveRefreshGrant(db({ familyStartedAt: new Date(NOW.getTime() - DAY), consent: null }), {
      client: customer, presented, scope: 'openid', now: NOW,
    });
    expect(result.ok).toBe(false);
  });

  it('refuses when openid is no longer allowed for the client', async () => {
    const result = await resolveRefreshGrant(db({ familyStartedAt: new Date(NOW.getTime() - DAY), consent: liveConsent }), {
      client: { ...customer, allowedScopes: ['email'] }, presented, scope: 'openid email', now: NOW,
    });
    expect(result.ok).toBe(false);
  });

  it('does not ask an operator-vetted client for consent', async () => {
    const result = await resolveRefreshGrant(db({ familyStartedAt: new Date(NOW.getTime() - DAY), consent: null }), {
      client: { ...customer, consentRequired: false }, presented, scope: 'openid email', now: NOW,
    });
    expect(result).toMatchObject({ ok: true, scope: 'openid email' });
  });

  it('does not ask a FIRST_PARTY client for consent', async () => {
    const result = await resolveRefreshGrant(db({ familyStartedAt: new Date(NOW.getTime() - DAY), consent: null }), {
      client: firstParty, presented, scope: 'openid email', now: NOW,
    });
    expect(result).toMatchObject({ ok: true, scope: 'openid email' });
  });
});
