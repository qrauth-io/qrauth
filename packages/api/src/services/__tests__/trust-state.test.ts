import { describe, it, expect } from 'vitest';

import {
  computeTrustState,
  isIssuerVerified,
  TRUST_SCORE_THRESHOLD,
  type TrustInputs,
} from '../trust-state.js';

const PASSING: TrustInputs = {
  signatureValid: true,
  revokedOrExpired: false,
  geoBlocked: false,
  trustScore: 100,
  lookalikeDestination: false,
  issuerSuspended: false,
  demoCode: false,
  destinationFlagged: false,
  issuer: { domainVerified: true, kycStatus: 'PENDING' },
};

describe('isIssuerVerified', () => {
  it.each([
    [{ domainVerified: true, kycStatus: 'PENDING' }, true],
    [{ domainVerified: false, kycStatus: 'VERIFIED' }, true],
    [{ domainVerified: true, kycStatus: 'VERIFIED' }, true],
    [{ domainVerified: false, kycStatus: 'PENDING' }, false],
    [{ domainVerified: false, kycStatus: 'UNDER_REVIEW' }, false],
    [{ domainVerified: false, kycStatus: 'REJECTED' }, false],
  ])('%o -> %s', (org, expected) => {
    expect(isIssuerVerified(org)).toBe(expected);
  });

  it('ignores trustLevel on its own', () => {
    const org = { domainVerified: false, kycStatus: 'PENDING', trustLevel: 'BUSINESS' };

    expect(isIssuerVerified(org)).toBe(false);
  });
});

describe('computeTrustState', () => {
  it('VERIFIED when every check passes and the issuer is verified', () => {
    expect(computeTrustState(PASSING)).toBe('VERIFIED');
  });

  it('SIGNED_UNVERIFIED_ISSUER when every check passes but the issuer is not verified', () => {
    expect(
      computeTrustState({ ...PASSING, issuer: { domainVerified: false, kycStatus: 'UNDER_REVIEW' } }),
    ).toBe('SIGNED_UNVERIFIED_ISSUER');
  });

  it.each<[string, Partial<TrustInputs>]>([
    ['invalid signature', { signatureValid: false }],
    ['revoked or expired', { revokedOrExpired: true }],
    ['geo-blocked', { geoBlocked: true }],
    ['trust score at the threshold', { trustScore: TRUST_SCORE_THRESHOLD }],
    ['trust score below the threshold', { trustScore: 0 }],
    ['lookalike destination', { lookalikeDestination: true }],
    ['suspended issuer', { issuerSuspended: true }],
    ['flagged destination', { destinationFlagged: true }],
  ])('UNTRUSTED for a verified issuer with %s', (_label, override) => {
    expect(computeTrustState({ ...PASSING, ...override })).toBe('UNTRUSTED');
  });

  it('UNTRUSTED for an unverified issuer with a lookalike destination', () => {
    expect(
      computeTrustState({
        ...PASSING,
        lookalikeDestination: true,
        issuer: { domainVerified: false, kycStatus: 'PENDING' },
      }),
    ).toBe('UNTRUSTED');
  });

  it('VERIFIED just above the threshold (the fraud score floor of 30 alone does not block)', () => {
    expect(computeTrustState({ ...PASSING, trustScore: 30 })).toBe('VERIFIED');
  });
});

describe('computeTrustState — demo codes', () => {
  it('a demo code of a verified issuer is capped at SIGNED_UNVERIFIED_ISSUER', () => {
    expect(computeTrustState({ ...PASSING, demoCode: true })).toBe('SIGNED_UNVERIFIED_ISSUER');
  });

  it('a demo code that fails a check is still UNTRUSTED', () => {
    expect(computeTrustState({ ...PASSING, demoCode: true, revokedOrExpired: true })).toBe('UNTRUSTED');
    expect(computeTrustState({ ...PASSING, demoCode: true, lookalikeDestination: true })).toBe('UNTRUSTED');
  });
});
