import { describe, expect, it } from 'vitest';

import { customerLogoRefusal, isIssuerVerified } from '../index.js';

/**
 * Customer-logo eligibility (ADR-0005 D9, amended 2026-10-29): a paid plan
 * and a verified issuer. The API's 403s and the dashboard's disabled
 * "Your Logo" both come from customerLogoRefusal.
 */

describe('isIssuerVerified', () => {
  it.each([
    [{ domainVerified: true, kycStatus: 'PENDING' }, true],
    [{ domainVerified: false, kycStatus: 'VERIFIED' }, true],
    [{ domainVerified: true, kycStatus: 'VERIFIED' }, true],
    [{ domainVerified: false, kycStatus: 'UNDER_REVIEW' }, false],
    [{ domainVerified: false, kycStatus: 'REJECTED' }, false],
    [{ domainVerified: false, kycStatus: 'PENDING' }, false],
  ])('%o is %s', (org, expected) => {
    expect(isIssuerVerified(org)).toBe(expected);
  });
});

describe('customerLogoRefusal', () => {
  it.each(['PRO', 'BUSINESS', 'ENTERPRISE'])('%s with a verified domain is allowed', (plan) => {
    expect(customerLogoRefusal({ plan, domainVerified: true, kycStatus: 'PENDING' })).toBeNull();
  });

  it('a paid plan with a completed KYC review is allowed', () => {
    expect(customerLogoRefusal({ plan: 'PRO', domainVerified: false, kycStatus: 'VERIFIED' })).toBeNull();
  });

  it('a paid plan without a verified issuer is refused for verification', () => {
    expect(customerLogoRefusal({ plan: 'PRO', domainVerified: false, kycStatus: 'UNDER_REVIEW' })).toBe('verification');
  });

  it('FREE is refused for the plan, verified or not', () => {
    expect(customerLogoRefusal({ plan: 'FREE', domainVerified: true, kycStatus: 'VERIFIED' })).toBe('plan');
    expect(customerLogoRefusal({ plan: 'FREE', domainVerified: false, kycStatus: 'PENDING' })).toBe('plan');
  });

  it('an unknown plan is treated as FREE', () => {
    expect(customerLogoRefusal({ plan: 'GOLD', domainVerified: true, kycStatus: 'VERIFIED' })).toBe('plan');
  });
});
