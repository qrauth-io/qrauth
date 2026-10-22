import { describe, it, expect } from 'vitest';
import { computeWantRedirect } from './approval.js';

describe('computeWantRedirect', () => {
  it('returns true when dr=1 regardless of Referer', () => {
    expect(computeWantRedirect(true, undefined, null)).toBe(true);
    expect(computeWantRedirect(true, 'https://other.example/foo', 'https://wp-site.example/wp-login.php')).toBe(true);
  });

  it('returns true when Referer origin matches redirectUrl origin', () => {
    expect(
      computeWantRedirect(false, 'https://wp-site.example/wp-login.php', 'https://wp-site.example/wp-login.php'),
    ).toBe(true);
    expect(
      computeWantRedirect(false, 'https://wp-site.example/some-other-page', 'https://wp-site.example/wp-login.php'),
    ).toBe(true);
  });

  it('returns false when Referer origin differs from redirectUrl origin', () => {
    expect(
      computeWantRedirect(false, 'https://attacker.example/foo', 'https://wp-site.example/wp-login.php'),
    ).toBe(false);
  });

  it('returns false when Referer is missing (cross-device QR scan)', () => {
    expect(computeWantRedirect(false, undefined, 'https://wp-site.example/wp-login.php')).toBe(false);
    expect(computeWantRedirect(false, '', 'https://wp-site.example/wp-login.php')).toBe(false);
  });

  it('returns false when redirectUrl is null', () => {
    expect(computeWantRedirect(false, 'https://wp-site.example/wp-login.php', null)).toBe(false);
  });

  it('returns false when Referer is malformed', () => {
    expect(computeWantRedirect(false, 'not-a-url', 'https://wp-site.example/wp-login.php')).toBe(false);
  });
});
