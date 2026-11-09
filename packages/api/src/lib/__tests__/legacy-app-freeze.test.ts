import { describe, it, expect } from 'vitest';
import { PLATFORM_ORG_SLUG, appCreationBlockedByFreeze } from '../legacy-app-freeze.js';

/**
 * ADR-0004 D2/D4 in code (audit 2026-10 FINDING-009): when the freeze is on,
 * no organization but the platform's can register a new App.
 */
describe('appCreationBlockedByFreeze', () => {
  it('blocks nothing while the freeze is off', () => {
    expect(appCreationBlockedByFreeze({ freezeEnabled: false, organizationSlug: 'acme' })).toBe(false);
  });

  it('blocks an ordinary organization when the freeze is on', () => {
    expect(appCreationBlockedByFreeze({ freezeEnabled: true, organizationSlug: 'acme' })).toBe(true);
    expect(appCreationBlockedByFreeze({ freezeEnabled: true, organizationSlug: null })).toBe(true);
  });

  it('never blocks the platform organization (CLI)', () => {
    expect(PLATFORM_ORG_SLUG).toBe('qrauth-platform');
    expect(appCreationBlockedByFreeze({ freezeEnabled: true, organizationSlug: 'qrauth-platform' })).toBe(false);
  });
});
