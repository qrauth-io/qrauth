import { describe, it, expect } from 'vitest';

import { profileNameClaim } from '../oidc-profile-name.js';
import { withAppleFormPostName, type OAuthUser } from '../oauth.js';

describe('profileNameClaim', () => {
  it('returns a real name', () => {
    expect(profileNameClaim({ name: 'Jane Doe', email: 'jane@example.com' })).toBe('Jane Doe');
  });

  it('omits a name that is only the email (any case, any spacing)', () => {
    expect(profileNameClaim({ name: 'p5c9@privaterelay.appleid.com', email: 'p5c9@privaterelay.appleid.com' })).toBeUndefined();
    expect(profileNameClaim({ name: ' Jane@Example.com ', email: 'jane@example.com' })).toBeUndefined();
  });

  it('omits an empty name', () => {
    expect(profileNameClaim({ name: '   ', email: 'jane@example.com' })).toBeUndefined();
  });
});

describe('withAppleFormPostName', () => {
  const user: OAuthUser = { providerId: 'apple-sub', email: 'x@privaterelay.appleid.com', emailVerified: true, name: 'x@privaterelay.appleid.com' };

  it('uses the name Apple sends on the first authorisation', () => {
    const raw = JSON.stringify({ name: { firstName: ' Jane ', lastName: 'Doe' }, email: 'x@privaterelay.appleid.com' });

    expect(withAppleFormPostName(user, raw)).toEqual({ ...user, name: 'Jane Doe' });
  });

  it('keeps a first name alone', () => {
    expect(withAppleFormPostName(user, JSON.stringify({ name: { firstName: 'Jane' } })).name).toBe('Jane');
  });

  it.each([undefined, '', 'not json', JSON.stringify({}), JSON.stringify({ name: { firstName: 7 } })])(
    'leaves the user unchanged without a usable name (%s)',
    (raw) => {
      expect(withAppleFormPostName(user, raw)).toBe(user);
    },
  );
});
