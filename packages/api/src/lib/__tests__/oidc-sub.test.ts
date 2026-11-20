import { describe, it, expect } from 'vitest';
import { randomBytes } from 'node:crypto';
import { deriveSectorIdentifier, computeSubForClient, OidcSectorHostMissingError } from '../oidc-sub.js';
import { computePairwiseSub, OidcPairwiseSecretMissingError } from '../oidc-pairwise.js';

/**
 * The single source of truth for the pairwise `sub` (ADR-0003 Slice 4). Load
 * bearing: /token and /userinfo both derive `sub` through this helper, so a
 * stock RP sees the same `sub` in the ID token and the /userinfo response.
 */

const SECRET = randomBytes(32);

describe('deriveSectorIdentifier', () => {
  it('uses the sector_identifier_uri host when registered', () => {
    expect(
      deriveSectorIdentifier({
        sectorIdentifierUri: 'https://sector.example.com/sec.json',
        redirectUris: ['https://app.example.com/callback'],
      }),
    ).toBe('sector.example.com');
  });

  it('falls back to the first redirect URI host when no sector_identifier_uri', () => {
    expect(
      deriveSectorIdentifier({
        sectorIdentifierUri: null,
        redirectUris: ['http://localhost:9000/callback'],
      }),
    ).toBe('localhost:9000');
  });

  it('throws when the client has no redirect URIs', () => {
    expect(() => deriveSectorIdentifier({ sectorIdentifierUri: null, redirectUris: [] })).toThrow();
  });
});

describe('computeSubForClient', () => {
  const client = { sectorHost: 'localhost:9000' };

  it('matches computePairwiseSub with the stored sector host (no drift)', () => {
    const viaHelper = computeSubForClient({ userId: 'user_abc', client, pairwiseSecret: SECRET });
    const direct = computePairwiseSub({
      userId: 'user_abc',
      sectorIdentifier: 'localhost:9000',
      pairwiseSecret: SECRET,
    });
    expect(viaHelper).toBe(direct);
  });

  it('is stable for the same (client, user) and distinct across sectors', () => {
    const a = computeSubForClient({ userId: 'user_abc', client, pairwiseSecret: SECRET });
    const again = computeSubForClient({ userId: 'user_abc', client, pairwiseSecret: SECRET });
    const otherSector = computeSubForClient({
      userId: 'user_abc',
      client: { sectorHost: 'other.example.com' },
      pairwiseSecret: SECRET,
    });
    expect(a).toBe(again);
    expect(a).not.toBe(otherSector);
  });

  it('propagates OidcPairwiseSecretMissingError when the secret is unset', () => {
    expect(() => computeSubForClient({ userId: 'u', client, pairwiseSecret: undefined })).toThrow(
      OidcPairwiseSecretMissingError,
    );
  });

  // Audit 2026-10 FINDING-004: the sub depends on the stored sector host and
  // on nothing else about the registration.
  it('does not change when redirect URIs are reordered, replaced or the sector URI is edited', () => {
    const stored = { sectorHost: 'app.example.com' };
    const before = computeSubForClient({
      userId: 'user_abc',
      client: { ...stored, redirectUris: ['https://app.example.com/cb', 'http://localhost:3000/cb'], sectorIdentifierUri: null } as never,
      pairwiseSecret: SECRET,
    });
    const variants = [
      { redirectUris: ['http://localhost:3000/cb', 'https://app.example.com/cb'], sectorIdentifierUri: null },
      { redirectUris: ['https://app.example.com/other'], sectorIdentifierUri: null },
      { redirectUris: ['https://app.example.com/cb'], sectorIdentifierUri: 'https://elsewhere.example/sector.json' },
    ];
    for (const variant of variants) {
      expect(
        computeSubForClient({ userId: 'user_abc', client: { ...stored, ...variant } as never, pairwiseSecret: SECRET }),
      ).toBe(before);
    }
  });

  it('equals what the first-redirect-URI rule produced before, once that host is stored', () => {
    const legacySector = deriveSectorIdentifier({ sectorIdentifierUri: null, redirectUris: ['https://app.example.com/cb'] });
    expect(computeSubForClient({ userId: 'u1', client: { sectorHost: legacySector }, pairwiseSecret: SECRET })).toBe(
      computePairwiseSub({ userId: 'u1', sectorIdentifier: 'app.example.com', pairwiseSecret: SECRET }),
    );
  });

  it('refuses to derive a sub for a client with no stored sector host', () => {
    expect(() => computeSubForClient({ userId: 'u', client: { sectorHost: null }, pairwiseSecret: SECRET })).toThrow(
      OidcSectorHostMissingError,
    );
  });
});
