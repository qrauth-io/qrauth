import { describe, it, expect } from 'vitest';
import { randomBytes } from 'node:crypto';
import { deriveSectorIdentifier, computeSubForClient } from '../oidc-sub.js';
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
  const client = { sectorIdentifierUri: null, redirectUris: ['http://localhost:9000/callback'] };

  it('matches computePairwiseSub with the derived sector identifier (no drift)', () => {
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
      client: { sectorIdentifierUri: null, redirectUris: ['https://other.example.com/cb'] },
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
});
