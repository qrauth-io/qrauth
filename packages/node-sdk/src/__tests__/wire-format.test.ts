import { describe, it, expect, vi, afterEach } from 'vitest';
import { QRAuth } from '../client.js';
import type { RevisionActor, VerificationResult } from '../types.js';
import type { AppLinkContent, LinkListContent } from '../types.js';
import {
  createAppLinkResponse,
  createLinkListResponse,
  getAppLinkResponse,
  getLinkListResponse,
  verifyAppLink,
  verifyLinkList,
  bulkCreateResponse,
  createResponse,
  getResponse,
  historyResponse,
  restoreResponse,
  verifyFlagged,
  verifyRevoked,
  verifySignedUnverifiedIssuer,
  verifyUntrustedLookalike,
  verifyVerified,
} from './fixtures/wire.js';

// The fixtures are real API responses; `tsc -p tsconfig.test.json` (part of
// `npm test`) checks them against the SDK types with `satisfies`. These tests
// check that the client hands them through unchanged and that the documented
// ways of reading them work.

function respond(body: unknown, status = 200) {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(
    new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } }),
  ));
}

afterEach(() => {
  vi.unstubAllGlobals();
});

const client = () => new QRAuth({ apiKey: 'k', baseUrl: 'https://api.test' });

describe('verify() results across trust states', () => {
  it.each<[string, VerificationResult]>([
    ['VERIFIED', verifyVerified],
    ['SIGNED_UNVERIFIED_ISSUER', verifySignedUnverifiedIssuer],
    ['UNTRUSTED (lookalike)', verifyUntrustedLookalike],
    ['UNTRUSTED (revoked)', verifyRevoked],
    ['UNTRUSTED (flagged)', verifyFlagged],
  ])('%s: verified mirrors trust_state', async (_label, fixture) => {
    respond(fixture);

    const result = await client().verify('tok');

    expect(result).toEqual(fixture);
    expect(result.verified).toBe(result.trust_state === 'VERIFIED');
  });

  it('scan_mode is FLASH only on the VERIFIED result', async () => {
    respond(verifyVerified);
    expect((await client().verify('tok')).scan_mode).toBe('FLASH');

    for (const fixture of [verifySignedUnverifiedIssuer, verifyUntrustedLookalike, verifyRevoked, verifyFlagged]) {
      respond(fixture);
      expect((await client().verify('tok')).scan_mode).toBe('PAGE');
    }
  });

  it('names the issuer only when VERIFIED (narrowing on organization.verified)', async () => {
    respond(verifyVerified);
    const result = await client().verify('tok');

    expect(result.organization.verified).toBe(true);
    if (result.organization.verified) {
      expect(result.organization.name).toBe('Acme Wire Ltd');
      expect(result.organization.verified_domain).toBe('acme-wire.example');
    }
    expect(verifySignedUnverifiedIssuer.organization).toEqual({ verified: false });
  });

  it('failure responses carry no destination_url', () => {
    expect(verifyRevoked).not.toHaveProperty('destination_url');
    expect(verifyFlagged).not.toHaveProperty('destination_url');
    expect(verifySignedUnverifiedIssuer.destination_url).toBe('https://example.com/pay');
  });

  it('domain_warning uses the wire names similar_to / verified_org / similarity', async () => {
    respond(verifyUntrustedLookalike);
    const result = await client().verify('tok');

    expect(result.domain_warning).toEqual({
      message: expect.any(String),
      similar_to: 'acme-wire.example',
      verified_org: 'Acme Wire Ltd',
      similarity: 95,
    });
  });
});

describe('create responses', () => {
  it('create(): alg_version and merkle_batch_id as sent', async () => {
    respond(createResponse, 201);

    const qr = await client().create({ destination: 'https://acme-wire.example/menu' });

    expect(qr.alg_version).toBe('hybrid-ecdsa-slhdsa-v1');
    expect(qr.merkle_batch_id).toBe(createResponse.merkle_batch_id);
  });

  it('create() and bulk() send scanMode in the request body', async () => {
    respond(createResponse, 201);
    await client().create({ destination: 'https://acme-wire.example/menu', scanMode: 'PAGE' });
    const createBody = JSON.parse(vi.mocked(fetch).mock.calls[0][1]!.body as string);
    expect(createBody.scanMode).toBe('PAGE');

    respond(bulkCreateResponse, 207);
    await client().bulk([{ destination: 'https://acme-wire.example/a', scanMode: 'PAGE' }]);
    const bulkBody = JSON.parse(vi.mocked(fetch).mock.calls[0][1]!.body as string);
    expect(bulkBody.items[0].scanMode).toBe('PAGE');
  });

  it('create() leaves scanMode to the API default when omitted', async () => {
    respond(createResponse, 201);
    await client().create({ destination: 'https://acme-wire.example/menu' });
    const body = JSON.parse(vi.mocked(fetch).mock.calls[0][1]!.body as string);
    expect(body).not.toHaveProperty('scanMode');
  });

  it('bulk(): counts are under summary', async () => {
    respond(bulkCreateResponse, 207);

    const res = await client().bulk([{ destination: 'https://acme-wire.example/a' }]);

    expect(res.summary).toEqual({ total: 1, succeeded: 1, failed: 0 });
    expect(res.results[0].success).toBe(true);
  });

  it('get(): verification_url is the URL the code encodes', async () => {
    respond(getResponse);

    const qr = await client().get('RKcPf9kv');

    expect(qr.verification_url).toBe('http://localhost:3000/v/RKcPf9kv');
    expect(qr).toEqual(getResponse);
  });
});

describe('edit history', () => {
  it('getHistory(): revisions as sent, newest first', async () => {
    respond(historyResponse);

    const history = await client().getHistory('RKcPf9kv');

    expect(history).toEqual(historyResponse);
    expect(history.data.map((r) => r.revision)).toEqual([5, 4, 3, 2, 1]);
  });

  it('BASELINE carries every tracked field with before null', () => {
    const baseline = historyResponse.data[4];

    expect(baseline.kind).toBe('BASELINE');
    expect(Object.keys(baseline.changes).sort()).toEqual(
      ['content', 'destinationUrl', 'expiresAt', 'scanMode', 'status', 'style'],
    );
    expect(Object.values(baseline.changes).every((c) => c.before === null)).toBe(true);
  });

  it('actor narrows on type', () => {
    const describeActor = (actor: RevisionActor): string => {
      switch (actor.type) {
        case 'USER':
          return actor.name ?? actor.email ?? actor.id;
        case 'API_KEY':
          return actor.label ?? actor.prefix ?? actor.id;
        case 'SYSTEM':
          return actor.id;
      }
    };

    expect(historyResponse.data.map((r) => describeActor(r.actor))).toEqual(
      ['Jane Doe', 'CI', 'cmkey0002', 'cmuser0002', 'migration'],
    );
  });

  it('restoreDestination(): the updated code as sent; RESTORED names its source', async () => {
    respond(restoreResponse);

    const qr = await client().restoreDestination('RKcPf9kv', 1);

    expect(qr).toEqual(restoreResponse);
    expect(historyResponse.data[1]).toMatchObject({ kind: 'RESTORED', restoredFrom: 1 });
  });
});

describe('smart link and link list responses', () => {
  it('create: a lookalike link is named in domain_warnings[].url', async () => {
    respond(createAppLinkResponse, 201);
    const created = await client().create({ contentType: 'app-link', content: getAppLinkResponse.content as AppLinkContent });

    expect(created.domain_warnings?.[0]).toEqual({
      url: 'https://thessa1oniki.gr/app',
      similar_to: 'thessaloniki.gr',
      verified_org: 'Municipality of Thessaloniki',
      similarity: 95,
      reason: 'homoglyph_match',
    });
    respond(createLinkListResponse, 201);
    expect((await client().create({ contentType: 'link-list', content: getLinkListResponse.content as LinkListContent })).domain_warnings).toBeUndefined();
  });

  it('get: content has the documented shape, links stored normalized', async () => {
    respond(getAppLinkResponse);
    const app = await client().get('tok');
    expect(app.contentType).toBe('app-link');
    expect(Object.keys(app.content as AppLinkContent).sort()).toEqual(['androidUrl', 'fallbackUrl', 'iosUrl']);

    respond(getLinkListResponse);
    const list = (await client().get('tok')).content as LinkListContent;
    expect(list.links.map((l) => l.url)).toEqual(['https://example.com/menu', 'https://bookings.example.com/bistro']);
  });

  it('verify: the verify page is the destination and scan_mode is PAGE; a lookalike link is UNTRUSTED', async () => {
    respond(verifyLinkList);
    const list = await client().verify('tok');
    expect(list).toMatchObject({ trust_state: 'VERIFIED', scan_mode: 'PAGE' });
    expect(list.destination_url).toMatch(/\/v\/jKJw3QHd$/);

    respond(verifyAppLink);
    const app = await client().verify('tok');
    expect(app).toMatchObject({ trust_state: 'UNTRUSTED', verified: false, scan_mode: 'PAGE' });
    expect(app.domain_warning?.similar_to).toBe('thessaloniki.gr');
  });
});
