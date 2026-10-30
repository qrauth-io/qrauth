import { describe, it, expect, vi, afterEach } from 'vitest';
import { QRAuth } from '../client.js';
import type { VerificationResult } from '../types.js';
import {
  bulkCreateResponse,
  createResponse,
  getResponse,
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
