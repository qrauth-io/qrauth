import { describe, it, expect, vi } from 'vitest';
import { Prisma, type PrismaClient } from '@prisma/client';
import { OidcClientAdminService } from '../oidc-client-admin.js';
import { PLAN_LIMITS } from '../../config/plan-limits.js';
import { hashString } from '../../lib/crypto.js';
import { constantTimeEqualString } from '../../lib/constant-time.js';

// Unit coverage for the admin service with a stubbed Prisma delegate. The
// secret lifecycle assertions go through constantTimeEqualString — the same
// helper /token uses — so the tests prove the stored hash actually verifies
// (or stops verifying) under the production comparison path.
//
// $transaction is a passthrough that hands the SAME oidcClient delegate to
// the callback as `tx` and records the isolation options, so the FINDING-002
// tests can assert the count and the create run inside one Serializable
// transaction.

function makeService(oidcClient: Record<string, ReturnType<typeof vi.fn>>): {
  service: OidcClientAdminService;
  transaction: ReturnType<typeof vi.fn>;
} {
  const transaction = vi.fn(
    async (fn: (tx: unknown) => Promise<unknown>, _opts?: unknown) => fn({ oidcClient }),
  );
  const service = new OidcClientAdminService({
    oidcClient,
    $transaction: transaction,
  } as unknown as PrismaClient);
  return { service, transaction };
}

function serializationFailure(): Prisma.PrismaClientKnownRequestError {
  return new Prisma.PrismaClientKnownRequestError('could not serialize access', {
    code: 'P2034',
    clientVersion: 'test',
  });
}

/** count() below the cap so plain createClient tests sail through the gate. */
const countBelowCap = () => vi.fn(async () => 0);

describe('OidcClientAdminService.createClient', () => {
  it('stores only the hash for confidential clients and forces tier CUSTOMER', async () => {
    const create = vi.fn(async ({ data }: { data: Record<string, unknown> }) => ({
      id: 'row1',
      createdAt: new Date(),
      updatedAt: new Date(),
      ...data,
    }));
    const { service } = makeService({ create, count: countBelowCap() });

    const result = await service.createClient('org1', 'BUSINESS', {
      name: 'Acme',
      redirectUris: ['https://acme.example/cb'],
      allowedScopes: ['openid'],
      clientType: 'confidential',
      idTokenSignedResponseAlg: 'RS256',
    });

    expect(result.outcome).toBe('created');
    if (result.outcome !== 'created') return;
    const { client, clientSecret } = result;
    expect(clientSecret).toBeTruthy();
    const persisted = create.mock.calls[0][0].data as Record<string, string>;
    expect(persisted.tier).toBe('CUSTOMER');
    // The persisted value is the SHA-256 of the returned plaintext, never the
    // plaintext itself.
    expect(constantTimeEqualString(hashString(clientSecret!), persisted.clientSecretHash)).toBe(true);
    expect(persisted.clientSecretHash).not.toBe(clientSecret);
    // The response projection must never carry the hash.
    expect('clientSecretHash' in client).toBe(false);
    expect(client.clientType).toBe('confidential');
  });

  it('creates public clients with no secret and a null hash', async () => {
    const create = vi.fn(async ({ data }: { data: Record<string, unknown> }) => ({
      id: 'row2',
      createdAt: new Date(),
      updatedAt: new Date(),
      ...data,
    }));
    const { service } = makeService({ create, count: countBelowCap() });

    const result = await service.createClient('org1', 'BUSINESS', {
      name: 'Acme SPA',
      redirectUris: ['https://spa.acme.example/cb'],
      allowedScopes: ['openid'],
      clientType: 'public',
      idTokenSignedResponseAlg: 'RS256',
    });

    expect(result.outcome).toBe('created');
    if (result.outcome !== 'created') return;
    expect(result.clientSecret).toBeNull();
    expect(create.mock.calls[0][0].data.clientSecretHash).toBeNull();
    expect(result.client.clientType).toBe('public');
  });
});

describe('FINDING-001 — sectorIdentifierUri host must match a redirect URI host', () => {
  const baseInput = {
    name: 'Acme',
    allowedScopes: ['openid'],
    clientType: 'confidential' as const,
    idTokenSignedResponseAlg: 'RS256' as const,
  };

  it('create: rejects a sector host matching no redirect URI, without touching the DB', async () => {
    const create = vi.fn();
    const { service, transaction } = makeService({ create, count: countBelowCap() });

    const result = await service.createClient('org1', 'BUSINESS', {
      ...baseInput,
      redirectUris: ['https://rp-a.example/cb'],
      sectorIdentifierUri: 'https://victim-rp.example/sector.json',
    });

    expect(result.outcome).toBe('sector_host_mismatch');
    expect(create).not.toHaveBeenCalled();
    // The input-only check fires BEFORE the transaction is even opened.
    expect(transaction).not.toHaveBeenCalled();
  });

  // Was accepted under the interim rule; two public hosts are now refused
  // whatever the sector URI says (audit 2026-10 FINDING-004).
  it('create: two redirect hosts are refused even when the sector host matches the SECOND one', async () => {
    const create = vi.fn(async ({ data }: { data: Record<string, unknown> }) => ({
      id: 'row1',
      createdAt: new Date(),
      updatedAt: new Date(),
      ...data,
    }));
    const { service } = makeService({ create, count: countBelowCap() });

    const result = await service.createClient('org1', 'BUSINESS', {
      ...baseInput,
      redirectUris: ['https://rp-a.example/cb', 'https://rp-b.example/cb'],
      sectorIdentifierUri: 'https://rp-b.example/sector.json',
    });

    expect(result.outcome).toBe('redirect_hosts_not_covered');
    expect(create).not.toHaveBeenCalled();
  });

  it('create: same hostname but different port is rejected (.host semantics)', async () => {
    const create = vi.fn();
    const { service } = makeService({ create, count: countBelowCap() });

    const result = await service.createClient('org1', 'BUSINESS', {
      ...baseInput,
      redirectUris: ['https://rp.example:8443/cb'],
      sectorIdentifierUri: 'https://rp.example/sector.json',
    });

    expect(result.outcome).toBe('sector_host_mismatch');
    expect(create).not.toHaveBeenCalled();
  });

  it('create: https sector on a loopback redirect host is allowed (host equality, nothing more)', async () => {
    const create = vi.fn(async ({ data }: { data: Record<string, unknown> }) => ({
      id: 'row1',
      createdAt: new Date(),
      updatedAt: new Date(),
      ...data,
    }));
    const { service } = makeService({ create, count: countBelowCap() });

    const result = await service.createClient('org1', 'BUSINESS', {
      ...baseInput,
      redirectUris: ['http://localhost:3000/cb'],
      sectorIdentifierUri: 'https://localhost:3000/sector.json',
    });

    expect(result.outcome).toBe('created');
  });

  it('create: no sectorIdentifierUri is unaffected by the invariant', async () => {
    const create = vi.fn(async ({ data }: { data: Record<string, unknown> }) => ({
      id: 'row1',
      createdAt: new Date(),
      updatedAt: new Date(),
      ...data,
    }));
    const { service } = makeService({ create, count: countBelowCap() });

    const result = await service.createClient('org1', 'BUSINESS', {
      ...baseInput,
      redirectUris: ['https://rp-a.example/cb'],
    });

    expect(result.outcome).toBe('created');
  });

  it('patch: rejects setting a sector whose host matches no existing redirect URI', async () => {
    const findFirst = vi.fn(async () => ({
      sectorIdentifierUri: null,
      redirectUris: ['https://rp-a.example/cb'],
    }));
    const updateMany = vi.fn();
    const { service } = makeService({ findFirst, updateMany });

    const result = await service.updateClient('row1', 'org1', {
      sectorIdentifierUri: 'https://victim-rp.example/sector.json',
    });

    expect(result.outcome).toBe('sector_host_mismatch');
    expect(updateMany).not.toHaveBeenCalled();
  });

  it('patch: rejects a redirectUris change that orphans the EXISTING sector', async () => {
    const findFirst = vi.fn(async () => ({
      sectorIdentifierUri: 'https://rp-a.example/sector.json',
      redirectUris: ['https://rp-a.example/cb'],
    }));
    const updateMany = vi.fn();
    const { service } = makeService({ findFirst, updateMany });

    const result = await service.updateClient('row1', 'org1', {
      redirectUris: ['https://rp-c.example/cb'],
    });

    expect(result.outcome).toBe('redirect_hosts_not_covered');
    expect(updateMany).not.toHaveBeenCalled();
  });

  it('patch: clearing the sector with null is always allowed', async () => {
    const row = {
      id: 'row1',
      organizationId: 'org1',
      clientId: 'qrauth_oidc_abc',
      clientSecretHash: hashString('s'),
      name: 'Acme',
      redirectUris: ['https://rp-c.example/cb'],
      allowedScopes: ['openid'],
      tier: 'CUSTOMER',
      sectorIdentifierUri: null,
      idTokenSignedResponseAlg: 'RS256',
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    const findFirst = vi.fn(async () => row);
    const updateMany = vi.fn(async () => ({ count: 1 }));
    const { service } = makeService({ findFirst, updateMany });

    const result = await service.updateClient('row1', 'org1', {
      sectorIdentifierUri: null,
      redirectUris: ['https://rp-c.example/cb'],
    });

    expect(result.outcome).toBe('updated');
    expect(updateMany).toHaveBeenCalledOnce();
  });

  it('patch: changing redirectUris with no existing sector skips the check', async () => {
    const row = {
      id: 'row1',
      organizationId: 'org1',
      clientId: 'qrauth_oidc_abc',
      clientSecretHash: null,
      name: 'Acme',
      redirectUris: ['https://rp-d.example/cb'],
      allowedScopes: ['openid'],
      tier: 'CUSTOMER',
      sectorIdentifierUri: null,
      idTokenSignedResponseAlg: 'RS256',
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    const findFirst = vi.fn(async () => row);
    const updateMany = vi.fn(async () => ({ count: 1 }));
    const { service } = makeService({ findFirst, updateMany });

    const result = await service.updateClient('row1', 'org1', {
      redirectUris: ['https://rp-d.example/cb'],
    });

    expect(result.outcome).toBe('updated');
  });

  it('patch: name-only updates do not read the existing row at all', async () => {
    const findFirst = vi.fn(async () => ({
      id: 'row1',
      organizationId: 'org1',
      clientId: 'qrauth_oidc_abc',
      clientSecretHash: null,
      name: 'Renamed',
      redirectUris: ['https://rp-d.example/cb'],
      allowedScopes: ['openid'],
      tier: 'CUSTOMER',
      sectorIdentifierUri: null,
      idTokenSignedResponseAlg: 'RS256',
      createdAt: new Date(),
      updatedAt: new Date(),
    }));
    const updateMany = vi.fn(async () => ({ count: 1 }));
    const { service } = makeService({ findFirst, updateMany });

    const result = await service.updateClient('row1', 'org1', { name: 'Renamed' });

    expect(result.outcome).toBe('updated');
    // Only the post-update re-read (getClient) hits findFirst — exactly once.
    expect(findFirst).toHaveBeenCalledTimes(1);
  });
});

describe('FINDING-002 — transactional per-org cap', () => {
  const input = {
    name: 'Acme',
    redirectUris: ['https://acme.example/cb'],
    allowedScopes: ['openid'],
    clientType: 'confidential' as const,
    idTokenSignedResponseAlg: 'RS256' as const,
  };

  it('runs the count and the create inside one Serializable transaction', async () => {
    const count = countBelowCap();
    const create = vi.fn(async ({ data }: { data: Record<string, unknown> }) => ({
      id: 'row1',
      createdAt: new Date(),
      updatedAt: new Date(),
      ...data,
    }));
    const { service, transaction } = makeService({ create, count });

    const result = await service.createClient('org1', 'BUSINESS', input);

    expect(result.outcome).toBe('created');
    expect(transaction).toHaveBeenCalledOnce();
    expect(transaction.mock.calls[0][1]).toMatchObject({ isolationLevel: 'Serializable' });
    // Both queries ran via the tx delegate the transaction callback received.
    expect(count).toHaveBeenCalledOnce();
    expect(create).toHaveBeenCalledOnce();
  });

  it('returns quota_exceeded at the cap without inserting', async () => {
    const count = vi.fn(async () => PLAN_LIMITS.BUSINESS.oidcClients as number);
    const create = vi.fn();
    const { service } = makeService({ create, count });

    const result = await service.createClient('org1', 'BUSINESS', input);

    expect(result.outcome).toBe('quota_exceeded');
    expect(create).not.toHaveBeenCalled();
  });

  it('retries once on a serialization failure (P2034) and succeeds', async () => {
    const count = countBelowCap();
    const create = vi.fn(async ({ data }: { data: Record<string, unknown> }) => ({
      id: 'row1',
      createdAt: new Date(),
      updatedAt: new Date(),
      ...data,
    }));
    let attempts = 0;
    const transaction = vi.fn(async (fn: (tx: unknown) => Promise<unknown>) => {
      attempts += 1;
      if (attempts === 1) throw serializationFailure();
      return fn({ oidcClient: { count, create } });
    });
    const service = new OidcClientAdminService({
      oidcClient: { count, create },
      $transaction: transaction,
    } as unknown as PrismaClient);

    const result = await service.createClient('org1', 'BUSINESS', input);

    expect(result.outcome).toBe('created');
    expect(transaction).toHaveBeenCalledTimes(2);
  });

  it('surfaces quota/conflict (not a throw) after two serialization failures', async () => {
    const transaction = vi.fn(async () => {
      throw serializationFailure();
    });
    const service = new OidcClientAdminService({
      oidcClient: {},
      $transaction: transaction,
    } as unknown as PrismaClient);

    const result = await service.createClient('org1', 'BUSINESS', input);

    expect(result.outcome).toBe('quota_exceeded');
    expect(transaction).toHaveBeenCalledTimes(2);
  });

  it('rethrows non-serialization transaction errors untouched', async () => {
    const boom = new Error('connection lost');
    const transaction = vi.fn(async () => {
      throw boom;
    });
    const service = new OidcClientAdminService({
      oidcClient: {},
      $transaction: transaction,
    } as unknown as PrismaClient);

    await expect(service.createClient('org1', 'BUSINESS', input)).rejects.toBe(boom);
    expect(transaction).toHaveBeenCalledTimes(1);
  });
});

describe('OidcClientAdminService.rotateSecret', () => {
  it('rotates: the new secret verifies against the new hash, the old one does not', async () => {
    const initialSecret = 'qrauth_oidc_secret_old';
    let storedHash = hashString(initialSecret);

    const findFirst = vi.fn(async () => ({ clientSecretHash: storedHash }));
    const updateMany = vi.fn(async ({ data }: { data: { clientSecretHash: string } }) => {
      storedHash = data.clientSecretHash;
      return { count: 1 };
    });
    const { service } = makeService({ findFirst, updateMany });

    const result = await service.rotateSecret('row1', 'org1');

    expect(result.outcome).toBe('rotated');
    if (result.outcome === 'rotated') {
      // New secret verifies under the production comparison...
      expect(constantTimeEqualString(hashString(result.clientSecret), storedHash)).toBe(true);
      // ...and the pre-rotation secret is invalid immediately (single-secret
      // model, no overlap window).
      expect(constantTimeEqualString(hashString(initialSecret), storedHash)).toBe(false);
    }
    // Org scoping + FIRST_PARTY exclusion + not-null guard live in the WHERE.
    const where = updateMany.mock.calls[0][0].where as Record<string, unknown>;
    expect(where).toMatchObject({
      id: 'row1',
      organizationId: 'org1',
      tier: { not: 'FIRST_PARTY' },
      clientSecretHash: { not: null },
    });
  });

  it('returns public_client for a client with no secret (route maps it to 400)', async () => {
    const findFirst = vi.fn(async () => ({ clientSecretHash: null }));
    const updateMany = vi.fn();
    const { service } = makeService({ findFirst, updateMany });

    const result = await service.rotateSecret('row1', 'org1');

    expect(result.outcome).toBe('public_client');
    expect(updateMany).not.toHaveBeenCalled();
  });

  it('returns not_found when the org-scoped lookup misses', async () => {
    const findFirst = vi.fn(async () => null);
    const { service } = makeService({ findFirst });

    const result = await service.rotateSecret('row1', 'other-org');

    expect(result.outcome).toBe('not_found');
  });
});

describe('OidcClientAdminService views', () => {
  it('never exposes clientSecretHash from list or get', async () => {
    const row = {
      id: 'row1',
      organizationId: 'org1',
      clientId: 'qrauth_oidc_abc',
      clientSecretHash: hashString('whatever'),
      name: 'Acme',
      redirectUris: ['https://acme.example/cb'],
      allowedScopes: ['openid'],
      tier: 'CUSTOMER',
      sectorIdentifierUri: null,
      idTokenSignedResponseAlg: 'RS256',
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    const { service } = makeService({
      findMany: vi.fn(async () => [row]),
      findFirst: vi.fn(async () => row),
    });

    const listed = await service.listClients('org1');
    const fetched = await service.getClient('row1', 'org1');

    expect('clientSecretHash' in listed[0]).toBe(false);
    expect(fetched).not.toBeNull();
    expect('clientSecretHash' in fetched!).toBe(false);
    expect(fetched!.clientType).toBe('confidential');
  });
});

// Audit 2026-10 FINDING-004: the pairwise sector is a stored, immutable host
// set at creation, and every non-loopback redirect host must equal it.
describe('FINDING-004 (2026-10) — stored sector host', () => {
  const baseInput = {
    name: 'Acme',
    allowedScopes: ['openid'],
    clientType: 'public' as const,
    idTokenSignedResponseAlg: 'RS256' as const,
  };
  const makeCreate = () =>
    vi.fn(async ({ data }: { data: Record<string, unknown> }) => ({
      id: 'row1', createdAt: new Date(), updatedAt: new Date(), ...data,
    }));

  it('create: stores the host of the first redirect URI as sectorHost', async () => {
    const create = makeCreate();
    const { service } = makeService({ create, count: countBelowCap() });

    const result = await service.createClient('org1', 'BUSINESS', { ...baseInput, redirectUris: ['https://app.example.com/cb'] });

    expect(result.outcome).toBe('created');
    expect(create.mock.calls[0][0].data.sectorHost).toBe('app.example.com');
  });

  it('create: stores the sectorIdentifierUri host when one is given', async () => {
    const create = makeCreate();
    const { service } = makeService({ create, count: countBelowCap() });

    await service.createClient('org1', 'BUSINESS', {
      ...baseInput,
      redirectUris: ['https://app.example.com/cb'],
      sectorIdentifierUri: 'https://app.example.com/sector.json',
    });

    expect(create.mock.calls[0][0].data.sectorHost).toBe('app.example.com');
  });

  it('create: rejects redirect URIs on two hosts, without touching the DB', async () => {
    const create = makeCreate();
    const { service, transaction } = makeService({ create, count: countBelowCap() });

    const result = await service.createClient('org1', 'BUSINESS', {
      ...baseInput,
      redirectUris: ['https://victim-rp.example/cb', 'https://attacker.example/cb'],
    });

    expect(result.outcome).toBe('redirect_hosts_not_covered');
    expect(transaction).not.toHaveBeenCalled();
  });

  it('create: rejects two hosts even with a sectorIdentifierUri on one of them', async () => {
    const { service } = makeService({ create: makeCreate(), count: countBelowCap() });

    const result = await service.createClient('org1', 'BUSINESS', {
      ...baseInput,
      redirectUris: ['https://a.example/cb', 'https://b.example/cb'],
      sectorIdentifierUri: 'https://a.example/sector.json',
    });

    expect(result.outcome).toBe('redirect_hosts_not_covered');
  });

  it('create: loopback hosts do not count, in any position', async () => {
    const create = makeCreate();
    const { service } = makeService({ create, count: countBelowCap() });

    const result = await service.createClient('org1', 'BUSINESS', {
      ...baseInput,
      redirectUris: ['https://app.example.com/cb', 'http://localhost:3000/cb', 'http://127.0.0.1:8080/cb'],
    });

    expect(result.outcome).toBe('created');
    expect(create.mock.calls[0][0].data.sectorHost).toBe('app.example.com');
  });

  it('create: a loopback-first list takes the real host as its sector, not the loopback one', async () => {
    const create = makeCreate();
    const { service } = makeService({ create, count: countBelowCap() });

    const result = await service.createClient('org1', 'BUSINESS', {
      ...baseInput,
      redirectUris: ['http://localhost:3000/cb', 'https://app.example.com/cb'],
    });

    expect(result.outcome).toBe('created');
    expect(create.mock.calls[0][0].data.sectorHost).toBe('app.example.com');
  });

  it('create: a loopback-only development client keeps the first redirect host', async () => {
    const create = makeCreate();
    const { service } = makeService({ create, count: countBelowCap() });

    await service.createClient('org1', 'BUSINESS', { ...baseInput, redirectUris: ['http://localhost:3001/cb', 'http://127.0.0.1:9/cb'] });

    expect(create.mock.calls[0][0].data.sectorHost).toBe('localhost:3001');
  });

  const existingRow = {
    sectorHost: 'app.example.com',
    sectorIdentifierUri: null,
    redirectUris: ['https://app.example.com/cb'],
  };
  const makeUpdateService = (row: Record<string, unknown> = existingRow) => {
    const updateMany = vi.fn(async (_args: { data: Record<string, unknown> }) => ({ count: 1 }));
    const findFirst = vi.fn(async () => ({ id: 'row1', createdAt: new Date(), updatedAt: new Date(), tier: 'CUSTOMER', ...row }));
    return { ...makeService({ updateMany, findFirst }), updateMany };
  };

  it('patch: reordering or adding loopback redirect URIs keeps sectorHost untouched', async () => {
    const { service, updateMany } = makeUpdateService();

    const result = await service.updateClient('row1', 'org1', {
      redirectUris: ['http://localhost:3000/cb', 'https://app.example.com/cb'],
    });

    expect(result.outcome).toBe('updated');
    expect('sectorHost' in updateMany.mock.calls[0][0].data).toBe(false);
  });

  it('patch: rejects moving the client to a host the stored sector does not cover', async () => {
    const { service, updateMany } = makeUpdateService();

    const result = await service.updateClient('row1', 'org1', { redirectUris: ['https://attacker.example/cb'] });

    expect(result.outcome).toBe('redirect_hosts_not_covered');
    expect(updateMany).not.toHaveBeenCalled();
  });

  it('patch: rejects adding a second host', async () => {
    const { service } = makeUpdateService();

    const result = await service.updateClient('row1', 'org1', {
      redirectUris: ['https://app.example.com/cb', 'https://other.example/cb'],
    });

    expect(result.outcome).toBe('redirect_hosts_not_covered');
  });

  it('patch: a sectorIdentifierUri must be on the stored sector host, whatever the redirect order', async () => {
    const { service } = makeUpdateService({
      ...existingRow,
      redirectUris: ['https://app.example.com/cb', 'http://localhost:3000/cb'],
    });

    const mismatch = await service.updateClient('row1', 'org1', { sectorIdentifierUri: 'https://localhost:3000/sector.json' });
    const match = await service.updateClient('row1', 'org1', { sectorIdentifierUri: 'https://app.example.com/sector.json' });

    expect(mismatch.outcome).toBe('sector_host_mismatch');
    expect(match.outcome).toBe('updated');
  });

  it('patch: clearing the sectorIdentifierUri does not change sectorHost', async () => {
    const { service, updateMany } = makeUpdateService({
      ...existingRow,
      sectorIdentifierUri: 'https://app.example.com/sector.json',
    });

    const result = await service.updateClient('row1', 'org1', { sectorIdentifierUri: null });

    expect(result.outcome).toBe('updated');
    expect('sectorHost' in updateMany.mock.calls[0][0].data).toBe(false);
  });

  it('views expose sectorHost', async () => {
    const { service } = makeUpdateService();
    const client = await service.getClient('row1', 'org1');
    expect(client?.sectorHost).toBe('app.example.com');
  });
});
