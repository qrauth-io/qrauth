import { describe, it, expect, vi } from 'vitest';

// approveSession calls cacheDel (Redis); stub the cache module so these unit
// tests stay hermetic and don't need Redis.
vi.mock('../../lib/cache.js', () => ({
  cacheGet: vi.fn(async () => null),
  cacheSet: vi.fn(async () => undefined),
  cacheDel: vi.fn(async () => undefined),
}));

import { AuthSessionService, SigningUnavailableError } from '../auth-session.js';

const FUTURE = new Date(Date.now() + 60_000);

interface ApproveFakeOpts {
  appSlug: string;
  appOrgId: string;
  signingKey: { keyId: string; status: string } | null;
}

/**
 * Fake Prisma modelling exactly the calls approveSession makes — including the
 * `signingKey.findFirst` lookup (the call PR2's fake never modelled, which is
 * how the keyless-platform-org 503 slipped through). The findFirst is a spy so
 * tests can assert it is skipped for the CLI app.
 */
function makeApproveFake(opts: ApproveFakeOpts) {
  const session = {
    id: 's1',
    appId: 'app1',
    token: 'tok_1',
    status: 'PENDING',
    scopes: ['identity'],
    expiresAt: FUTURE,
    app: { id: 'app1', slug: opts.appSlug, organizationId: opts.appOrgId },
  };
  const findFirst = vi.fn(async () => opts.signingKey);
  let updated: Record<string, unknown> = {};
  const prisma = {
    authSession: {
      findUnique: async () => ({ ...session }),
      updateMany: async ({ data }: any) => {
        updated = { ...session, ...data };
        return { count: 1 };
      },
      findUniqueOrThrow: async () => ({ ...updated }),
    },
    user: {
      findUnique: async () => ({ id: 'u1', name: 'Test', email: 't@example.com' }),
    },
    signingKey: { findFirst: findFirst },
  };
  const signingService = { signCanonical: vi.fn(async () => 'BASE64SIG') };
  const service = new AuthSessionService(prisma as any, signingService as any);
  return { service, findFirst, signingService, getUpdated: () => updated };
}

describe('approveSession — federation signature (ADR-0002 §7)', () => {
  it('skips signing for the qrauth-cli app: APPROVED, null signature, no key lookup', async () => {
    const { service, findFirst, signingService, getUpdated } = makeApproveFake({
      appSlug: 'qrauth-cli',
      appOrgId: 'org_qrauth_platform',
      signingKey: null, // platform org is keyless — must not matter for CLI
    });

    const result = await service.approveSession('s1', 'u1', undefined, undefined, 'org_user');

    expect(result.status).toBe('APPROVED');
    expect(result.signature).toBeNull();
    // The whole point: the signing-key lookup is never reached for CLI.
    expect(findFirst).not.toHaveBeenCalled();
    expect(signingService.signCanonical).not.toHaveBeenCalled();
    // Persisted: null signature + the resolved target org.
    expect(getUpdated().signature).toBeNull();
    expect(getUpdated().targetOrganizationId).toBe('org_user');
  });

  it('still signs for a federation (non-cli) app when a key exists', async () => {
    const { service, findFirst, signingService } = makeApproveFake({
      appSlug: 'acme-login',
      appOrgId: 'org_acme',
      signingKey: { keyId: 'k1', status: 'ACTIVE' },
    });

    const result = await service.approveSession('s1', 'u1');

    expect(findFirst).toHaveBeenCalledTimes(1);
    expect(signingService.signCanonical).toHaveBeenCalledTimes(1);
    expect(result.signature).toBe('k1:BASE64SIG');
  });

  it('still fails closed for a federation app with no active key (regression)', async () => {
    const { service } = makeApproveFake({
      appSlug: 'acme-login',
      appOrgId: 'org_acme',
      signingKey: null,
    });

    await expect(service.approveSession('s1', 'u1')).rejects.toBeInstanceOf(SigningUnavailableError);
  });
});
