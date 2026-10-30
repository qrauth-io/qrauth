import { describe, it, expect, beforeAll, afterAll, beforeEach, vi } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';

/**
 * PATCH /api/v1/qrcodes/:token runs the same destination-similarity check as
 * create whenever the destination changes, and records the same HIGH fraud
 * incident when the new destination looks like a verified organization's
 * domain. The check is non-blocking, as on create.
 */

process.env.REDIS_URL ??= 'redis://localhost:6379';
process.env.JWT_SECRET ??= 'a'.repeat(32);
process.env.ANIMATED_QR_SECRET ??= 'a'.repeat(64);

const LOOKALIKE = 'https://paypa1-billing.example/login';
const CLEAN = 'https://example.com/menu';

const domainCheckCalls = vi.hoisted(() => [] as string[]);

vi.mock('../../services/domain.js', () => ({
  DomainService: class {
    async checkUrlAgainstVerifiedDomains(url: string) {
      domainCheckCalls.push(url);
      return url === 'https://paypa1-billing.example/login'
        ? {
            isSuspicious: true,
            warnings: [{ domain: 'paypal.com', verifiedOrgName: 'PayPal', similarity: 0.9, reason: 'typosquat' }],
          }
        : { isSuspicious: false, warnings: [] };
    }
    extractDomain(url: string) {
      return new URL(url).hostname;
    }
  },
}));
vi.mock('../../services/hybrid-signing.js', () => ({
  HybridSigningService: class {
    async signSingleQR() {
      return {
        ecdsaSignature: 'sig-new',
        algVersion: 'hybrid-ecdsa-slhdsa-v1',
        batchId: 'b1',
        leafIndex: 0,
        leafHash: 'h',
        leafNonce: 'n',
        merklePath: [],
      };
    }
  },
}));
vi.mock('../../services/mac.js', () => ({
  MacService: class {
    async signCanonical() {
      return { mac: 'mac-new', keyVersion: 1 };
    }
  },
}));
vi.mock('../../lib/cache.js', () => ({
  cacheGet: vi.fn(async () => null),
  cacheSet: vi.fn(async () => undefined),
  cacheDel: vi.fn(async () => undefined),
}));

const existingRow = {
  id: 'qr_1',
  token: 'tok_1',
  organizationId: 'org_1',
  destinationUrl: CLEAN,
  contentType: 'url',
  content: null,
  label: 'Menu',
  expiresAt: null,
  latitude: null,
  longitude: null,
  radiusM: 50,
  signature: 'sig-old',
  signingKeyId: 'sk_1',
  keyId: 'k1',
  algVersion: 'hybrid-ecdsa-slhdsa-v1',
  merkleBatchId: null,
  merkleLeafIndex: null,
  merkleLeafHash: null,
  merkleLeafNonce: null,
  merklePath: null,
  macTokenMac: 'mac-old',
  macKeyVersion: 1,
};

const fraudIncidentCreate = vi.fn(async () => ({}));
const prisma = {
  qRCode: {
    findUnique: vi.fn(async () => existingRow),
    update: vi.fn(async ({ data }: { data: Record<string, unknown> }) => ({ ...existingRow, ...data })),
  },
  fraudIncident: { create: fraudIncidentCreate },
  user: { findUnique: vi.fn(async () => ({ emailVerified: true })) },
};

let app: FastifyInstance;

const patch = (payload: Record<string, unknown>) =>
  app.inject({
    method: 'PATCH',
    url: '/api/v1/qrcodes/tok_1',
    headers: { 'content-type': 'application/json' },
    payload: JSON.stringify(payload),
  });

beforeAll(async () => {
  app = Fastify();
  app.decorate('prisma', prisma as never);
  app.decorate('signingService', {
    getActiveKey: async () => ({ id: 'sk_2', keyId: 'k2' }),
  } as never);
  app.decorate('batchSigner', {} as never);
  app.decorateRequest('user', null);
  app.decorate('authenticate', async (request: { user: unknown }) => {
    request.user = { id: 'user_1', orgId: 'org_1', role: 'OWNER', email: 'owner@example.com' };
  });
  const { default: qrCodeRoutes } = await import('../qrcodes.js');
  await app.register(qrCodeRoutes, { prefix: '/api/v1/qrcodes' });
  await app.ready();
});

afterAll(async () => {
  await app.close();
});

beforeEach(() => {
  domainCheckCalls.length = 0;
  fraudIncidentCreate.mockClear();
});

describe('PATCH /qrcodes/:token — destination similarity check', () => {
  it('checks the new destination and records a HIGH incident for a lookalike', async () => {
    const res = await patch({ destinationUrl: LOOKALIKE });

    expect(res.statusCode).toBe(200);
    expect(domainCheckCalls).toEqual([LOOKALIKE]);
    expect(fraudIncidentCreate).toHaveBeenCalledTimes(1);
    expect(fraudIncidentCreate).toHaveBeenCalledWith({
      data: expect.objectContaining({
        qrCodeId: 'qr_1',
        type: 'MANUAL_REPORT',
        severity: 'HIGH',
        details: expect.objectContaining({ reason: 'suspicious_domain', similarTo: 'paypal.com' }),
      }),
    });
    // Non-blocking, as on create: the edit is saved and the warning returned.
    expect(res.json().destinationUrl).toBe(LOOKALIKE);
    expect(res.json().domain_warnings).toEqual([
      { similar_to: 'paypal.com', verified_org: 'PayPal', similarity: 0.9, reason: 'typosquat' },
    ]);
  });

  it('records nothing for a clean new destination', async () => {
    const res = await patch({ destinationUrl: 'https://example.org/new' });

    expect(res.statusCode).toBe(200);
    expect(domainCheckCalls).toEqual(['https://example.org/new']);
    expect(fraudIncidentCreate).not.toHaveBeenCalled();
    expect(res.json()).not.toHaveProperty('domain_warnings');
  });

  it('skips the check when the destination does not change', async () => {
    const res = await patch({ label: 'Renamed' });

    expect(res.statusCode).toBe(200);
    expect(domainCheckCalls).toEqual([]);
    expect(fraudIncidentCreate).not.toHaveBeenCalled();
  });
});
