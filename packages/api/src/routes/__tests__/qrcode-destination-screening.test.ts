import { describe, it, expect, beforeAll, afterAll, beforeEach, vi } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';

/**
 * Destination screening on create, bulk create and destination edits, with
 * the Web Risk verdict mocked: a hit is refused (422 DestinationFlagged), a
 * clean result passes, and an unavailable API lets the edit through and
 * queues a re-check. A flagged code is cleared only by a clean new URL.
 */

process.env.REDIS_URL ??= 'redis://localhost:6379';
process.env.JWT_SECRET ??= 'a'.repeat(32);
process.env.ANIMATED_QR_SECRET ??= 'a'.repeat(64);

const screening = vi.hoisted(() => ({
  verdict: { verdict: 'clean' } as { verdict: string; threatTypes?: string[]; detail?: string },
  enqueue: vi.fn(async () => undefined),
}));
vi.mock('../../services/destination-screening.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../services/destination-screening.js')>()),
  screenDestination: vi.fn(async () => screening.verdict),
  enqueueDestinationRecheck: screening.enqueue,
}));

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

let existingRow: Record<string, unknown> = {
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


Object.assign(prisma, {
  organization: { findUnique: vi.fn(async () => ({ plan: 'FREE' })) },
  membership: { findFirst: vi.fn(async () => ({ id: 'm1' })) },
});
Object.assign(prisma.qRCode, { count: vi.fn(async () => 0) });
let app: FastifyInstance;

const send = (method: 'PATCH' | 'POST', url: string, payload: Record<string, unknown>) =>
  app.inject({
    method,
    url: `/api/v1/qrcodes${url}`,
    headers: { 'content-type': 'application/json' },
    payload: JSON.stringify(payload),
  });

beforeAll(async () => {
  app = Fastify();
  app.decorate('prisma', prisma as never);
  app.decorate('signingService', { getActiveKey: async () => ({ id: 'sk_2', keyId: 'k2' }) } as never);
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

const BASE_ROW = { ...existingRow };

beforeEach(() => {
  existingRow = { ...BASE_ROW, destinationFlaggedAt: null, destinationFlagReason: null };
  screening.verdict = { verdict: 'clean' };
  screening.enqueue.mockClear();
  prisma.qRCode.update.mockClear();
});

const HIT = { verdict: 'flagged', threatTypes: ['SOCIAL_ENGINEERING'] };

describe('create and bulk create', () => {
  it('POST / → 422 DestinationFlagged for a listed destination', async () => {
    screening.verdict = HIT;

    const res = await send('POST', '', { destinationUrl: 'https://bad.example' });

    expect(res.statusCode).toBe(422);
    expect(res.json()).toMatchObject({ error: 'DestinationFlagged', threatType: 'SOCIAL_ENGINEERING' });
  });

  it('POST /bulk reports a listed item as DESTINATION_FLAGGED', async () => {
    screening.verdict = HIT;

    const res = await send('POST', '/bulk', { items: [{ destinationUrl: 'https://bad.example' }] });

    expect(res.statusCode).toBe(207);
    expect(res.json().results[0]).toMatchObject({
      success: false,
      errorCode: 'DESTINATION_FLAGGED',
      threatTypes: ['SOCIAL_ENGINEERING'],
    });
  });
});

describe('PATCH destination', () => {
  it('422 for a listed new destination; nothing is written', async () => {
    screening.verdict = HIT;

    const res = await send('PATCH', '/tok_1', { destinationUrl: 'https://bad.example' });

    expect(res.statusCode).toBe(422);
    expect(prisma.qRCode.update).not.toHaveBeenCalled();
  });

  it('API unavailable: the edit goes through and a re-check is queued', async () => {
    screening.verdict = { verdict: 'unavailable', detail: 'timeout' };

    const res = await send('PATCH', '/tok_1', { destinationUrl: 'https://new.example' });

    expect(res.statusCode).toBe(200);
    expect(screening.enqueue).toHaveBeenCalledWith('tok_1', expect.anything());
  });

  it('a clean new destination clears an existing flag', async () => {
    existingRow = { ...existingRow, destinationFlaggedAt: new Date(), destinationFlagReason: 'MALWARE' };

    const res = await send('PATCH', '/tok_1', { destinationUrl: 'https://new.example' });

    expect(res.statusCode).toBe(200);
    expect(prisma.qRCode.update.mock.calls[0][0].data).toMatchObject({ destinationFlaggedAt: null, destinationFlagReason: null });
    expect(screening.enqueue).not.toHaveBeenCalled();
  });

  it.each([
    ['unavailable', { verdict: 'unavailable', detail: 'timeout' }, 503],
    ['not configured', { verdict: 'skipped' }, 409],
  ])('a flagged code cannot be repointed while screening is %s', async (_label, verdict, status) => {
    existingRow = { ...existingRow, destinationFlaggedAt: new Date(), destinationFlagReason: 'MALWARE' };
    screening.verdict = verdict;

    const res = await send('PATCH', '/tok_1', { destinationUrl: 'https://new.example' });

    expect(res.statusCode).toBe(status);
    expect(prisma.qRCode.update).not.toHaveBeenCalled();
  });

  it('a label-only edit does not screen or clear anything', async () => {
    existingRow = { ...existingRow, destinationFlaggedAt: new Date() };

    const res = await send('PATCH', '/tok_1', { label: 'New label' });

    expect(res.statusCode).toBe(200);
    expect(prisma.qRCode.update.mock.calls[0][0].data).not.toHaveProperty('destinationFlaggedAt');
  });
});
