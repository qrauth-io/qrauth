import { describe, it, expect, beforeAll, afterAll, beforeEach, vi } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';

/**
 * POST /api/v1/demo/qrcodes (unauthenticated): http(s) destinations only,
 * every row is marked source = 'demo' so the verify page never shows it as
 * VERIFIED, and the route uses the fail-closed `demo` rate-limit tier.
 */

process.env.REDIS_URL ??= 'redis://localhost:6379';
process.env.JWT_SECRET ??= 'a'.repeat(32);
process.env.ANIMATED_QR_SECRET ??= 'a'.repeat(64);
process.env.DEMO_API_KEY = 'demo-key-for-tests';

vi.mock('../../services/hybrid-signing.js', () => ({
  HybridSigningService: class {
    async signSingleQR() {
      return {
        ecdsaSignature: 'sig',
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
      return { mac: 'mac', keyVersion: 1 };
    }
  },
}));
vi.mock('../../services/transparency.js', () => ({
  TransparencyLogService: class {
    async appendEntry() {
      return { logIndex: 1 };
    }
  },
}));
vi.mock('../../services/domain.js', () => ({
  DomainService: class {
    async checkUrlAgainstVerifiedDomains() {
      return { isSuspicious: false, warnings: [] };
    }
  },
}));

const created: Array<Record<string, unknown>> = [];
const prisma = {
  apiKey: { findFirst: vi.fn(async () => ({ organizationId: 'org_qrauth' })) },
  qRCode: {
    create: vi.fn(async ({ data }: { data: Record<string, unknown> }) => {
      created.push(data);
      return { id: 'qr_1', createdAt: new Date(), ...data };
    }),
  },
};

let app: FastifyInstance;
const routeConfigs: Array<{ url: string; method: string | string[]; config?: unknown }> = [];

const create = (payload: unknown) =>
  app.inject({
    method: 'POST',
    url: '/api/v1/demo/qrcodes',
    headers: { 'content-type': 'application/json' },
    payload: JSON.stringify(payload),
  });

beforeAll(async () => {
  app = Fastify();
  app.decorate('prisma', prisma as never);
  app.decorate('signingService', { getActiveKey: async () => ({ id: 'sk_1', keyId: 'k1' }) } as never);
  app.decorate('batchSigner', {} as never);
  app.addHook('onRoute', (r) => { routeConfigs.push({ url: r.url, method: r.method, config: r.config }); });
  const { default: demoRoutes } = await import('../demo.js');
  await app.register(demoRoutes, { prefix: '/api/v1/demo' });
  await app.ready();
});

afterAll(async () => {
  await app.close();
});

beforeEach(() => {
  created.length = 0;
});

describe('POST /api/v1/demo/qrcodes', () => {
  it('marks the row as a demo code', async () => {
    const res = await create({ url: 'https://example.com/landing' });

    expect(res.statusCode).toBeLessThan(300);
    expect(created).toHaveLength(1);
    expect(created[0]).toMatchObject({ source: 'demo', destinationUrl: 'https://example.com/landing' });
  });

  it.each(['javascript:alert(1)', 'data:text/html,<b>x</b>', 'intent://x#Intent;end', 'ftp://example.com'])(
    'rejects %s',
    async (url) => {
      const res = await create({ url });

      expect(res.statusCode).toBe(400);
      expect(created).toHaveLength(0);
    },
  );

  it('uses the demo rate-limit tier (5/min per network, fails closed)', async () => {
    const { rateLimitDemo } = await import('../../middleware/rateLimit.js');
    const route = routeConfigs.find((r) => r.url === '/api/v1/demo/qrcodes' && r.method === 'POST');

    expect((route?.config as { rateLimit?: unknown })?.rateLimit).toBe(rateLimitDemo);
    expect(rateLimitDemo).toMatchObject({ max: 5, timeWindow: '1 minute', skipOnError: false });
  });
});
