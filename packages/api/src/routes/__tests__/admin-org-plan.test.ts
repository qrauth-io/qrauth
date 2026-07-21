import { describe, it, expect, beforeAll, afterEach } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';

/**
 * Integration test for PATCH /api/v1/admin/organizations/:orgId/plan
 * (superadmin org-plan control). Builds a minimal Fastify app wiring the real
 * admin route + its real requireAdmin gate and zod validation, with a stubbed
 * `authenticate` (reads x-test-email to populate request.user) and a stubbed
 * `prisma` — so the gate, the subscription guard, the no-op short-circuit, and
 * the audit write are all exercised without DB/Redis/JWT weight. Mirrors the
 * internal-mac-stats.test.ts harness pattern.
 */

beforeAll(() => {
  process.env.DATABASE_URL = 'postgresql://test:test@localhost:5432/test';
  process.env.REDIS_URL = 'redis://localhost:6379';
  process.env.JWT_SECRET = 'a'.repeat(32);
  process.env.ANIMATED_QR_SECRET = 'a'.repeat(64);
  process.env.ADMIN_EMAILS = 'admin@qrauth.io';
});

const ADMIN = 'admin@qrauth.io';
const NON_ADMIN = 'member@example.com';

type OrgRow = { id: string; plan: string; stripeSubscriptionId: string | null };

interface Harness {
  app: FastifyInstance;
  updateCalls: Array<Record<string, unknown>>;
  auditCalls: Array<Record<string, unknown>>;
}

async function buildApp(org: OrgRow | null): Promise<Harness> {
  const updateCalls: Array<Record<string, unknown>> = [];
  const auditCalls: Array<Record<string, unknown>> = [];

  const prisma = {
    organization: {
      findUnique: async () => org,
      update: async ({ data }: { data: Record<string, unknown> }) => {
        updateCalls.push(data);
        return { id: org!.id, plan: data.plan as string };
      },
    },
    auditLog: {
      create: async ({ data }: { data: Record<string, unknown> }) => {
        auditCalls.push(data);
      },
    },
  };

  const app = Fastify({ logger: false });
  app.decorate('prisma', prisma as never);
  // Stub auth: x-test-email present → authenticated as that user; absent → 401.
  app.decorate('authenticate', async (req: never, reply: never) => {
    const request = req as unknown as { headers: Record<string, string>; user?: unknown };
    const email = request.headers['x-test-email'];
    if (!email) {
      (reply as unknown as { status: (n: number) => { send: (b: unknown) => void } })
        .status(401)
        .send({ statusCode: 401, error: 'Unauthorized', message: 'auth required' });
      return;
    }
    request.user = { id: 'u_1', orgId: 'o_1', role: 'OWNER', email };
  });

  const { default: adminRoutes } = await import('../admin.js');
  await app.register(adminRoutes, { prefix: '/api/v1/admin' });
  await app.ready();
  return { app, updateCalls, auditCalls };
}

function patchPlan(
  app: FastifyInstance,
  orgId: string,
  body: unknown,
  email: string | null = ADMIN
) {
  return app.inject({
    method: 'PATCH',
    url: `/api/v1/admin/organizations/${orgId}/plan`,
    headers: email ? { 'x-test-email': email } : {},
    payload: body,
  });
}

describe('PATCH /admin/organizations/:orgId/plan', () => {
  let current: Harness | null = null;

  afterEach(async () => {
    if (current) {
      await current.app.close();
      current = null;
    }
  });

  it('403s for an authenticated non-admin user', async () => {
    current = await buildApp({ id: 'o_1', plan: 'FREE', stripeSubscriptionId: null });
    const res = await patchPlan(current.app, 'o_1', { plan: 'PRO' }, NON_ADMIN);
    expect(res.statusCode).toBe(403);
    expect(current.updateCalls).toHaveLength(0);
  });

  it('401s when unauthenticated', async () => {
    current = await buildApp({ id: 'o_1', plan: 'FREE', stripeSubscriptionId: null });
    const res = await patchPlan(current.app, 'o_1', { plan: 'PRO' }, null);
    expect(res.statusCode).toBe(401);
  });

  it('happy path: changes plan, returns old/new + hasStripeSubscription, writes audit', async () => {
    current = await buildApp({ id: 'o_1', plan: 'FREE', stripeSubscriptionId: null });
    const res = await patchPlan(current.app, 'o_1', { plan: 'PRO' });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toMatchObject({
      id: 'o_1',
      oldPlan: 'FREE',
      newPlan: 'PRO',
      hasStripeSubscription: false,
    });
    expect(current.updateCalls).toEqual([{ plan: 'PRO' }]);
    expect(current.auditCalls).toHaveLength(1);
    expect(current.auditCalls[0]).toMatchObject({
      action: 'admin.organization.planChange',
      resource: 'Organization',
      resourceId: 'o_1',
      metadata: { from: 'FREE', to: 'PRO', confirmStripeOverride: false },
    });
  });

  it('409 subscription guard: org with a subscription, no override flag', async () => {
    current = await buildApp({ id: 'o_1', plan: 'FREE', stripeSubscriptionId: 'sub_123' });
    const res = await patchPlan(current.app, 'o_1', { plan: 'PRO' });
    expect(res.statusCode).toBe(409);
    expect(res.json()).toMatchObject({ error: 'Conflict', hasStripeSubscription: true });
    expect(res.json().message).toMatch(/active Stripe subscription/i);
    // No mutation, no audit when the guard trips.
    expect(current.updateCalls).toHaveLength(0);
    expect(current.auditCalls).toHaveLength(0);
  });

  it('confirmStripeOverride: true lets the change through and records the flag', async () => {
    current = await buildApp({ id: 'o_1', plan: 'FREE', stripeSubscriptionId: 'sub_123' });
    const res = await patchPlan(current.app, 'o_1', { plan: 'ENTERPRISE', confirmStripeOverride: true });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toMatchObject({
      oldPlan: 'FREE',
      newPlan: 'ENTERPRISE',
      hasStripeSubscription: true,
    });
    expect(current.updateCalls).toEqual([{ plan: 'ENTERPRISE' }]);
    expect(current.auditCalls[0]).toMatchObject({
      metadata: { from: 'FREE', to: 'ENTERPRISE', confirmStripeOverride: true },
    });
  });

  it('no-op (same plan): 200 with noop, no mutation, no audit — even with a subscription', async () => {
    current = await buildApp({ id: 'o_1', plan: 'PRO', stripeSubscriptionId: 'sub_123' });
    const res = await patchPlan(current.app, 'o_1', { plan: 'PRO' });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toMatchObject({ oldPlan: 'PRO', newPlan: 'PRO', noop: true });
    expect(current.updateCalls).toHaveLength(0);
    expect(current.auditCalls).toHaveLength(0);
  });

  it('404 for an unknown org', async () => {
    current = await buildApp(null);
    const res = await patchPlan(current.app, 'missing', { plan: 'PRO' });
    expect(res.statusCode).toBe(404);
  });

  it('400 for an invalid plan value', async () => {
    current = await buildApp({ id: 'o_1', plan: 'FREE', stripeSubscriptionId: null });
    const res = await patchPlan(current.app, 'o_1', { plan: 'GOLD' });
    expect(res.statusCode).toBe(400);
  });

  it('400 for an unknown body key (strict schema)', async () => {
    current = await buildApp({ id: 'o_1', plan: 'FREE', stripeSubscriptionId: null });
    const res = await patchPlan(current.app, 'o_1', { plan: 'PRO', trustLevel: 'GOVERNMENT' });
    expect(res.statusCode).toBe(400);
    // The KYC/trust boundary can't be crossed even by smuggling a field.
    expect(current.updateCalls).toHaveLength(0);
  });
});
