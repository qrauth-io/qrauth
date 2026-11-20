/**
 * Dev seed for organization policies (ADR-0008 D8), for review on a local
 * dev server.
 *
 * Drives the running API (API_URL, default http://127.0.0.1:3000) so codes
 * and policies are written by the real routes; Prisma is used only for
 * setup the API cannot do (email verification, plan, temporary
 * memberships, a legacy API key). Creates:
 *
 *   Policy Review Co (BUSINESS), no policy yet:
 *     owner@, admin@, manager@, member@policy-review.local
 *     - a legacy API key ("Print shop integration": no owner, MEMBER), as
 *       keys created before owners were recorded
 *     - an API key owned by admin@ ("CI deploy", MANAGER)
 *     - codes on example.com (www and shop subdomains), one on example.net,
 *       a link list with one link on example.org, and a vCard
 *   Downgraded Review Org (PRO): owner@downgraded-review.local; an
 *     enforced allowlist (example.com) and minimum role MANAGER set while
 *     on Business, then moved to Pro.
 *   Locked Review Org (PRO): owner@locked-review.local, no policy.
 *
 * Password for every account: password123. Local databases only; re-running
 * needs a fresh database (run `npm run db:seed -w packages/api` first, it
 * creates the organization used to park invitees).
 *
 *   npm run db:seed:policies -w packages/api   (with the API dev server running)
 */
import { PrismaClient } from '@prisma/client';

import { generateApiKey } from '../src/lib/crypto.js';
import { hashPassword } from '../src/lib/password.js';

const API = process.env.API_URL ?? 'http://127.0.0.1:3000';
const PASSWORD = 'password123';

const db = new PrismaClient();

function assertLocal(): void {
  const host = (() => {
    try {
      return new URL(process.env.DATABASE_URL ?? '').hostname;
    } catch {
      return '';
    }
  })();
  if (process.env.NODE_ENV === 'production' || !['localhost', '127.0.0.1', '::1'].includes(host)) {
    throw new Error('seed-policies-dev: refusing to run against a non-local database');
  }
}

type Auth = { bearer?: string; apiKey?: string };

async function api<T = Record<string, unknown>>(method: string, path: string, auth: Auth, body?: unknown): Promise<T> {
  const headers: Record<string, string> = { 'user-agent': 'qrauth-policies-seed/1.0' };
  if (auth.bearer) headers.authorization = `Bearer ${auth.bearer}`;
  if (auth.apiKey) headers['x-api-key'] = auth.apiKey;
  if (body !== undefined) headers['content-type'] = 'application/json';
  const res = await fetch(`${API}${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  const text = await res.text();
  if (!res.ok) throw new Error(`${method} ${path} → ${res.status}: ${text.slice(0, 300)}`);
  return (text ? JSON.parse(text) : {}) as T;
}

async function signup(email: string, name: string, organizationName: string): Promise<string> {
  await api('POST', '/api/v1/auth/signup', {}, { name, email, password: PASSWORD, organizationName });
  // Verified and past onboarding, so the dashboard opens directly.
  await db.user.update({ where: { email }, data: { emailVerified: true, onboardedAt: new Date() } });
  const m = await db.membership.findFirstOrThrow({ where: { user: { email } }, select: { organizationId: true } });
  await db.organization.update({ where: { id: m.organizationId }, data: { onboardedAt: new Date() } });
  return m.organizationId;
}

async function login(email: string): Promise<string> {
  const res = await api<{ token?: string; accessToken?: string }>('POST', '/api/v1/auth/login', {}, { email, password: PASSWORD });
  const token = res.token ?? res.accessToken;
  if (!token) throw new Error(`login ${email}: no token in response`);
  return token;
}

/** A verified user who joins `orgId` with `role` through a real invitation. */
async function addMember(owner: string, orgId: string, email: string, name: string, role: string, parkingOrgId: string): Promise<void> {
  const user = await db.user.create({ data: { email, name, passwordHash: await hashPassword(PASSWORD), emailVerified: true, onboardedAt: new Date() } });
  await db.membership.create({ data: { userId: user.id, organizationId: parkingOrgId, role: 'VIEWER' } });
  await api('POST', `/api/v1/organizations/${orgId}/invitations`, { bearer: owner }, { email, role });
  const { token } = await db.invitation.findFirstOrThrow({ where: { email, organizationId: orgId }, select: { token: true } });
  await api('POST', `/api/v1/organizations/invitations/${token}/accept`, { bearer: await login(email) }, {});
  await db.membership.deleteMany({ where: { userId: user.id, organizationId: parkingOrgId } });
}

async function seedReviewOrg(parkingOrgId: string): Promise<void> {
  const orgId = await signup('owner@policy-review.local', 'Olga Owner', 'Policy Review Co');
  await db.organization.update({ where: { id: orgId }, data: { plan: 'BUSINESS' } });
  const owner = await login('owner@policy-review.local');
  await addMember(owner, orgId, 'admin@policy-review.local', 'Adam Admin', 'ADMIN', parkingOrgId);
  await addMember(owner, orgId, 'manager@policy-review.local', 'Mona Manager', 'MANAGER', parkingOrgId);
  await addMember(owner, orgId, 'member@policy-review.local', 'Mia Member', 'MEMBER', parkingOrgId);

  // The API now records an owner on every key, so the legacy key is written directly.
  const legacy = generateApiKey();
  await db.apiKey.create({ data: { organizationId: orgId, keyHash: legacy.hash, prefix: legacy.prefix, label: 'Print shop integration' } });
  await api('POST', '/api/v1/api-keys', { bearer: await login('admin@policy-review.local') }, { label: 'CI deploy', role: 'MANAGER' });

  const codes: Array<Record<string, unknown>> = [
    { label: 'Menu', destinationUrl: 'https://www.example.com/menu' },
    { label: 'Spring poster', destinationUrl: 'https://shop.example.com/spring' },
    { label: 'Old campaign', destinationUrl: 'https://www.example.net/old-campaign' },
    {
      label: 'Visitor links',
      contentType: 'link-list',
      content: {
        title: 'Visitor links',
        links: [
          { label: 'Opening hours', url: 'https://www.example.com/hours' },
          { label: 'Partner map', url: 'https://maps.example.org/partner' },
        ],
      },
    },
    { label: 'Front desk contact', contentType: 'vcard', content: { firstName: 'Front', lastName: 'Desk', website: 'https://www.example.org/' } },
  ];
  for (const body of codes) await api('POST', '/api/v1/qrcodes', { bearer: owner }, body);
}

async function seedDowngradedOrg(): Promise<void> {
  const orgId = await signup('owner@downgraded-review.local', 'Dora Downgraded', 'Downgraded Review Org');
  await db.organization.update({ where: { id: orgId }, data: { plan: 'BUSINESS' } });
  const owner = await login('owner@downgraded-review.local');
  await api('POST', '/api/v1/qrcodes', { bearer: owner }, { label: 'Kiosk', destinationUrl: 'https://www.example.com/kiosk' });
  await api('PUT', '/api/v1/policies', { bearer: owner }, {
    allowlistMode: 'ENFORCE',
    allowlist: [{ domain: 'example.com' }],
    destinationEditMinRole: 'MANAGER',
  });
  await db.organization.update({ where: { id: orgId }, data: { plan: 'PRO' } });
}

async function main(): Promise<void> {
  assertLocal();
  const parking = await db.organization.findFirstOrThrow({ where: { slug: 'municipality-thessaloniki' }, select: { id: true } });
  await seedReviewOrg(parking.id);
  await seedDowngradedOrg();
  const lockedOrg = await signup('owner@locked-review.local', 'Luca Locked', 'Locked Review Org');
  await db.organization.update({ where: { id: lockedOrg }, data: { plan: 'PRO' } });
  console.log('seed-policies-dev: Policy Review Co, Downgraded Review Org and Locked Review Org are ready.');
}

main()
  .catch((err) => {
    console.error(err);
    process.exitCode = 1;
  })
  .finally(async () => {
    await db.$disconnect();
    process.exit();
  });
