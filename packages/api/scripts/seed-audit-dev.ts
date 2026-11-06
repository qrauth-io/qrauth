/**
 * Dev seed for the audit log (ADR-0008), for review on a local dev server.
 *
 * Drives the running API (API_URL, default http://127.0.0.1:3000) so every
 * entry is written by the real routes; Prisma is used only for setup the
 * API cannot do (email verification, plan, temporary memberships, an aged
 * signing key). Creates:
 *
 *   Audit Review Co (BUSINESS): owner@, admin@, member@audit-review.local
 *     - invitations accepted, an API key, QR codes created by the key,
 *       destination and label edits, a revoke, tags, a folder, bulk tag and
 *       move, a logo uploaded with the API key and deleted by the owner, a member role
 *       change, a QRAuth staff action (KYC approval), and a scheduled
 *       signing-key rotation (system job).
 *   Pro Review Org (PRO): owner@pro-review.local, to see the locked page.
 *
 * Password for every account: password123. Staff account:
 * staff@qrauth.local (needs ADMIN_EMAILS=staff@qrauth.local in the API env).
 *
 * Local databases only. Re-running needs a fresh database.
 *
 *   npm run db:seed:audit -w packages/api   (with the API dev server running)
 */
import { PrismaClient } from '@prisma/client';
import sharp from 'sharp';

import { hashPassword } from '../src/lib/password.js';
import { SigningService } from '../src/services/signing.js';
import { rotateStaleSigningKeys } from '../src/workers/signing-key-rotation.js';

const API = process.env.API_URL ?? 'http://127.0.0.1:3000';
const PASSWORD = 'password123';
const STAFF_EMAIL = 'staff@qrauth.local';
const DAY_MS = 24 * 60 * 60 * 1000;

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
    throw new Error('seed-audit-dev: refusing to run against a non-local database');
  }
}

type Auth = { bearer?: string; apiKey?: string };

async function api<T = Record<string, unknown>>(
  method: string,
  path: string,
  auth: Auth,
  body?: unknown,
  raw?: { buffer: Buffer; type: string },
): Promise<T> {
  const headers: Record<string, string> = { 'user-agent': 'qrauth-audit-seed/1.0' };
  if (auth.bearer) headers.authorization = `Bearer ${auth.bearer}`;
  if (auth.apiKey) headers['x-api-key'] = auth.apiKey;
  if (body !== undefined) headers['content-type'] = 'application/json';
  if (raw) headers['content-type'] = raw.type;
  const res = await fetch(`${API}${path}`, {
    method,
    headers,
    body: raw ? new Uint8Array(raw.buffer) : body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`${method} ${path} → ${res.status}: ${text.slice(0, 300)}`);
  return (text ? JSON.parse(text) : {}) as T;
}

async function signup(email: string, name: string, organizationName: string): Promise<void> {
  await api('POST', '/api/v1/auth/signup', {}, { name, email, password: PASSWORD, organizationName });
  await db.user.update({ where: { email }, data: { emailVerified: true } });
}

async function login(email: string): Promise<string> {
  const res = await api<{ token?: string; accessToken?: string }>('POST', '/api/v1/auth/login', {}, { email, password: PASSWORD });
  const token = res.token ?? res.accessToken;
  if (!token) throw new Error(`login ${email}: no token in response`);
  return token;
}

async function orgOf(email: string): Promise<string> {
  const m = await db.membership.findFirstOrThrow({ where: { user: { email } }, select: { organizationId: true } });
  return m.organizationId;
}

/** A user with no organization yet: verified, with a temporary membership so they can sign in to accept. */
async function invitee(email: string, name: string, parkingOrgId: string): Promise<string> {
  const user = await db.user.create({ data: { email, name, passwordHash: await hashPassword(PASSWORD), emailVerified: true } });
  await db.membership.create({ data: { userId: user.id, organizationId: parkingOrgId, role: 'VIEWER' } });
  return user.id;
}

async function inviteAndAccept(owner: string, orgId: string, email: string, role: string, parkingOrgId: string): Promise<void> {
  await api('POST', `/api/v1/organizations/${orgId}/invitations`, { bearer: owner }, { email, role });
  const { token } = await db.invitation.findFirstOrThrow({ where: { email, organizationId: orgId }, select: { token: true } });
  await api('POST', `/api/v1/organizations/invitations/${token}/accept`, { bearer: await login(email) }, {});
  await db.membership.deleteMany({ where: { user: { email }, organizationId: parkingOrgId } });
}

async function logoPng(): Promise<Buffer> {
  return sharp({ create: { width: 256, height: 256, channels: 4, background: { r: 20, g: 90, b: 200, alpha: 1 } } }).png().toBuffer();
}

async function seedBusinessOrg(): Promise<void> {
  const parking = (await db.organization.findFirstOrThrow({ where: { slug: 'municipality-thessaloniki' } })).id;

  await signup('owner@audit-review.local', 'Olga Owner', 'Audit Review Co');
  const orgId = await orgOf('owner@audit-review.local');
  await db.organization.update({ where: { id: orgId }, data: { plan: 'BUSINESS' } });
  const owner = await login('owner@audit-review.local');

  await invitee('admin@audit-review.local', 'Adam Admin', parking);
  await invitee('member@audit-review.local', 'Mia Member', parking);
  await inviteAndAccept(owner, orgId, 'admin@audit-review.local', 'ADMIN', parking);
  await inviteAndAccept(owner, orgId, 'member@audit-review.local', 'VIEWER', parking);
  const memberId = (await db.user.findUniqueOrThrow({ where: { email: 'member@audit-review.local' } })).id;
  await api('PATCH', `/api/v1/organizations/${orgId}/members/${memberId}`, { bearer: owner }, { role: 'MEMBER' });

  const key = await api<{ key?: string; rawKey?: string; apiKey?: string }>(
    'POST', `/api/v1/organizations/${orgId}/api-keys`, { bearer: owner }, { label: 'Print shop integration' },
  );
  const apiKey = key.key ?? key.rawKey ?? key.apiKey;
  if (!apiKey) throw new Error(`API key response had no key: ${Object.keys(key).join(', ')}`);

  // QR codes created with the API key; edited and organised by people.
  const created: string[] = [];
  for (const [label, url] of [['Menu', 'https://example.com/menu'], ['Poster spring', 'https://example.com/spring'], ['Old flyer', 'https://example.com/flyer']]) {
    const qr = await api<{ token: string }>('POST', '/api/v1/qrcodes', { apiKey }, { destinationUrl: url, label });
    created.push(qr.token);
  }
  const [menu, poster, flyer] = created;
  await api('PATCH', `/api/v1/qrcodes/${menu}`, { bearer: owner }, { destinationUrl: 'https://example.com/menu-autumn' });
  await api('PATCH', `/api/v1/qrcodes/${poster}`, { bearer: await login('admin@audit-review.local') }, { label: 'Poster spring (A2)' });
  await api('DELETE', `/api/v1/qrcodes/${flyer}`, { bearer: owner });

  const tag = await api<{ id: string }>('POST', '/api/v1/tags', { bearer: owner }, { name: 'Print', color: 'blue' });
  await api('PATCH', `/api/v1/tags/${tag.id}`, { bearer: owner }, { color: 'teal' });
  const folder = await api<{ id: string }>('POST', '/api/v1/folders', { apiKey }, { name: 'Campaigns' });
  await api('POST', '/api/v1/qrcodes/bulk-tag', { bearer: owner }, { tokens: [menu, poster], add: [tag.id] });
  await api('POST', '/api/v1/qrcodes/bulk-move', { apiKey }, { tokens: [menu, poster], folderId: folder.id });

  // QRAuth staff: KYC approval makes the issuer verified, which customer logos need.
  const staff = await login(STAFF_EMAIL);
  await api('POST', `/api/v1/admin/kyc-reviews/${orgId}/approve`, { bearer: staff }, { note: 'Documents checked' });

  const logo = await api<{ id: string }>('POST', '/api/v1/assets/logos?name=Brand%20mark', { apiKey }, undefined, { buffer: await logoPng(), type: 'image/png' });
  await api('DELETE', `/api/v1/assets/logos/${logo.id}`, { bearer: owner });

  // System job: the scheduled signing-key rotation, run on an aged key of this org only.
  await db.signingKey.updateMany({ where: { organizationId: orgId, status: 'ACTIVE' }, data: { createdAt: new Date(Date.now() - 120 * DAY_MS) } });
  await rotateStaleSigningKeys(db, new SigningService(db));
}

async function seedStaff(): Promise<void> {
  const staff = await db.user.create({
    data: { email: STAFF_EMAIL, name: 'QRAuth Staff', passwordHash: await hashPassword(PASSWORD), emailVerified: true },
  });
  const parking = await db.organization.findFirstOrThrow({ where: { slug: 'municipality-thessaloniki' } });
  await db.membership.create({ data: { userId: staff.id, organizationId: parking.id, role: 'VIEWER' } });
}

async function main(): Promise<void> {
  assertLocal();
  await seedStaff();
  await seedBusinessOrg();
  await signup('owner@pro-review.local', 'Paul Pro', 'Pro Review Org');
  await db.organization.update({ where: { id: await orgOf('owner@pro-review.local') }, data: { plan: 'PRO' } });
  const organizationId = await orgOf('owner@audit-review.local');
  const count = await db.auditLog.count({ where: { organizationId } });
  const revisions = await db.qRCodeRevision.count({ where: { organizationId } });
  console.log(`seed-audit-dev: Audit Review Co has ${count} audit entries and ${revisions} QR revisions.`);
}

main()
  .catch((err) => {
    console.error(err);
    process.exitCode = 1;
  })
  .finally(async () => {
    await db.$disconnect();
    // Imported services open queue connections that keep Node alive.
    process.exit();
  });
