import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from 'fastify';
import sharp from 'sharp';

import { fakeLogoDb } from '../../services/__tests__/fake-logo-db.js';

/**
 * /api/v1/assets/logos (ADR-0005 D6, D9): roles, verified email, the paid
 * plan gate, the raw-body parser on the upload route only, the 1 MiB body
 * limit, sanitisation errors, the per-organization cap, organization scoping
 * (404 for another organization's id), the private one-day cache header, and
 * delete refused while a code draws the logo.
 */

process.env.DATABASE_URL ??= 'postgresql://test:test@localhost:5432/test';
process.env.REDIS_URL ??= 'redis://localhost:6379';
process.env.JWT_SECRET ??= 'a'.repeat(32);
process.env.ANIMATED_QR_SECRET ??= 'a'.repeat(64);

const { LOGO_CACHE_CONTROL } = await import('../assets.js');
const { LOGO_MAX_PER_ORG } = await import('../../services/logo-library.js');

let fake = fakeLogoDb();
let role = 'OWNER';
let orgId = 'org_1';
let plan = 'PRO';
let domainVerified = true;
let kycStatus = 'PENDING';
let emailVerified = true;

const prisma = {
  get contentAsset() { return fake.db.contentAsset; },
  get contentAssetBlob() { return fake.db.contentAssetBlob; },
  get qRCode() { return fake.db.qRCode; },
  $transaction: (...args: Parameters<typeof fake.db.$transaction>) => fake.db.$transaction(...args),
  organization: { findUnique: async () => ({ plan, domainVerified, kycStatus }) },
  user: { findUnique: async () => ({ emailVerified }) },
  // An API key's organization has a verified owner.
  membership: { findFirst: async () => (actorId === 'api-key' ? { id: 'm1' } : null) },
};

let actorId = 'user_1';
let app: FastifyInstance;
const parsedBodies: string[] = [];
const AUTH = { authorization: 'Bearer test' };

beforeAll(async () => {
  app = Fastify();
  app.decorate('prisma', prisma as never);
  app.decorateRequest('user', null);
  // As middleware/auth.ts: 401 without credentials, which reads only headers.
  app.decorate('authenticate', async (request: FastifyRequest, reply: FastifyReply) => {
    if (request.headers.authorization !== 'Bearer test') {
      return reply.status(401).send({ statusCode: 401, error: 'Unauthorized', message: 'Missing or invalid authentication' });
    }
    (request as unknown as { user: unknown }).user = { id: actorId, orgId, role, email: 'o@example.com' };
  });
  // Records whether a request's body reached the route's content-type parser.
  app.addHook('preValidation', async (request) => {
    if (request.url.startsWith('/api/v1/assets/logos')) parsedBodies.push(request.url);
  });
  const { default: assetRoutes } = await import('../assets.js');
  await app.register(assetRoutes, { prefix: '/api/v1/assets' });
  // A sibling JSON route, to show the image parser is not registered beyond the upload route.
  app.post('/echo', async (request) => ({ isBuffer: Buffer.isBuffer(request.body) }));
  await app.ready();
});

afterAll(async () => {
  await app.close();
});

beforeEach(() => {
  fake = fakeLogoDb();
  role = 'OWNER';
  orgId = 'org_1';
  plan = 'PRO';
  domainVerified = true;
  kycStatus = 'PENDING';
  emailVerified = true;
  actorId = 'user_1';
});

const png = (w = 128, h = 128) =>
  sharp({ create: { width: w, height: h, channels: 4, background: '#1B5E20' } }).png().toBuffer();

const upload = (body: Buffer | string, contentType = 'image/png', query = '') =>
  app.inject({ method: 'POST', url: `/api/v1/assets/logos${query}`, headers: { ...AUTH, 'content-type': contentType }, payload: body });

const get = (url: string) => app.inject({ method: 'GET', url: `/api/v1/assets${url}`, headers: AUTH });
const del = (url: string) => app.inject({ method: 'DELETE', url: `/api/v1/assets${url}`, headers: AUTH });

describe('POST /logos', () => {
  it('stores the normalised PNG and answers 201 with the logo', async () => {
    const res = await upload(await png(1024, 512), 'image/png', '?name=Brand%20mark.png');
    expect(res.statusCode).toBe(201);
    expect(res.json()).toMatchObject({ id: 'asset_1', name: 'Brand mark.png', width: 512, height: 256 });
    expect(fake.assets[0]).toMatchObject({ organizationId: 'org_1', kind: 'LOGO', mimeType: 'image/png' });
    // Only the normalised PNG is kept, not the upload.
    const stored = fake.blobs.get('asset_1')!;
    expect((await sharp(stored).metadata()).width).toBe(512);
  });

  it.each(['image/jpeg', 'image/webp'])('accepts %s', async (type) => {
    const body = type === 'image/jpeg' ? await sharp(await png()).jpeg().toBuffer() : await sharp(await png()).webp().toBuffer();
    expect((await upload(body, type)).statusCode).toBe(201);
  });

  it('trusts the magic bytes, not the declared type', async () => {
    const jpeg = await sharp(await png()).jpeg().toBuffer();
    expect((await upload(jpeg, 'image/png')).statusCode).toBe(201);
    const res = await upload(Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"/>'), 'image/png');
    expect(res.statusCode).toBe(415);
    expect(res.json()).toMatchObject({ code: 'svg-not-accepted' });
  });

  it.each([
    ['image/svg+xml', '<svg xmlns="http://www.w3.org/2000/svg"/>'],
    ['image/gif', 'GIF89a'],
    ['application/octet-stream', 'x'],
  ])('refuses the content type %s with 415', async (type, body) => {
    expect((await upload(body, type)).statusCode).toBe(415);
    expect(fake.assets).toHaveLength(0);
  });

  it('refuses a JSON body with 415', async () => {
    const res = await upload(JSON.stringify({ png: 'x' }), 'application/json');
    expect(res.statusCode).toBe(415);
    expect(res.json()).toMatchObject({ code: 'unsupported-type' });
  });

  it('an anonymous upload is 401 before the body is read, even over 1 MiB (not 413)', async () => {
    parsedBodies.length = 0;
    const res = await app.inject({
      method: 'POST',
      url: '/api/v1/assets/logos',
      headers: { 'content-type': 'image/png' },
      payload: Buffer.alloc(2 * 1024 * 1024),
    });
    expect(res.statusCode).toBe(401);
    expect(parsedBodies).toEqual([]);
    expect(fake.assets).toHaveLength(0);
  });

  it('refuses a body over 1 MiB with 413', async () => {
    const res = await upload(Buffer.concat([await png(), Buffer.alloc(1024 * 1024)]));
    expect(res.statusCode).toBe(413);
    expect(fake.assets).toHaveLength(0);
  });

  it('refuses an image smaller than 64 px with 422 and the rule code', async () => {
    const res = await upload(await png(32, 32));
    expect(res.statusCode).toBe(422);
    expect(res.json()).toMatchObject({ statusCode: 422, code: 'dimensions' });
  });

  it.each(['MANAGER', 'MEMBER', 'ADMIN'])('%s may upload', async (r) => {
    role = r;
    expect((await upload(await png())).statusCode).toBe(201);
  });

  it('VIEWER may not upload', async () => {
    role = 'VIEWER';
    expect((await upload(await png())).statusCode).toBe(403);
  });

  it('needs a verified email', async () => {
    emailVerified = false;
    const res = await upload(await png());
    expect(res.statusCode).toBe(403);
    expect(res.json()).toMatchObject({ error: 'EmailNotVerified' });
    expect(fake.assets).toHaveLength(0);
  });

  it('is refused on FREE with the content-type gate’s body shape', async () => {
    plan = 'FREE';
    const res = await upload(await png());
    expect(res.statusCode).toBe(403);
    expect(res.json()).toEqual({
      statusCode: 403,
      error: 'Forbidden',
      message: 'Customer logos are not included in the Free plan. Upgrade at https://qrauth.io/dashboard/pricing.',
    });
    expect(fake.assets).toHaveLength(0);
  });

  it('FREE with a verified domain is still refused with the plan 403', async () => {
    plan = 'FREE';
    domainVerified = true;
    const res = await upload(await png());
    expect(res.statusCode).toBe(403);
    expect(res.json().code).toBeUndefined();
    expect(res.json().message).toMatch(/not included in the Free plan/);
  });

  it.each(['PENDING', 'UNDER_REVIEW', 'REJECTED'])(
    'a paid plan without a verified domain and with KYC %s is 403 logo-verification-required',
    async (status) => {
      domainVerified = false;
      kycStatus = status;
      const res = await upload(await png());
      expect(res.statusCode).toBe(403);
      expect(res.json()).toEqual({
        statusCode: 403,
        error: 'Forbidden',
        code: 'logo-verification-required',
        message: 'Custom logos require a verified domain or completed verification',
      });
      expect(fake.assets).toHaveLength(0);
    },
  );

  it('a paid plan with a completed KYC review (no verified domain) may upload', async () => {
    domainVerified = false;
    kycStatus = 'VERIFIED';
    expect((await upload(await png())).statusCode).toBe(201);
  });

  it.each(['PRO', 'BUSINESS', 'ENTERPRISE'])('%s may upload', async (p) => {
    plan = p;
    expect((await upload(await png())).statusCode).toBe(201);
  });

  it(`answers 409 once the organization has ${LOGO_MAX_PER_ORG} logos`, async () => {
    const body = await png();
    for (let i = 0; i < LOGO_MAX_PER_ORG; i++) expect((await upload(body)).statusCode).toBe(201);
    const res = await upload(body);
    expect(res.statusCode).toBe(409);
    expect(res.json().message).toMatch(/up to 50 logos/);
  });

  it('registers the raw image parser on the upload route only', async () => {
    const res = await app.inject({ method: 'POST', url: '/echo', headers: { 'content-type': 'image/png' }, payload: await png() });
    expect(res.statusCode).toBe(415);
  });
});

describe('audit log', () => {
  it('an upload writes logo.upload with the actor, organization, asset and size', async () => {
    const res = await upload(await png());
    expect(res.statusCode).toBe(201);
    expect(fake.audits).toEqual([
      {
        organizationId: 'org_1',
        userId: 'user_1',
        action: 'logo.upload',
        resource: 'ContentAsset',
        resourceId: 'asset_1',
        metadata: { kind: 'LOGO', sizeBytes: res.json().sizeBytes },
        ipAddress: '127.0.0.1',
      },
    ]);
  });

  it('a delete writes logo.delete with the size of the deleted logo', async () => {
    const { sizeBytes } = (await upload(await png())).json();
    fake.audits.length = 0;
    expect((await del('/logos/asset_1')).statusCode).toBe(204);
    expect(fake.audits).toEqual([
      expect.objectContaining({ userId: 'user_1', organizationId: 'org_1', action: 'logo.delete', resourceId: 'asset_1', metadata: { kind: 'LOGO', sizeBytes } }),
    ]);
  });

  it('a refused upload or delete writes nothing', async () => {
    expect((await upload(await png(32, 32))).statusCode).toBe(422);
    expect((await upload(await png())).statusCode).toBe(201);
    fake.audits.length = 0;
    fake.state.references = 1;
    expect((await del('/logos/asset_1')).statusCode).toBe(409);
    expect((await del('/logos/asset_404')).statusCode).toBe(404);
    expect(fake.audits).toEqual([]);
  });

  it('a change made with an API key writes no audit row (AuditLog names a user)', async () => {
    actorId = 'api-key';
    expect((await upload(await png())).statusCode).toBe(201);
    expect((await del('/logos/asset_1')).statusCode).toBe(204);
    expect(fake.audits).toEqual([]);
  });
});

describe('GET /logos and /logos/:id', () => {
  beforeEach(async () => {
    expect((await upload(await png(), 'image/png', '?name=mine')).statusCode).toBe(201);
  });

  it.each(['OWNER', 'ADMIN', 'MANAGER', 'MEMBER', 'VIEWER'])('%s may list and read', async (r) => {
    role = r;
    expect((await get('/logos')).json()).toEqual({ data: [expect.objectContaining({ id: 'asset_1', name: 'mine' })] });
    expect((await get('/logos/asset_1')).statusCode).toBe(200);
  });

  it('serves the stored PNG with a private one-day cache header', async () => {
    const res = await get('/logos/asset_1');
    expect(res.headers['content-type']).toBe('image/png');
    expect(res.headers['cache-control']).toBe(LOGO_CACHE_CONTROL);
    expect(LOGO_CACHE_CONTROL).toBe('private, max-age=86400');
    expect(Buffer.compare(res.rawPayload, fake.blobs.get('asset_1')!)).toBe(0);
  });

  it('answers 404 for another organization’s logo, exactly as for a missing id', async () => {
    orgId = 'org_2';
    const other = await get('/logos/asset_1');
    const missing = await get('/logos/asset_404');
    expect(other.statusCode).toBe(404);
    expect(other.json()).toEqual({ ...missing.json(), message: expect.stringContaining('asset_1') });
    expect((await get('/logos')).json()).toEqual({ data: [] });
  });

  it('lists and serves logos on FREE, so a downgraded organization keeps its codes', async () => {
    plan = 'FREE';
    expect((await get('/logos')).json().data).toHaveLength(1);
    expect((await get('/logos/asset_1')).statusCode).toBe(200);
  });

  it('lists and serves logos after a loss of verification', async () => {
    domainVerified = false;
    expect((await get('/logos')).json().data).toHaveLength(1);
    expect((await get('/logos/asset_1')).statusCode).toBe(200);
  });
});

describe('DELETE /logos/:id', () => {
  beforeEach(async () => {
    expect((await upload(await png())).statusCode).toBe(201);
  });

  it('deletes an unused logo with 204', async () => {
    expect((await del('/logos/asset_1')).statusCode).toBe(204);
    expect(fake.assets).toHaveLength(0);
    expect((await get('/logos/asset_1')).statusCode).toBe(404);
  });

  it('answers 409 with the count while codes draw the logo, and keeps it', async () => {
    fake.state.references = 2;
    const res = await del('/logos/asset_1');
    expect(res.statusCode).toBe(409);
    expect(res.json()).toMatchObject({ statusCode: 409, count: 2, message: expect.stringMatching(/2 QR codes use this logo/) });
    expect(fake.assets).toHaveLength(1);
  });

  it('names a single code in the singular', async () => {
    fake.state.references = 1;
    expect((await del('/logos/asset_1')).json().message).toMatch(/^1 QR code uses this logo\. Choose another logo for it/);
  });

  it.each(['OWNER', 'ADMIN', 'MANAGER'])('%s may delete', async (r) => {
    role = r;
    expect((await del('/logos/asset_1')).statusCode).toBe(204);
  });

  it.each(['MEMBER', 'VIEWER'])('%s may not delete', async (r) => {
    role = r;
    expect((await del('/logos/asset_1')).statusCode).toBe(403);
    expect(fake.assets).toHaveLength(1);
  });

  it.each([
    ['downgraded to FREE', () => { plan = 'FREE'; }],
    ['no longer verified', () => { domainVerified = false; }],
  ])('a logo can still be deleted when %s', async (_label, change) => {
    change();
    expect((await del('/logos/asset_1')).statusCode).toBe(204);
  });

  it('answers 404 for another organization’s logo and deletes nothing', async () => {
    orgId = 'org_2';
    expect((await del('/logos/asset_1')).statusCode).toBe(404);
    expect(fake.assets).toHaveLength(1);
  });
});
