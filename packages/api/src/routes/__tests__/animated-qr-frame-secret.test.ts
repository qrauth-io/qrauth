import { describe, it, expect, beforeAll, afterAll, beforeEach, vi } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';
import { createHash, createHmac, randomBytes } from 'node:crypto';

/**
 * Living Codes frame secret: possession proof and rotation.
 *
 * Public (client ID only) callers register frameChallenge = base64url(SHA-256(frameVerifier))
 * when the auth session is created (POST /auth-sessions) and receive the frame secret only
 * from POST /session/secret with the verifier in the body. POST /session never registers a
 * challenge for a public client. Confidential callers authenticate with the client secret. Every
 * issuance starts a new secret generation; frames signed under an earlier one fail.
 */

process.env.DATABASE_URL ??= 'postgresql://test:test@localhost:5432/test';
process.env.REDIS_URL ??= 'redis://localhost:6379';
process.env.JWT_SECRET ??= 'a'.repeat(32);
process.env.ANIMATED_QR_SECRET ??= 'b'.repeat(64);
process.env.WEBAUTHN_ORIGIN = 'https://qrauth.test';

const store = new Map<string, string>();
vi.mock('../../lib/cache.js', () => ({
  redis: {},
  cacheGet: async (k: string) => (store.has(k) ? JSON.parse(store.get(k)!) : null),
  cacheSet: async (k: string, v: unknown) => {
    store.set(k, JSON.stringify(v));
  },
  cacheSetIfAbsent: async (k: string, v: unknown) => {
    if (store.has(k)) return false;
    store.set(k, JSON.stringify(v));
    return true;
  },
  cacheIncr: async (k: string) => {
    const n = (store.has(k) ? Number(store.get(k)) : 0) + 1;
    store.set(k, String(n));
    return n;
  },
  cacheDel: async (k: string) => {
    store.delete(k);
  },
  cacheTake: async () => null,
}));

const APP = { id: 'app_1', organizationId: 'org_1', allowedScopes: [] as string[] };
const OTHER_APP = { id: 'app_2', organizationId: 'org_2', allowedScopes: [] as string[] };
vi.mock('../../services/app.js', () => ({
  AppService: class {
    async findByClientId(clientId: string) {
      if (clientId === 'pub_client') return APP;
      if (clientId === 'other_client') return OTHER_APP;
      return null;
    }
    async authenticateApp(clientId: string, secret: string) {
      return clientId === 'conf_client' && secret === 'right-secret' ? APP : null;
    }
  },
}));

const SESSION = {
  id: 'cmauthsession0001',
  token: 'TokAbc123',
  appId: 'app_1',
  expiresAt: new Date(Date.now() + 5 * 60_000),
};

let app: FastifyInstance;

beforeAll(async () => {
  app = Fastify({ logger: false });
  app.decorate('prisma', {
    authSession: {
      findUnique: async ({ where }: { where: { id?: string; token?: string } }) =>
        where.id === SESSION.id || where.token === SESSION.token ? SESSION : null,
    },
  } as never);
  app.decorate('macSigner', undefined as never);
  app.decorate('macSignerStatsCollector', undefined as never);
  app.decorate('macSignerBackend', 'local' as never);
  const { default: routes } = await import('../animated-qr.js');
  await app.register(routes, { prefix: '/api/v1/animated-qr' });
  await app.ready();
});

afterAll(async () => {
  await app?.close();
});

beforeEach(() => store.clear());

const PUBLIC = { 'x-client-id': 'pub_client' };
const CONFIDENTIAL = { 'x-client-id': 'conf_client', 'x-client-secret': 'right-secret' };

function newVerifier(): { verifier: string; challenge: string } {
  const verifier = randomBytes(32).toString('base64url');
  return { verifier, challenge: createHash('sha256').update(verifier, 'ascii').digest('base64url') };
}

function post(url: string, headers: Record<string, string>, payload: unknown) {
  return app.inject({ method: 'POST', url: `/api/v1/animated-qr${url}`, headers, payload: payload as object });
}

function frame(secretHex: string, baseUrl: string, frameIndex: number, timestamp = Date.now()) {
  const hmac = createHmac('sha256', Buffer.from(secretHex, 'hex'))
    .update(`${baseUrl}:${timestamp}:${frameIndex}`)
    .digest('hex')
    .slice(0, 16);
  return { baseUrl, frameIndex, timestamp, hmac };
}

async function validate(f: ReturnType<typeof frame>) {
  const res = await post('/validate', {}, f);
  return res.json() as { valid: boolean; reason?: string };
}

/** What POST /auth-sessions does when the create body carries frameChallenge. */
async function registerAtCreation(challenge: string) {
  const { registerFrameChallenge } = await import('../../services/animated-qr-frame-proof.js');
  return registerFrameChallenge(SESSION.id, challenge, 300);
}

async function publicSecret(verifier: string) {
  return post('/session/secret', PUBLIC, { token: SESSION.token, frameVerifier: verifier });
}

describe('POST /session — public client', () => {
  it('client ID + token only -> 401, and no secret in the response', async () => {
    const res = await post('/session', PUBLIC, { token: SESSION.token });
    expect(res.statusCode).toBe(401);
    expect(res.body).not.toContain('frameSecret');
  });

  it('client ID + token only on /session/secret -> 401', async () => {
    const res = await post('/session/secret', PUBLIC, { token: SESSION.token });
    expect(res.statusCode).toBe(401);
    expect(res.body).not.toContain('frameSecret');
  });

  it('with the challenge registered at creation, returns no secret (201)', async () => {
    const { challenge } = newVerifier();
    await registerAtCreation(challenge);
    const res = await post('/session', PUBLIC, { token: SESSION.token });
    expect(res.statusCode).toBe(201);
    expect(res.json().frameSecret).toBeUndefined();
    expect(res.json().baseUrl).toContain(SESSION.token);
  });

  it('accepts the registered challenge echoed in the body (201)', async () => {
    const { challenge } = newVerifier();
    await registerAtCreation(challenge);
    const res = await post('/session', PUBLIC, { token: SESSION.token, frameChallenge: challenge });
    expect(res.statusCode).toBe(201);
  });

  it('never registers a challenge for a public client after creation (401), and the token alone cannot reach the secret', async () => {
    const late = newVerifier();
    const res = await post('/session', PUBLIC, { token: SESSION.token, frameChallenge: late.challenge });
    expect(res.statusCode).toBe(401);
    const secret = await publicSecret(late.verifier);
    expect(secret.statusCode).toBe(401);
    expect(secret.json().frameSecret).toBeUndefined();
  });

  it('a different challenge does not displace the registered one (401), and the original verifier still works', async () => {
    const original = newVerifier();
    await registerAtCreation(original.challenge);
    const other = newVerifier();
    expect((await post('/session', PUBLIC, { token: SESSION.token, frameChallenge: other.challenge })).statusCode).toBe(401);
    expect((await publicSecret(other.verifier)).statusCode).toBe(401);
    expect((await publicSecret(original.verifier)).statusCode).toBe(200);
  });

  it('rejects a malformed challenge (400)', async () => {
    const res = await post('/session', PUBLIC, { token: SESSION.token, frameChallenge: 'short' });
    expect(res.statusCode).toBe(400);
  });

  it("another app's client gets the same 401 as an unknown token", async () => {
    await registerAtCreation(newVerifier().challenge);
    const other = await post('/session', { 'x-client-id': 'other_client' }, { token: SESSION.token });
    const unknown = await post('/session', PUBLIC, { token: 'NoSuchTok1' });
    expect(other.statusCode).toBe(401);
    expect(unknown.statusCode).toBe(401);
    expect(other.json().message).toBe(unknown.json().message);
  });
});

describe('POST /session/secret — frame verifier', () => {
  it('correct frame_verifier -> 200 with a frame secret that verifies', async () => {
    const { verifier, challenge } = newVerifier();
    await registerAtCreation(challenge);
    const res = await publicSecret(verifier);
    expect(res.statusCode).toBe(200);
    const { frameSecret, baseUrl } = res.json();
    expect(frameSecret).toMatch(/^[0-9a-f]{64}$/);
    expect(await validate(frame(frameSecret, baseUrl, 0))).toEqual({ valid: true });
  });

  it('wrong verifier -> 401', async () => {
    const { challenge } = newVerifier();
    await registerAtCreation(challenge);
    const res = await publicSecret(newVerifier().verifier);
    expect(res.statusCode).toBe(401);
    expect(res.body).not.toContain('frameSecret');
  });

  it('verifier in the query string is refused (400), even when correct', async () => {
    const { verifier, challenge } = newVerifier();
    await registerAtCreation(challenge);
    const res = await app.inject({
      method: 'POST',
      url: `/api/v1/animated-qr/session/secret?frameVerifier=${verifier}`,
      headers: PUBLIC,
      payload: { token: SESSION.token },
    });
    expect(res.statusCode).toBe(400);
    expect(res.body).not.toContain('frameSecret');
  });

  it('a session created without a challenge cannot use the verifier path (401)', async () => {
    await post('/session', CONFIDENTIAL, { token: SESSION.token });
    const res = await publicSecret(newVerifier().verifier);
    expect(res.statusCode).toBe(401);
  });

  it('after a refetch, frames signed with the old secret are rejected; the new secret verifies from frame 0', async () => {
    const { verifier, challenge } = newVerifier();
    await registerAtCreation(challenge);

    const first = (await publicSecret(verifier)).json();
    expect(await validate(frame(first.frameSecret, first.baseUrl, 0))).toEqual({ valid: true });
    expect(await validate(frame(first.frameSecret, first.baseUrl, 1))).toEqual({ valid: true });

    // Reload: the same browser fetches again with its verifier.
    const res = await publicSecret(verifier);
    expect(res.statusCode).toBe(200);
    const second = res.json();
    expect(second.frameSecret).not.toBe(first.frameSecret);

    const old = await validate(frame(first.frameSecret, first.baseUrl, 2));
    expect(old.valid).toBe(false);
    expect(old.reason).toBe('Invalid HMAC');

    // The new generation starts again at frame 0.
    expect(await validate(frame(second.frameSecret, second.baseUrl, 0))).toEqual({ valid: true });
  });
});

describe('POST /session/secret — public client limits', () => {
  it('unknown token or another app -> uniform 401', async () => {
    const { verifier, challenge } = newVerifier();
    await registerAtCreation(challenge);
    const unknown = await post('/session/secret', PUBLIC, { token: 'NoSuchTok1', frameVerifier: verifier });
    const other = await post('/session/secret', { 'x-client-id': 'other_client' }, { token: SESSION.token, frameVerifier: verifier });
    expect(unknown.statusCode).toBe(401);
    expect(other.statusCode).toBe(401);
    expect(other.json().message).toBe(unknown.json().message);
  });

  it('caps attempts per auth session (429 after the limit)', async () => {
    const { SECRET_ATTEMPTS_PER_MINUTE } = await import('../../services/animated-qr-frame-proof.js');
    await registerAtCreation(newVerifier().challenge);
    for (let i = 0; i < SECRET_ATTEMPTS_PER_MINUTE; i++) {
      expect((await publicSecret(newVerifier().verifier)).statusCode).toBe(401);
    }
    expect((await publicSecret(newVerifier().verifier)).statusCode).toBe(429);
  });
});

describe('confidential client', () => {
  it('wrong client secret -> 401', async () => {
    const res = await post('/session', { 'x-client-id': 'conf_client', 'x-client-secret': 'wrong' }, { token: SESSION.token });
    expect(res.statusCode).toBe(401);
    expect(res.body).not.toContain('frameSecret');
  });

  it('client secret -> 201 with a frame secret; refetch rotates it', async () => {
    const a = await post('/session', CONFIDENTIAL, { authSessionId: SESSION.id });
    expect(a.statusCode).toBe(201);
    const first = a.json();
    expect(await validate(frame(first.frameSecret, first.baseUrl, 0))).toEqual({ valid: true });

    const b = await post('/session/secret', CONFIDENTIAL, { authSessionId: SESSION.id });
    expect(b.statusCode).toBe(200);
    const second = b.json();
    expect((await validate(frame(first.frameSecret, first.baseUrl, 5))).valid).toBe(false);
    expect(await validate(frame(second.frameSecret, second.baseUrl, 0))).toEqual({ valid: true });
  });
});

describe('POST /validate — anti-replay unchanged within a generation', () => {
  it('rejects a repeated frame index', async () => {
    const { frameSecret, baseUrl } = (await post('/session', CONFIDENTIAL, { token: SESSION.token })).json();
    expect(await validate(frame(frameSecret, baseUrl, 3))).toEqual({ valid: true });
    expect(await validate(frame(frameSecret, baseUrl, 3))).toEqual({ valid: false, reason: 'Replayed frame index' });
  });

  it('rejects a frame older than 5 s', async () => {
    const { frameSecret, baseUrl } = (await post('/session', CONFIDENTIAL, { token: SESSION.token })).json();
    const res = await validate(frame(frameSecret, baseUrl, 0, Date.now() - 6000));
    expect(res.valid).toBe(false);
  });
});
