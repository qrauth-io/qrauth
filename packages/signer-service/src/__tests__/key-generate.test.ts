import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';
import { mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createPrivateKey, createPublicKey, createSign, createVerify, randomBytes, timingSafeEqual } from 'node:crypto';
import { slh_dsa_sha2_128s } from '@noble/post-quantum/slh-dsa.js';

/**
 * POST /v1/keys/generate: the signer generates and stores the key pair and
 * returns public material only. The route under test is the production
 * registrar (`registerKeyGenerateRoute`); the bearer hook mirrors server.ts.
 */

process.env.SIGNER_MASTER_KEY = randomBytes(32).toString('base64');
const TOKEN = 't'.repeat(40);

let app: FastifyInstance;
let keysDir: string;
let decryptAtRest: (envelope: string) => Buffer;

beforeAll(async () => {
  keysDir = mkdtempSync(join(tmpdir(), 'signer-keygen-'));
  ({ decryptAtRest } = await import('../key-at-rest.js'));
  const { registerKeyGenerateRoute } = await import('../key-generate.js');
  app = Fastify({ logger: false });
  app.addHook('onRequest', async (request, reply) => {
    const m = (request.headers.authorization ?? '').match(/^Bearer (.+)$/);
    const provided = Buffer.from(m?.[1] ?? '', 'utf8');
    const expected = Buffer.from(TOKEN, 'utf8');
    if (provided.length !== expected.length || !timingSafeEqual(provided, expected)) {
      return reply.status(401).send({ error: 'unauthorized' });
    }
  });
  registerKeyGenerateRoute(app, { keysDir });
  await app.ready();
});

afterAll(async () => {
  await app.close();
  rmSync(keysDir, { recursive: true, force: true });
});

const generate = (payload: unknown, token = TOKEN) =>
  app.inject({ method: 'POST', url: '/v1/keys/generate', headers: { authorization: `Bearer ${token}` }, payload: payload as object });

describe('POST /v1/keys/generate', () => {
  it('rejects a missing or wrong bearer token (401)', async () => {
    expect((await generate({ kind: 'rs256' }, 'x'.repeat(40))).statusCode).toBe(401);
    const none = await app.inject({ method: 'POST', url: '/v1/keys/generate', payload: { kind: 'rs256' } });
    expect(none.statusCode).toBe(401);
  });

  it.each([[{}], [{ kind: 'ed25519' }], [{ kind: 'rs256', extra: 1 }], [['rs256']], [{ kind: 1 }]])(
    'rejects a malformed body %j (400) and writes nothing',
    async (body) => {
      const before = readdirSync(keysDir).length;
      expect((await generate(body)).statusCode).toBe(400);
      expect(readdirSync(keysDir).length).toBe(before);
    },
  );

  it('es256-slhdsa: stores both envelopes (0600) and returns only public keys that match them', async () => {
    const res = await generate({ kind: 'es256-slhdsa' });
    expect(res.statusCode).toBe(201);
    const body = res.json();
    expect(Object.keys(body).sort()).toEqual(['keyId', 'kind', 'publicKey', 'slhdsaPublicKey']);
    expect(body.keyId).toMatch(/^[0-9a-f-]{36}$/);
    expect(JSON.stringify(body)).not.toContain('PRIVATE KEY');

    for (const ext of ['ecdsa.enc', 'slhdsa.enc']) {
      const path = join(keysDir, `${body.keyId}.${ext}`);
      expect(statSync(path).mode & 0o777).toBe(0o600);
      expect(readFileSync(path, 'utf8').startsWith('qrauth-kek-v1\0')).toBe(true);
    }

    const pem = decryptAtRest(readFileSync(join(keysDir, `${body.keyId}.ecdsa.enc`), 'utf8')).toString('utf8');
    const derived = createPublicKey(createPrivateKey(pem)).export({ type: 'spki', format: 'pem' });
    expect(derived).toBe(body.publicKey);
    const sig = createSign('SHA256').update('probe').sign(pem);
    expect(createVerify('SHA256').update('probe').verify(body.publicKey, sig)).toBe(true);

    const sk = decryptAtRest(readFileSync(join(keysDir, `${body.keyId}.slhdsa.enc`), 'utf8'));
    expect(sk.length).toBe(64);
    const pk = Buffer.from(body.slhdsaPublicKey, 'base64');
    expect(sk.subarray(32).equals(pk)).toBe(true);
    const msg = Buffer.from('probe');
    expect(slh_dsa_sha2_128s.verify(slh_dsa_sha2_128s.sign(msg, sk), msg, pk)).toBe(true);
  });

  it('rs256: stores one envelope and returns an RSA-2048 public key that matches it', async () => {
    const res = await generate({ kind: 'rs256' });
    expect(res.statusCode).toBe(201);
    const body = res.json();
    expect(Object.keys(body).sort()).toEqual(['keyId', 'kind', 'publicKey']);
    const files = readdirSync(keysDir).filter((n) => n.startsWith(body.keyId));
    expect(files).toEqual([`${body.keyId}.rsa.enc`]);
    const pem = decryptAtRest(readFileSync(join(keysDir, files[0]), 'utf8')).toString('utf8');
    const key = createPrivateKey(pem);
    expect(key.asymmetricKeyType).toBe('rsa');
    expect(key.asymmetricKeyDetails?.modulusLength).toBe(2048);
    expect(createPublicKey(key).export({ type: 'spki', format: 'pem' })).toBe(body.publicKey);
  });

  it('leaves no temporary files behind', () => {
    expect(readdirSync(keysDir).filter((n) => n.includes('.tmp.'))).toEqual([]);
  });
});
