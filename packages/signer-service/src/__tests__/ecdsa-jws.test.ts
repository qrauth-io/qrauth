import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';
import {
  generateKeyPairSync,
  createVerify,
  createSign,
  timingSafeEqual,
} from 'node:crypto';
import { SignerKeyError } from '../key-cache.js';
import { SIGNER_ECDSA_CANONICAL_PREFIX } from '../domain-separation.js';
import { JWS_CANONICAL_INPUT_RE, signEcdsaJws } from '../ecdsa-jws.js';

/**
 * Tests for the prefix-free `/v1/sign-ecdsa-jws` endpoint (ADR-0003 Slice 3a).
 *
 * As with `mac-endpoints.test.ts`, we build a minimal Fastify app here
 * rather than importing `server.ts` (which has module-load side effects:
 * a `process.exit(1)` on missing env and a `listen()` IIFE). The app
 * mirrors the real wiring — the same H-5-style bearer `onRequest` hook
 * and the same handler logic, including the JWS-shape guard and the
 * `signEcdsaJws` primitive the production route calls.
 */
function buildJwsApp(opts: {
  expectedToken: string;
  keys: Record<string, string>; // keyId -> ECDSA private PEM
}): FastifyInstance {
  const expectedTokens = [Buffer.from(opts.expectedToken, 'utf8')];

  const app = Fastify({ logger: false });
  app.addHook('onRequest', async (request, reply) => {
    if (request.url === '/healthz') return;
    const header = request.headers.authorization ?? '';
    const match = header.match(/^Bearer (.+)$/);
    if (!match) return reply.status(401).send({ error: 'unauthorized' });
    const provided = Buffer.from(match[1], 'utf8');
    let ok = false;
    for (const expected of expectedTokens) {
      if (provided.length === expected.length && timingSafeEqual(provided, expected)) {
        ok = true;
        break;
      }
    }
    if (!ok) return reply.status(401).send({ error: 'unauthorized' });
  });

  app.post<{ Body: { keyId: string; canonicalInput: string } }>(
    '/v1/sign-ecdsa-jws',
    async (request, reply) => {
      const { keyId, canonicalInput } = request.body ?? ({} as never);
      if (typeof keyId !== 'string' || typeof canonicalInput !== 'string') {
        return reply.status(400).send({ error: 'malformed_request' });
      }
      if (!JWS_CANONICAL_INPUT_RE.test(canonicalInput)) {
        return reply.status(400).send({
          error: 'invalid_canonical_input',
          error_description: 'JWS canonical input must match base64url.base64url',
        });
      }
      let pem: string | undefined;
      try {
        pem = opts.keys[keyId];
        if (!pem) throw new SignerKeyError('key_not_found', 404);
      } catch (err) {
        if (err instanceof SignerKeyError) {
          return reply.status(err.status).send({ error: err.code });
        }
        return reply.status(500).send({ error: 'internal_error' });
      }
      const signature = signEcdsaJws(pem, canonicalInput);
      return { signature, kid: keyId, alg: 'ES256' };
    },
  );

  return app;
}

const TOKEN = 't'.repeat(40);
const KEY_ID = 'jws-key-1';

function makeKeyPair() {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return {
    pem: privateKey.export({ type: 'pkcs8', format: 'pem' }) as string,
    spki: publicKey.export({ type: 'spki', format: 'pem' }) as string,
  };
}

// A representative JWS canonical input: base64url(header).base64url(payload).
const VALID_INPUT = 'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYmMifQ';

describe('signEcdsaJws (primitive)', () => {
  it('produces a base64url raw R||S signature verifiable with ieee-p1363', () => {
    const { pem, spki } = makeKeyPair();
    const sig = signEcdsaJws(pem, VALID_INPUT);

    // 64-byte raw signature → 86 base64url chars, no padding/+//.
    expect(sig).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(Buffer.from(sig, 'base64url').length).toBe(64);

    const v = createVerify('SHA256');
    v.update(VALID_INPUT);
    v.end();
    const ok = v.verify(
      { key: spki, dsaEncoding: 'ieee-p1363' },
      Buffer.from(sig, 'base64url'),
    );
    expect(ok).toBe(true);
  });

  it('signs the bytes directly with no domain prefix', () => {
    const { pem, spki } = makeKeyPair();
    const sig = Buffer.from(signEcdsaJws(pem, VALID_INPUT), 'base64url');

    // Verifying against the PREFIXED input must fail — proving no prefix
    // was applied during signing.
    const v = createVerify('SHA256');
    v.update(SIGNER_ECDSA_CANONICAL_PREFIX + VALID_INPUT);
    v.end();
    expect(v.verify({ key: spki, dsaEncoding: 'ieee-p1363' }, sig)).toBe(false);
  });
});

describe('JWS_CANONICAL_INPUT_RE', () => {
  it('accepts base64url.base64url', () => {
    expect(JWS_CANONICAL_INPUT_RE.test(VALID_INPUT)).toBe(true);
  });
  it('rejects inputs containing the canonical domain prefix (has ":")', () => {
    expect(JWS_CANONICAL_INPUT_RE.test(`${SIGNER_ECDSA_CANONICAL_PREFIX}${VALID_INPUT}`)).toBe(false);
  });
  it('rejects single-segment, three-segment, and empty-segment inputs', () => {
    expect(JWS_CANONICAL_INPUT_RE.test('eyJhbGciOiJFUzI1NiJ9')).toBe(false);
    expect(JWS_CANONICAL_INPUT_RE.test('a.b.c')).toBe(false);
    expect(JWS_CANONICAL_INPUT_RE.test('a.')).toBe(false);
    expect(JWS_CANONICAL_INPUT_RE.test('.b')).toBe(false);
  });
});

describe('POST /v1/sign-ecdsa-jws', () => {
  let app: FastifyInstance;
  let spki: string;

  beforeEach(() => {
    const kp = makeKeyPair();
    spki = kp.spki;
    app = buildJwsApp({ expectedToken: TOKEN, keys: { [KEY_ID]: kp.pem } });
  });
  afterEach(async () => {
    await app.close();
  });

  it('rejects unauthenticated requests with 401', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/v1/sign-ecdsa-jws',
      payload: { keyId: KEY_ID, canonicalInput: VALID_INPUT },
    });
    expect(res.statusCode).toBe(401);
  });

  it('returns a JWS-verifiable signature on the happy path', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/v1/sign-ecdsa-jws',
      headers: { authorization: `Bearer ${TOKEN}` },
      payload: { keyId: KEY_ID, canonicalInput: VALID_INPUT },
    });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.kid).toBe(KEY_ID);
    expect(body.alg).toBe('ES256');
    expect(Buffer.from(body.signature, 'base64url').length).toBe(64);

    const v = createVerify('SHA256');
    v.update(VALID_INPUT);
    v.end();
    expect(
      v.verify({ key: spki, dsaEncoding: 'ieee-p1363' }, Buffer.from(body.signature, 'base64url')),
    ).toBe(true);
  });

  it('returns 400 invalid_canonical_input on a prefix-bearing input', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/v1/sign-ecdsa-jws',
      headers: { authorization: `Bearer ${TOKEN}` },
      payload: { keyId: KEY_ID, canonicalInput: `${SIGNER_ECDSA_CANONICAL_PREFIX}${VALID_INPUT}` },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe('invalid_canonical_input');
  });

  it('returns 400 invalid_canonical_input on a non-JWS-shaped input', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/v1/sign-ecdsa-jws',
      headers: { authorization: `Bearer ${TOKEN}` },
      payload: { keyId: KEY_ID, canonicalInput: 'not-a-jws-input' },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe('invalid_canonical_input');
  });

  it('returns 404 key_not_found on an unknown keyId', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/v1/sign-ecdsa-jws',
      headers: { authorization: `Bearer ${TOKEN}` },
      payload: { keyId: 'does-not-exist', canonicalInput: VALID_INPUT },
    });
    expect(res.statusCode).toBe(404);
    expect(res.json()).toEqual({ error: 'key_not_found' });
  });

  it('returns 400 malformed_request when canonicalInput is absent', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/v1/sign-ecdsa-jws',
      headers: { authorization: `Bearer ${TOKEN}` },
      payload: { keyId: KEY_ID },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe('malformed_request');
  });

  it('cross-domain isolation: a prefixed signature does NOT verify prefix-free', () => {
    // Produce a signature the way /v1/sign-ecdsa would (prefixed + DER),
    // then assert it is not a valid prefix-free JWS signature.
    const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const pem = privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;
    const s = createSign('SHA256');
    s.update(SIGNER_ECDSA_CANONICAL_PREFIX + VALID_INPUT);
    s.end();
    const derSig = s.sign(pem); // DER, prefixed domain

    const jwsSig = Buffer.from(signEcdsaJws(pem, VALID_INPUT), 'base64url'); // raw, prefix-free
    expect(Buffer.compare(derSig.subarray(0, 64), jwsSig)).not.toBe(0);
  });
});
