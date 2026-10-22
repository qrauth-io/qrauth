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
import { JWS_CANONICAL_INPUT_RE, signRsaJws } from '../rsa-jws.js';

/**
 * Tests for the prefix-free `/v1/sign-rsa-jws` endpoint (ADR-0003 Slice 7a,
 * RS256 — OIDC Core §15.1 mandatory-to-implement). Mirrors ecdsa-jws.test.ts:
 * a minimal Fastify app rather than importing server.ts (which has
 * module-load side effects), with the same H-5-style bearer hook, the same
 * JWS-shape guard, and the `signRsaJws` primitive the production route calls.
 */
function buildRsaJwsApp(opts: {
  expectedToken: string;
  keys: Record<string, string>; // keyId -> RSA private PEM
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
    '/v1/sign-rsa-jws',
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
      const signature = signRsaJws(pem, canonicalInput);
      return { signature, kid: keyId, alg: 'RS256' };
    },
  );

  return app;
}

const TOKEN = 't'.repeat(40);
const KEY_ID = 'rsa-jws-key-1';

function makeRsaKeyPair() {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  return {
    pem: privateKey.export({ type: 'pkcs8', format: 'pem' }) as string,
    spki: publicKey.export({ type: 'spki', format: 'pem' }) as string,
  };
}

function makeEcKeyPair() {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return {
    pem: privateKey.export({ type: 'pkcs8', format: 'pem' }) as string,
    spki: publicKey.export({ type: 'spki', format: 'pem' }) as string,
  };
}

// A representative JWS canonical input: base64url(header).base64url(payload).
const VALID_INPUT = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhYmMifQ';

describe('signRsaJws (primitive)', () => {
  it('produces a base64url RS256 signature verifiable with RSA-SHA256', () => {
    const { pem, spki } = makeRsaKeyPair();
    const sig = signRsaJws(pem, VALID_INPUT);

    expect(sig).toMatch(/^[A-Za-z0-9_-]+$/);
    // RSA-2048 signature is 256 bytes.
    expect(Buffer.from(sig, 'base64url').length).toBe(256);

    const v = createVerify('RSA-SHA256');
    v.update(VALID_INPUT);
    v.end();
    expect(v.verify(spki, Buffer.from(sig, 'base64url'))).toBe(true);
  });

  it('signs the bytes directly with no domain prefix', () => {
    const { pem, spki } = makeRsaKeyPair();
    const sig = Buffer.from(signRsaJws(pem, VALID_INPUT), 'base64url');

    // Verifying against the PREFIXED input must fail — proving no prefix was applied.
    const v = createVerify('RSA-SHA256');
    v.update(SIGNER_ECDSA_CANONICAL_PREFIX + VALID_INPUT);
    v.end();
    expect(v.verify(spki, sig)).toBe(false);
  });
});

describe('JWS_CANONICAL_INPUT_RE (shared with ecdsa-jws)', () => {
  it('accepts base64url.base64url', () => {
    expect(JWS_CANONICAL_INPUT_RE.test(VALID_INPUT)).toBe(true);
  });
  it('rejects inputs containing the canonical domain prefix (has ":")', () => {
    expect(JWS_CANONICAL_INPUT_RE.test(`${SIGNER_ECDSA_CANONICAL_PREFIX}${VALID_INPUT}`)).toBe(false);
  });
  it('rejects single-segment, three-segment, and empty-segment inputs', () => {
    expect(JWS_CANONICAL_INPUT_RE.test('eyJhbGciOiJSUzI1NiJ9')).toBe(false);
    expect(JWS_CANONICAL_INPUT_RE.test('a.b.c')).toBe(false);
    expect(JWS_CANONICAL_INPUT_RE.test('a.')).toBe(false);
    expect(JWS_CANONICAL_INPUT_RE.test('.b')).toBe(false);
  });
});

describe('POST /v1/sign-rsa-jws', () => {
  let app: FastifyInstance;
  let spki: string;

  beforeEach(() => {
    const kp = makeRsaKeyPair();
    spki = kp.spki;
    app = buildRsaJwsApp({ expectedToken: TOKEN, keys: { [KEY_ID]: kp.pem } });
  });
  afterEach(async () => {
    await app.close();
  });

  it('rejects unauthenticated requests with 401', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/v1/sign-rsa-jws',
      payload: { keyId: KEY_ID, canonicalInput: VALID_INPUT },
    });
    expect(res.statusCode).toBe(401);
  });

  it('returns an RS256 JWS-verifiable signature on the happy path', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/v1/sign-rsa-jws',
      headers: { authorization: `Bearer ${TOKEN}` },
      payload: { keyId: KEY_ID, canonicalInput: VALID_INPUT },
    });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.kid).toBe(KEY_ID);
    expect(body.alg).toBe('RS256');
    expect(Buffer.from(body.signature, 'base64url').length).toBe(256);

    const v = createVerify('RSA-SHA256');
    v.update(VALID_INPUT);
    v.end();
    expect(v.verify(spki, Buffer.from(body.signature, 'base64url'))).toBe(true);
  });

  it('returns 400 invalid_canonical_input on a prefix-bearing input', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/v1/sign-rsa-jws',
      headers: { authorization: `Bearer ${TOKEN}` },
      payload: { keyId: KEY_ID, canonicalInput: `${SIGNER_ECDSA_CANONICAL_PREFIX}${VALID_INPUT}` },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe('invalid_canonical_input');
  });

  it('returns 400 invalid_canonical_input on a non-JWS-shaped input', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/v1/sign-rsa-jws',
      headers: { authorization: `Bearer ${TOKEN}` },
      payload: { keyId: KEY_ID, canonicalInput: 'not-a-jws-input' },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe('invalid_canonical_input');
  });

  it('returns 404 key_not_found on an unknown keyId', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/v1/sign-rsa-jws',
      headers: { authorization: `Bearer ${TOKEN}` },
      payload: { keyId: 'does-not-exist', canonicalInput: VALID_INPUT },
    });
    expect(res.statusCode).toBe(404);
    expect(res.json()).toEqual({ error: 'key_not_found' });
  });

  it('returns 400 malformed_request when canonicalInput is absent', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/v1/sign-rsa-jws',
      headers: { authorization: `Bearer ${TOKEN}` },
      payload: { keyId: KEY_ID },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe('malformed_request');
  });

  it('cross-alg isolation: an RS256 signature does NOT verify under ES256, and vice versa', () => {
    const rsa = makeRsaKeyPair();
    const ec = makeEcKeyPair();

    // Node's verify() may either return false OR throw "Malformed signature"
    // on a length-mismatched cross-alg signature — both mean "not verified".
    const cannotVerify = (fn: () => boolean): boolean => {
      try {
        return fn() === false;
      } catch {
        return true;
      }
    };

    const rsaSig = Buffer.from(signRsaJws(rsa.pem, VALID_INPUT), 'base64url');
    // RS256 signature under an ES256 verifier over the identical input → rejected.
    expect(
      cannotVerify(() => {
        const v = createVerify('SHA256');
        v.update(VALID_INPUT);
        v.end();
        return v.verify({ key: ec.spki, dsaEncoding: 'ieee-p1363' }, rsaSig);
      }),
    ).toBe(true);

    // ES256 raw signature under an RSA verifier → also rejected.
    const ecSign = createSign('SHA256');
    ecSign.update(VALID_INPUT);
    ecSign.end();
    const ecSig = ecSign.sign({ key: ec.pem, dsaEncoding: 'ieee-p1363' });
    expect(
      cannotVerify(() => {
        const v = createVerify('RSA-SHA256');
        v.update(VALID_INPUT);
        v.end();
        return v.verify(rsa.spki, ecSig);
      }),
    ).toBe(true);
  });
});
