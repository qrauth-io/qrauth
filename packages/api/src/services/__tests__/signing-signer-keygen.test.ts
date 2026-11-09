import { describe, it, expect, vi, afterEach } from 'vitest';
import { createPublicKey, generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto';
import { mkdtempSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

/**
 * SIGNER_KEYGEN=signer: SigningService gets key material from the signer's
 * POST /v1/keys/generate and never touches envelopes or the master key.
 *
 * `lib/key-at-rest.js` is mocked to throw, so any encrypt/decrypt on this
 * path fails the test. The signer is a stubbed `fetch`.
 */

vi.mock('../../lib/queue.js', () => ({
  webhookQueue: { add: vi.fn(async () => ({ id: 'job_1' })) },
  closeQueues: vi.fn(async () => {}),
}));

const keyAtRest = vi.hoisted(() => ({
  encryptAtRest: vi.fn(() => {
    throw new Error('encryptAtRest must not run with SIGNER_KEYGEN=signer');
  }),
  decryptAtRest: vi.fn(() => {
    throw new Error('decryptAtRest must not run with SIGNER_KEYGEN=signer');
  }),
  loadMasterKey: vi.fn(() => {
    throw new Error('loadMasterKey must not run with SIGNER_KEYGEN=signer');
  }),
}));
vi.mock('../../lib/key-at-rest.js', () => keyAtRest);

const ENV_KEYS = ['SIGNER_KEYGEN', 'ECDSA_SIGNER', 'ECDSA_SIGNER_URL', 'ECDSA_SIGNER_TOKEN', 'SLH_DSA_SIGNER', 'SLH_DSA_SIGNER_URL', 'SLH_DSA_SIGNER_TOKEN', 'ECDSA_PRIVATE_KEY_PATH'];

function remoteEnv(keysDir: string) {
  Object.assign(process.env, {
    SIGNER_KEYGEN: 'signer',
    ECDSA_SIGNER: 'http',
    ECDSA_SIGNER_URL: 'http://signer.test/',
    ECDSA_SIGNER_TOKEN: 't'.repeat(40),
    SLH_DSA_SIGNER: 'http',
    SLH_DSA_SIGNER_URL: 'http://signer.test',
    SLH_DSA_SIGNER_TOKEN: 't'.repeat(40),
    ECDSA_PRIVATE_KEY_PATH: keysDir,
  });
}

function prismaStub() {
  const created: Record<string, unknown>[] = [];
  return {
    created,
    prisma: {
      signingKey: {
        create: vi.fn(async ({ data }: { data: Record<string, unknown> }) => {
          created.push(data);
          return { id: 'sk_1', ...data };
        }),
      },
      organization: { findUnique: vi.fn(async () => null) },
    } as never,
  };
}

const ecPub = () =>
  generateKeyPairSync('ec', { namedCurve: 'prime256v1', publicKeyEncoding: { type: 'spki', format: 'pem' }, privateKeyEncoding: { type: 'pkcs8', format: 'pem' } }).publicKey;
const rsaPub = (bits = 2048) =>
  generateKeyPairSync('rsa', { modulusLength: bits, publicKeyEncoding: { type: 'spki', format: 'pem' }, privateKeyEncoding: { type: 'pkcs8', format: 'pem' } }).publicKey;

function stubSigner(response: (kind: string) => unknown, status = 201) {
  const calls: { url: string; body: unknown; auth: string | undefined }[] = [];
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string, init: RequestInit) => {
      const body = JSON.parse(String(init.body));
      calls.push({ url, body, auth: (init.headers as Record<string, string>).Authorization });
      return { ok: status < 300, status, statusText: 'x', json: async () => response(body.kind) };
    }),
  );
  return calls;
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.clearAllMocks();
  for (const k of ENV_KEYS) delete process.env[k];
});

describe('SIGNER_KEYGEN=signer', () => {
  it('createKeyPair: asks the signer for es256-slhdsa, stores only public keys, writes no file', async () => {
    vi.resetModules();
    const keysDir = mkdtempSync(join(tmpdir(), 'qrauth-keys-'));
    remoteEnv(keysDir);
    const keyId = randomUUID();
    const slhdsaPublicKey = randomBytes(32).toString('base64');
    const publicKey = ecPub();
    const calls = stubSigner(() => ({ keyId, kind: 'es256-slhdsa', publicKey, slhdsaPublicKey }));

    const { SigningService } = await import('../signing.js');
    const { prisma, created } = prismaStub();
    const key = await new SigningService(prisma).createKeyPair('org_1');

    expect(calls).toHaveLength(1);
    expect(calls[0].url).toBe('http://signer.test/v1/keys/generate');
    expect(calls[0].body).toEqual({ kind: 'es256-slhdsa' });
    expect(calls[0].auth).toBe(`Bearer ${'t'.repeat(40)}`);
    expect(created[0]).toMatchObject({ organizationId: 'org_1', keyId, publicKey, slhdsaPublicKey, algorithm: 'ES256', status: 'ACTIVE', slhdsaAlgorithm: 'slh-dsa-sha2-128s' });
    expect(key.keyId).toBe(keyId);
    expect(readdirSync(keysDir)).toEqual([]);
    expect(keyAtRest.encryptAtRest).not.toHaveBeenCalled();
    expect(keyAtRest.decryptAtRest).not.toHaveBeenCalled();
    expect(keyAtRest.loadMasterKey).not.toHaveBeenCalled();
  });

  it('createRsaKeyPair: asks the signer for rs256 and stores an RS256 row', async () => {
    vi.resetModules();
    remoteEnv(mkdtempSync(join(tmpdir(), 'qrauth-keys-')));
    const keyId = randomUUID();
    const publicKey = rsaPub();
    const calls = stubSigner(() => ({ keyId, kind: 'rs256', publicKey }));

    const { SigningService } = await import('../signing.js');
    const { prisma, created } = prismaStub();
    await new SigningService(prisma).createRsaKeyPair('org_1');

    expect(calls[0].body).toEqual({ kind: 'rs256' });
    expect(created[0]).toMatchObject({ keyId, publicKey, algorithm: 'RS256' });
    expect(created[0]).not.toHaveProperty('slhdsaPublicKey');
    expect(keyAtRest.encryptAtRest).not.toHaveBeenCalled();
  });

  it.each([
    ['a non-UUID keyId', () => ({ keyId: 'abc', publicKey: ecPub(), slhdsaPublicKey: randomBytes(32).toString('base64') })],
    ['an RSA key where EC is expected', () => ({ keyId: randomUUID(), publicKey: rsaPub(), slhdsaPublicKey: randomBytes(32).toString('base64') })],
    ['a short SLH-DSA public key', () => ({ keyId: randomUUID(), publicKey: ecPub(), slhdsaPublicKey: randomBytes(16).toString('base64') })],
    ['private key material', () => ({ keyId: randomUUID(), publicKey: '-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n' })],
  ])('rejects a signer response with %s and writes no row', async (_label, response) => {
    vi.resetModules();
    remoteEnv(mkdtempSync(join(tmpdir(), 'qrauth-keys-')));
    stubSigner(response);
    const { SigningService } = await import('../signing.js');
    const { prisma, created } = prismaStub();
    await expect(new SigningService(prisma).createKeyPair('org_1')).rejects.toThrow(/key generation/);
    expect(created).toHaveLength(0);
  });

  it('a signer error propagates and writes no row', async () => {
    vi.resetModules();
    remoteEnv(mkdtempSync(join(tmpdir(), 'qrauth-keys-')));
    stubSigner(() => ({ error: 'internal_error' }), 500);
    const { SigningService } = await import('../signing.js');
    const { prisma, created } = prismaStub();
    await expect(new SigningService(prisma).createKeyPair('org_1')).rejects.toThrow(/\/v1\/keys\/generate failed: 500/);
    expect(created).toHaveLength(0);
  });

  it('rejects an RSA key that is not 2048-bit', async () => {
    const { parseGeneratedKey } = await import('../key-generator.js');
    expect(() => parseGeneratedKey('rs256', { keyId: randomUUID(), publicKey: rsaPub(3072) })).toThrow(/RSA-2048/);
  });

  it('accepts only canonical base64 for the SLH-DSA key and stores the re-exported SPKI PEM', async () => {
    const { parseGeneratedKey } = await import('../key-generator.js');
    const slh = randomBytes(32).toString('base64');
    const pem = ecPub();
    const ok = parseGeneratedKey('es256-slhdsa', { keyId: randomUUID(), publicKey: `${pem}\ntrailing text\n`, slhdsaPublicKey: slh });
    expect(ok.publicKey).toBe(createPublicKey(pem).export({ type: 'spki', format: 'pem' }).toString());
    expect(ok.slhdsaPublicKey).toBe(slh);
    expect(() =>
      parseGeneratedKey('es256-slhdsa', { keyId: randomUUID(), publicKey: pem, slhdsaPublicKey: `${slh}!!` }),
    ).toThrow(/canonical base64/);
  });
});

describe('rotation with SIGNER_KEYGEN=signer', () => {
  it('rotateKeyById: new key from the signer, probe signed through the signer, then committed', async () => {
    vi.resetModules();
    remoteEnv(mkdtempSync(join(tmpdir(), 'qrauth-keys-')));
    const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const publicKey = pair.publicKey.export({ type: 'spki', format: 'pem' }) as string;
    const newKeyId = randomUUID();
    const { sign } = await import('node:crypto');
    const urls: string[] = [];
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string, init: RequestInit) => {
        urls.push(url);
        const body = JSON.parse(String(init.body));
        if (url.endsWith('/v1/keys/generate')) {
          return { ok: true, status: 201, json: async () => ({ keyId: newKeyId, kind: 'es256-slhdsa', publicKey, slhdsaPublicKey: randomBytes(32).toString('base64') }) };
        }
        // /v1/sign-ecdsa-jws: P1363 signature over the canonical input.
        const sig = sign('sha256', Buffer.from(body.canonicalInput), { key: pair.privateKey, dsaEncoding: 'ieee-p1363' });
        return { ok: true, status: 200, json: async () => ({ signature: sig.toString('base64url') }) };
      }),
    );

    const current = { id: 'sk_old', keyId: 'old', organizationId: 'org_1', algorithm: 'ES256', status: 'ACTIVE' };
    const created: Record<string, unknown>[] = [];
    const tx = {
      signingKey: {
        updateMany: vi.fn(async () => ({ count: 1 })),
        create: vi.fn(async ({ data }: { data: Record<string, unknown> }) => {
          created.push(data);
          return { id: 'sk_new', ...data };
        }),
      },
    };
    const prisma = {
      signingKey: { findUnique: vi.fn(async () => current) },
      organization: { findUnique: vi.fn(async () => null) },
      $transaction: vi.fn(async (fn: (t: typeof tx) => unknown) => fn(tx)),
    } as never;

    const { SigningService } = await import('../signing.js');
    const next = await new SigningService(prisma).rotateKeyById('old');

    expect(urls).toEqual(['http://signer.test/v1/keys/generate', 'http://signer.test/v1/sign-ecdsa-jws']);
    expect(tx.signingKey.updateMany).toHaveBeenCalledTimes(1);
    expect(created[0]).toMatchObject({ keyId: newKeyId, publicKey, algorithm: 'ES256', organizationId: 'org_1' });
    expect(next.keyId).toBe(newKeyId);
    expect(keyAtRest.encryptAtRest).not.toHaveBeenCalled();
  });
});

describe('default signers follow the configured backend', () => {
  it('with ECDSA_SIGNER=http, an omitted RSA signer signs through the signer (no local fallback)', async () => {
    vi.resetModules();
    remoteEnv(mkdtempSync(join(tmpdir(), 'qrauth-keys-')));
    const fetchMock = vi.fn(async () => ({ ok: true, status: 200, json: async () => ({ signature: 'c2ln' }) }));
    vi.stubGlobal('fetch', fetchMock);
    const { SigningService } = await import('../signing.js');
    const svc = new SigningService(prismaStub().prisma);
    await svc.signRsaJws('kid', 'aGVhZA.cGF5');
    await svc.signCanonical('kid', 'canonical');
    const urls = fetchMock.mock.calls.map((c) => String((c as unknown[])[0]));
    expect(urls).toEqual(['http://signer.test/v1/sign-rsa-jws', 'http://signer.test/v1/sign-ecdsa']);
    expect(keyAtRest.decryptAtRest).not.toHaveBeenCalled();
  });
});

describe('config', () => {
  it('SIGNER_KEYGEN=signer requires both remote backends and the signer URL/token', async () => {
    const { assertKeygenBackends } = await import('../../lib/config.js');
    const base = {
      SIGNER_KEYGEN: 'signer' as const, ECDSA_SIGNER: 'http' as const, SLH_DSA_SIGNER: 'http' as const,
      ECDSA_SIGNER_URL: 'http://10.0.0.2:7788', ECDSA_SIGNER_TOKEN: 't',
      SLH_DSA_SIGNER_URL: 'http://10.0.0.2:7788/', SLH_DSA_SIGNER_TOKEN: 't',
    };
    expect(() => assertKeygenBackends(base)).not.toThrow();
    expect(() => assertKeygenBackends({ ...base, SLH_DSA_SIGNER_URL: 'http://10.0.0.3:7788' })).toThrow(/one signer/);
    expect(() => assertKeygenBackends({ ...base, SLH_DSA_SIGNER_TOKEN: 'other' })).toThrow(/one signer/);
    expect(() => assertKeygenBackends({ ...base, SLH_DSA_SIGNER: 'local' })).toThrow(/SLH_DSA_SIGNER=http/);
    expect(() => assertKeygenBackends({ ...base, ECDSA_SIGNER: 'local' })).toThrow(/ECDSA_SIGNER=http/);
    expect(() => assertKeygenBackends({ ...base, ECDSA_SIGNER_TOKEN: undefined })).toThrow(/ECDSA_SIGNER_TOKEN/);
    expect(() => assertKeygenBackends({ ...base, SIGNER_KEYGEN: 'local', ECDSA_SIGNER: 'local' })).not.toThrow();
  });

  it('the master key is needed only for local key generation or a local signing backend', async () => {
    const { apiNeedsMasterKey } = await import('../../lib/config.js');
    expect(apiNeedsMasterKey({ SIGNER_KEYGEN: 'signer', ECDSA_SIGNER: 'http', SLH_DSA_SIGNER: 'http' })).toBe(false);
    expect(apiNeedsMasterKey({ SIGNER_KEYGEN: 'local', ECDSA_SIGNER: 'http', SLH_DSA_SIGNER: 'http' })).toBe(true);
    expect(apiNeedsMasterKey({ SIGNER_KEYGEN: 'local', ECDSA_SIGNER: 'local', SLH_DSA_SIGNER: 'local' })).toBe(true);
  });

  it('/health secret check: no SIGNER_MASTER_KEY needed when the API does not need one', async () => {
    const { checkOidcRuntimeSecrets } = await import('../../lib/oidc-signing-keys.js');
    const pairwiseSecret = Buffer.alloc(32, 1);
    expect(checkOidcRuntimeSecrets({ pairwiseSecret, signerMasterKey: undefined, requireSignerMasterKey: false })).toEqual([]);
    expect(checkOidcRuntimeSecrets({ pairwiseSecret, signerMasterKey: undefined, requireSignerMasterKey: true })).toEqual(['SIGNER_MASTER_KEY']);
  });
});
