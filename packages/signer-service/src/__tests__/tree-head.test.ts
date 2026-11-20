import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash, generateKeyPairSync, randomBytes, sign as ecdsaSign, timingSafeEqual } from 'node:crypto';
import { slh_dsa_sha2_128s } from '@noble/post-quantum/slh-dsa.js';
import {
  TREE_HEAD_DOMAIN_PREFIX,
  TRUST_LOG_ORIGIN,
  consistencyProof,
  rootHash,
  sha256Hasher,
  treeHeadMessage,
} from '@qrauth/merkle-log';

/**
 * POST /v1/sign-tree-head (ADR-0009 D7) and the operator CLI functions.
 * The route under test is the production registrar; the bearer hook mirrors
 * server.ts. Signatures use the pure-JS SLH-DSA implementation.
 */

// Pure-JS SLH-DSA-SHA2-128s signs in about 1–2 s on CI runners and several
// tests sign three or four heads, so the 5 s default is too tight.
vi.setConfig({ testTimeout: 60_000 });

process.env.SIGNER_MASTER_KEY = randomBytes(32).toString('base64');
const TOKEN = 't'.repeat(40);

const { registerTreeHeadRoute } = await import('../tree-head.js');
const { readTreeHeadState, writeTreeHeadState, TREE_HEAD_STATE_FILE } = await import('../tree-head-store.js');
const { genesisInit, showState, exportTreeHeadPublicKey, reinitFromHead, CliError } = await import('../tree-head-cli.js');
const { nobleImplementation } = await import('../slh-dsa.js');
const { SIGNER_ECDSA_CANONICAL_PREFIX, SIGNER_MERKLE_ROOT_PREFIX, SIGNER_TREE_HEAD_PREFIX } = await import('../domain-separation.js');

const enc = new TextEncoder();
const leaves = Array.from({ length: 40 }, (_, i) => sha256Hasher.hashLeaf(enc.encode(`leaf-${i}`)));
const rootOf = (n: number) => rootHash(sha256Hasher, leaves.slice(0, n));
const b64 = (b: Uint8Array) => Buffer.from(b).toString('base64');

let keysDir: string;
let app: FastifyInstance;
let clock = 1_763_600_000_000;

async function buildApp(): Promise<FastifyInstance> {
  const a = Fastify({ logger: false });
  a.addHook('onRequest', async (request, reply) => {
    const m = (request.headers.authorization ?? '').match(/^Bearer (.+)$/);
    const provided = Buffer.from(m?.[1] ?? '', 'utf8');
    const expected = Buffer.from(TOKEN, 'utf8');
    if (provided.length !== expected.length || !timingSafeEqual(provided, expected)) {
      return reply.status(401).send({ error: 'unauthorized' });
    }
  });
  registerTreeHeadRoute(a, { keysDir, slhDsa: () => nobleImplementation, now: () => clock });
  await a.ready();
  return a;
}

function post(body: Record<string, unknown>, token = TOKEN) {
  return app.inject({ method: 'POST', url: '/v1/sign-tree-head', headers: { authorization: `Bearer ${token}` }, payload: body });
}

function head(treeSize: number, fromSize: number, proof: Uint8Array[] = [], root = rootOf(treeSize)) {
  return { logId: TRUST_LOG_ORIGIN, treeSize, rootHash: b64(root), fromSize, consistencyProof: proof.map(b64) };
}

const extension = (from: number, to: number) => head(to, from, consistencyProof(sha256Hasher, leaves.slice(0, to), from));

function verifySignature(res: { signature: string; signedAtMs: number }, treeSize: number, root: Uint8Array, publicKey: Uint8Array) {
  const msg = treeHeadMessage({ logId: TRUST_LOG_ORIGIN, treeSize, rootHash: root, signedAtMs: res.signedAtMs });
  return slh_dsa_sha2_128s.verify(Buffer.from(res.signature, 'base64'), msg, publicKey);
}

beforeEach(async () => {
  keysDir = mkdtempSync(join(tmpdir(), 'signer-tree-head-'));
  clock += 1000;
  app = await buildApp();
});

afterEach(async () => {
  await app.close();
  rmSync(keysDir, { recursive: true, force: true });
});

describe('genesis-init (operator command)', () => {
  it('creates the platform key and the genesis state, once', async () => {
    const out = await genesisInit(keysDir, TRUST_LOG_ORIGIN);
    const state = await readTreeHeadState(keysDir);
    expect(state.logs[TRUST_LOG_ORIGIN].lastSize).toBe(0);
    expect(Buffer.from(state.logs[TRUST_LOG_ORIGIN].lastRoot).equals(Buffer.from(sha256Hasher.emptyRoot()))).toBe(true);
    expect(state.logs[TRUST_LOG_ORIGIN].keyId).toBe(out.keyId);
    // the private key is an encrypted envelope, never a plain secret
    const envelope = readFileSync(join(keysDir, `${out.keyId}.treehead.enc`), 'utf8');
    expect(envelope.startsWith('qrauth-kek-v1\0')).toBe(true);

    await expect(genesisInit(keysDir, TRUST_LOG_ORIGIN)).rejects.toThrow(CliError);
    expect(readdirSync(keysDir).filter((f) => f.endsWith('.treehead.enc'))).toHaveLength(1);
  });

  it('refuses to run without SIGNER_MASTER_KEY', async () => {
    const saved = process.env.SIGNER_MASTER_KEY;
    delete process.env.SIGNER_MASTER_KEY;
    try {
      await expect(genesisInit(keysDir, TRUST_LOG_ORIGIN)).rejects.toThrow(/SIGNER_MASTER_KEY/);
    } finally {
      process.env.SIGNER_MASTER_KEY = saved;
    }
    expect(existsSync(join(keysDir, TREE_HEAD_STATE_FILE))).toBe(false);
  });

  it('the platform key cannot be used by the merkle-root or key-public routes (different file name)', async () => {
    const { keyId } = await genesisInit(keysDir, TRUST_LOG_ORIGIN);
    expect(existsSync(join(keysDir, `${keyId}.slhdsa.enc`))).toBe(false);
    expect(existsSync(join(keysDir, `${keyId}.ecdsa.enc`))).toBe(false);
  });
});

describe('POST /v1/sign-tree-head', () => {
  it('refuses all heads while the state is missing', async () => {
    const res = await post(head(3, 0));
    expect(res.statusCode).toBe(503);
    expect(res.json().error).toBe('tree_head_state_missing');
  });

  it('signs the genesis extension (fromSize 0, no proof) and the signature verifies', async () => {
    const { publicKey } = await genesisInit(keysDir, TRUST_LOG_ORIGIN);
    const res = await post(head(3, 0));
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.signedAtMs).toBe(clock);
    expect(verifySignature(body, 3, rootOf(3), Buffer.from(publicKey, 'base64'))).toBe(true);
    expect((await readTreeHeadState(keysDir)).logs[TRUST_LOG_ORIGIN].lastSize).toBe(3);
  });

  it('genesis is accepted once: a second fromSize 0 head is refused', async () => {
    await genesisInit(keysDir, TRUST_LOG_ORIGIN);
    expect((await post(head(3, 0))).statusCode).toBe(200);
    const again = await post(head(5, 0));
    expect(again.statusCode).toBe(409);
    expect(again.json().error).toBe('stale_from_size');
  });

  it('refuses a genesis head that carries a proof', async () => {
    await genesisInit(keysDir, TRUST_LOG_ORIGIN);
    const res = await post(head(3, 0, [rootOf(1)]));
    expect(res.statusCode).toBe(409);
    expect(res.json().error).toBe('unexpected_proof');
  });

  it('signs a valid extension with an RFC 9162 consistency proof', async () => {
    const { publicKey } = await genesisInit(keysDir, TRUST_LOG_ORIGIN);
    expect((await post(head(3, 0))).statusCode).toBe(200);
    clock += 1;
    const res = await post(extension(3, 17));
    expect(res.statusCode).toBe(200);
    expect(verifySignature(res.json(), 17, rootOf(17), Buffer.from(publicKey, 'base64'))).toBe(true);
    clock += 1;
    expect((await post(extension(17, 40))).statusCode).toBe(200);
    expect((await readTreeHeadState(keysDir)).logs[TRUST_LOG_ORIGIN].lastSize).toBe(40);
  });

  it('allows re-signing the same head, with a fresh timestamp', async () => {
    await genesisInit(keysDir, TRUST_LOG_ORIGIN);
    await post(head(5, 0));
    clock += 500;
    const res = await post(head(5, 5));
    expect(res.statusCode).toBe(200);
    expect(res.json().signedAtMs).toBe(clock);
  });

  describe('refusals after a head at size 10', () => {
    beforeEach(async () => {
      await genesisInit(keysDir, TRUST_LOG_ORIGIN);
      expect((await post(head(10, 0))).statusCode).toBe(200);
      clock += 1;
    });

    const cases: Array<[string, () => Record<string, unknown>, string]> = [
      ['stale fromSize', () => extension(5, 20), 'stale_from_size'],
      ['smaller treeSize', () => head(7, 10), 'not_an_extension'],
      ['different root at the same size (equivocation)', () => head(10, 10, [], rootOf(11)), 'equivocation'],
      ['a bit-flipped proof', () => {
        const h = extension(10, 20);
        const p = (h.consistencyProof as string[]).map((x) => Buffer.from(x, 'base64'));
        p[0][0] ^= 1;
        return { ...h, consistencyProof: p.map(b64) };
      }, 'inconsistent'],
      ['a forged proof for a different tree', () => {
        const other = Array.from({ length: 20 }, (_, i) => sha256Hasher.hashLeaf(enc.encode(`forged-${i}`)));
        return head(20, 10, consistencyProof(sha256Hasher, other, 10), rootHash(sha256Hasher, other));
      }, 'inconsistent'],
      ['a truncated proof', () => {
        const h = extension(10, 20);
        return { ...h, consistencyProof: (h.consistencyProof as string[]).slice(0, -1) };
      }, 'inconsistent'],
      ['a missing proof', () => head(20, 10), 'inconsistent'],
      ['the right proof with a wrong new root', () => ({ ...extension(10, 20), rootHash: b64(rootOf(21)) }), 'inconsistent'],
    ];

    it.each(cases)('refuses %s', async (_name, body, error) => {
      const res = await post(body());
      expect(res.statusCode).toBe(409);
      expect(res.json().error).toBe(error);
      expect((await readTreeHeadState(keysDir)).logs[TRUST_LOG_ORIGIN].lastSize).toBe(10);
    });

    it('equivocation: after one root at size 20, another root at size 20 is refused', async () => {
      expect((await post(extension(10, 20))).statusCode).toBe(200);
      clock += 1;
      const other = [...leaves.slice(0, 19), sha256Hasher.hashLeaf(enc.encode('evil'))];
      const res = await post(head(20, 20, [], rootHash(sha256Hasher, other)));
      expect(res.statusCode).toBe(409);
      expect(res.json().error).toBe('equivocation');
    });

    it('refuses to sign when the clock has gone back', async () => {
      clock -= 10_000;
      const res = await post(extension(10, 20));
      expect(res.statusCode).toBe(503);
      expect(res.json().error).toBe('clock_regressed');
    });

    it('refuses an unknown log', async () => {
      const res = await post({ ...extension(10, 20), logId: 'example.com/other' });
      expect(res.statusCode).toBe(404);
      expect(res.json().error).toBe('unknown_log');
    });
  });

  it.each([
    [{}],
    [{ ...head(1, 0), extra: 1 }],
    [{ ...head(1, 0), treeSize: -1 }],
    [{ ...head(1, 0), treeSize: 1.5 }],
    [{ ...head(1, 0), treeSize: '1' }],
    [{ ...head(1, 0), rootHash: 'not-base64!' }],
    [{ ...head(1, 0), rootHash: b64(new Uint8Array(31)) }],
    [{ ...head(1, 0), consistencyProof: [b64(new Uint8Array(33))] }],
    [{ ...head(1, 0), consistencyProof: Array.from({ length: 65 }, () => b64(new Uint8Array(32))) }],
    [{ ...head(1, 0), logId: 'has space' }],
  ])('rejects a malformed body (400) %#', async (body) => {
    await genesisInit(keysDir, TRUST_LOG_ORIGIN);
    const res = await post(body as Record<string, unknown>);
    expect(res.statusCode).toBe(400);
    expect((await readTreeHeadState(keysDir)).logs[TRUST_LOG_ORIGIN].lastSize).toBe(0);
  });

  it('requires the bearer token', async () => {
    await genesisInit(keysDir, TRUST_LOG_ORIGIN);
    expect((await post(head(1, 0), 'x'.repeat(40))).statusCode).toBe(401);
  });
});

describe('state file', () => {
  it('a crash between the temp write and the rename leaves the previous state valid', async () => {
    await genesisInit(keysDir, TRUST_LOG_ORIGIN);
    expect((await post(head(10, 0))).statusCode).toBe(200);
    const before = await readTreeHeadState(keysDir);
    const next = { logs: { [TRUST_LOG_ORIGIN]: { ...before.logs[TRUST_LOG_ORIGIN], lastSize: 99 } } };
    await expect(
      writeTreeHeadState(keysDir, next, { beforeRename: () => { throw new Error('simulated crash'); } }),
    ).rejects.toThrow('simulated crash');
    expect((await readTreeHeadState(keysDir)).logs[TRUST_LOG_ORIGIN].lastSize).toBe(10);
    clock += 1;
    expect((await post(extension(10, 20))).statusCode).toBe(200);
  });

  it('a corrupt state refuses all heads', async () => {
    await genesisInit(keysDir, TRUST_LOG_ORIGIN);
    writeFileSync(join(keysDir, TREE_HEAD_STATE_FILE), '{"version":1,"logs":');
    const res = await post(head(3, 0));
    expect(res.statusCode).toBe(503);
    expect(res.json().error).toBe('tree_head_state_corrupt');
  });

  it('an edited state (integrity check fails) refuses all heads', async () => {
    await genesisInit(keysDir, TRUST_LOG_ORIGIN);
    expect((await post(head(10, 0))).statusCode).toBe(200);
    const path = join(keysDir, TREE_HEAD_STATE_FILE);
    const tampered = readFileSync(path, 'utf8').replace('"lastSize":10', '"lastSize":2');
    writeFileSync(path, tampered);
    const res = await post(extension(2, 20));
    expect(res.statusCode).toBe(503);
    expect(res.json().error).toBe('tree_head_state_corrupt');
  });

  it('a deleted state refuses all heads', async () => {
    await genesisInit(keysDir, TRUST_LOG_ORIGIN);
    rmSync(join(keysDir, TREE_HEAD_STATE_FILE));
    expect((await post(head(3, 0))).json().error).toBe('tree_head_state_missing');
  });
});

describe('domain separation', () => {
  it('the three signer signing prefixes are distinct and none is a prefix of another', () => {
    const prefixes = [SIGNER_TREE_HEAD_PREFIX, SIGNER_MERKLE_ROOT_PREFIX.toString('utf8'), SIGNER_ECDSA_CANONICAL_PREFIX];
    expect(SIGNER_TREE_HEAD_PREFIX).toBe(TREE_HEAD_DOMAIN_PREFIX);
    for (const a of prefixes) for (const b of prefixes) if (a !== b) expect(b.startsWith(a)).toBe(false);
  });

  it('a tree-head signature does not verify as a merkle-root signature, and vice versa', async () => {
    const { publicKey } = await genesisInit(keysDir, TRUST_LOG_ORIGIN);
    const pk = Buffer.from(publicKey, 'base64');
    const res = (await post(head(4, 0))).json();
    const msg = treeHeadMessage({ logId: TRUST_LOG_ORIGIN, treeSize: 4, rootHash: rootOf(4), signedAtMs: res.signedAtMs });
    const body = msg.subarray(TREE_HEAD_DOMAIN_PREFIX.length);
    const sig = Buffer.from(res.signature, 'base64');
    // the same signature over the merkle-root domain fails
    expect(slh_dsa_sha2_128s.verify(sig, Buffer.concat([SIGNER_MERKLE_ROOT_PREFIX, body]), pk)).toBe(false);
    expect(slh_dsa_sha2_128s.verify(sig, Buffer.concat([SIGNER_MERKLE_ROOT_PREFIX, rootOf(4)]), pk)).toBe(false);
    // a merkle-root-domain signature (as /v1/sign would make) over the same bytes fails as a tree head
    const sk = (await import('../tree-head-key.js')).loadTreeHeadSecretKey;
    const secret = await sk(keysDir, (await readTreeHeadState(keysDir)).logs[TRUST_LOG_ORIGIN].keyId);
    const merkleSig = slh_dsa_sha2_128s.sign(Buffer.concat([SIGNER_MERKLE_ROOT_PREFIX, body]), secret);
    expect(slh_dsa_sha2_128s.verify(merkleSig, msg, pk)).toBe(false);
  });

  it('an ECDSA-canonical signature never verifies as a tree head', async () => {
    const { publicKey } = await genesisInit(keysDir, TRUST_LOG_ORIGIN);
    const ec = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const msg = treeHeadMessage({ logId: TRUST_LOG_ORIGIN, treeSize: 1, rootHash: rootOf(1), signedAtMs: clock });
    const ecdsaSig = ecdsaSign('sha256', Buffer.concat([Buffer.from(SIGNER_ECDSA_CANONICAL_PREFIX), msg]), ec.privateKey);
    expect(slh_dsa_sha2_128s.verify(ecdsaSig, msg, Buffer.from(publicKey, 'base64'))).toBe(false);
  });
});

describe('operator commands', () => {
  it('show-state and export-tree-head-pubkey print the state and the key fingerprint', async () => {
    const { keyId, publicKey } = await genesisInit(keysDir, TRUST_LOG_ORIGIN);
    const state = await showState(keysDir);
    expect(state).toMatchObject({ [TRUST_LOG_ORIGIN]: { keyId, lastSize: 0, lastSignedAt: null } });
    const exported = await exportTreeHeadPublicKey(keysDir);
    expect(exported.keyId).toBe(keyId);
    expect(exported.publicKey).toBe(publicKey);
    expect(exported.fingerprintSha256).toBe(createHash('sha256').update(Buffer.from(publicKey, 'base64')).digest('hex'));
    expect(exported.vkey.startsWith(`${TRUST_LOG_ORIGIN}+`)).toBe(true);
  });

  describe('reinit-from-head', () => {
    async function signedHeadAt(n: number) {
      if (n > 0) expect((await post(head(n, 0))).statusCode).toBe(200);
      const { logs } = await readTreeHeadState(keysDir);
      const s = logs[TRUST_LOG_ORIGIN];
      return { logId: TRUST_LOG_ORIGIN, treeSize: s.lastSize, rootHash: b64(s.lastRoot), signedAtMs: s.lastSignedAtMs, keyId: s.keyId };
    }

    it('restores a lost state from a head the signer signed', async () => {
      await genesisInit(keysDir, TRUST_LOG_ORIGIN);
      const res = (await post(head(10, 0))).json();
      const signed = { ...(await signedHeadAt(0)), signature: res.signature };
      rmSync(join(keysDir, TREE_HEAD_STATE_FILE));

      await reinitFromHead(keysDir, JSON.stringify(signed), nobleImplementation);
      expect((await readTreeHeadState(keysDir)).logs[TRUST_LOG_ORIGIN].lastSize).toBe(10);
      clock += 1;
      expect((await post(extension(10, 20))).statusCode).toBe(200);
    });

    it('rejects a head whose signature does not verify', async () => {
      await genesisInit(keysDir, TRUST_LOG_ORIGIN);
      const res = (await post(head(10, 0))).json();
      const signed = { ...(await signedHeadAt(0)), signature: res.signature };
      rmSync(join(keysDir, TREE_HEAD_STATE_FILE));
      for (const bad of [
        { ...signed, treeSize: 11 },
        { ...signed, rootHash: b64(rootOf(9)) },
        { ...signed, signedAtMs: signed.signedAtMs + 1 },
        { ...signed, signature: b64(randomBytes(7856)) },
        { ...signed, keyId: 'another-key' },
      ]) {
        await expect(reinitFromHead(keysDir, JSON.stringify(bad), nobleImplementation)).rejects.toThrow(CliError);
      }
      expect(existsSync(join(keysDir, TREE_HEAD_STATE_FILE))).toBe(false);
    });

    it('refuses to move a valid state backwards', async () => {
      await genesisInit(keysDir, TRUST_LOG_ORIGIN);
      const res = (await post(head(10, 0))).json();
      const at10 = { ...(await signedHeadAt(0)), signature: res.signature };
      clock += 1;
      expect((await post(extension(10, 20))).statusCode).toBe(200);
      await expect(reinitFromHead(keysDir, JSON.stringify(at10), nobleImplementation)).rejects.toThrow(/backwards/);
      expect((await readTreeHeadState(keysDir)).logs[TRUST_LOG_ORIGIN].lastSize).toBe(20);
    });
  });
});
