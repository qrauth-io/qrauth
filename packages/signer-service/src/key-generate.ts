import { generateKeyPair, generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto';
import { link, open, unlink } from 'node:fs/promises';
import { dirname } from 'node:path';
import { promisify } from 'node:util';
import { join } from 'node:path';
import type { FastifyInstance } from 'fastify';
import { slh_dsa_sha2_128s } from '@noble/post-quantum/slh-dsa.js';
import { encryptAtRest } from './key-at-rest.js';

/**
 * Signer-side key generation (POST /v1/keys/generate).
 *
 * The signer generates the key pair, assigns the keyId, encrypts the private
 * half under its own master key and writes the envelope(s) into its keys
 * directory. The response carries public material only; private bytes never
 * leave this process. File formats match what the signer already loads:
 *
 *   <keyId>.ecdsa.enc   PKCS#8 PEM, EC P-256
 *   <keyId>.slhdsa.enc  64 raw bytes, SLH-DSA-SHA2-128s secret key
 *   <keyId>.rsa.enc     PKCS#8 PEM, RSA-2048
 */

export const KEY_KINDS = ['es256-slhdsa', 'rs256'] as const;
export type KeyKind = (typeof KEY_KINDS)[number];

export interface GeneratedKey {
  keyId: string;
  kind: KeyKind;
  /** SPKI PEM of the ECDSA P-256 or RSA-2048 public key. */
  publicKey: string;
  /** Base64 of the 32-byte SLH-DSA public key (es256-slhdsa only). */
  slhdsaPublicKey?: string;
}

/** SLH-DSA-SHA2-128s keygen seed length (3 x n, n = 16). */
const SLHDSA_SEED_BYTES = 48;

const generateKeyPairAsync = promisify(generateKeyPair);

/** fsync a directory so a completed link/unlink in it survives a crash. */
async function syncDir(dir: string): Promise<void> {
  const handle = await open(dir, 'r');
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

/**
 * Write a new file durably: temp file with mode 0600, fsync, hard-link to the
 * final name (fails with EEXIST instead of overwriting), remove the temp name,
 * fsync the directory. The final name must not exist yet.
 */
async function writeNewFile(path: string, contents: string): Promise<void> {
  const tmp = `${path}.tmp.${randomBytes(8).toString('hex')}`;
  const handle = await open(tmp, 'wx', 0o600);
  try {
    await handle.writeFile(contents, 'utf8');
    await handle.sync();
  } finally {
    await handle.close();
  }
  try {
    await link(tmp, path);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'EEXIST') {
      throw new Error(`refusing to overwrite existing key file ${path}`);
    }
    throw err;
  } finally {
    await unlink(tmp).catch(() => {});
  }
  await syncDir(dirname(path));
}

/** Remove a file written by writeNewFile and make the removal durable. */
async function removeFile(path: string): Promise<void> {
  await unlink(path).catch(() => {});
  await syncDir(dirname(path)).catch(() => {});
}

/**
 * Key generation is serialized: SLH-DSA key generation is CPU-bound and runs
 * on the event loop that also serves signing, so concurrent requests queue
 * here instead of competing.
 */
let keygenQueue: Promise<unknown> = Promise.resolve();
function serialized<T>(fn: () => Promise<T>): Promise<T> {
  const run = keygenQueue.then(fn, fn);
  keygenQueue = run.catch(() => {});
  return run;
}

/** Generate a key pair of `kind`, store its envelope(s) in `keysDir`, return public material. */
export async function generateAndStoreKey(keysDir: string, kind: KeyKind): Promise<GeneratedKey> {
  return serialized(() => generateAndStoreKeyNow(keysDir, kind));
}

async function generateAndStoreKeyNow(keysDir: string, kind: KeyKind): Promise<GeneratedKey> {
  const keyId = randomUUID();

  if (kind === 'rs256') {
    const { publicKey, privateKey } = await generateKeyPairAsync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    await writeNewFile(join(keysDir, `${keyId}.rsa.enc`), encryptAtRest(Buffer.from(privateKey, 'utf8')));
    return { keyId, kind, publicKey };
  }

  const { publicKey, privateKey } = generateKeyPairSync('ec', {
    namedCurve: 'prime256v1',
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  const slh = slh_dsa_sha2_128s.keygen(randomBytes(SLHDSA_SEED_BYTES));

  const ecdsaPath = join(keysDir, `${keyId}.ecdsa.enc`);
  const slhdsaPath = join(keysDir, `${keyId}.slhdsa.enc`);
  await writeNewFile(ecdsaPath, encryptAtRest(Buffer.from(privateKey, 'utf8')));
  try {
    await writeNewFile(slhdsaPath, encryptAtRest(Buffer.from(slh.secretKey)));
  } catch (err) {
    // Never leave half a key pair behind.
    await removeFile(ecdsaPath);
    throw err;
  }
  return {
    keyId,
    kind,
    publicKey,
    slhdsaPublicKey: Buffer.from(slh.publicKey).toString('base64'),
  };
}

/**
 * Register POST /v1/keys/generate on `app`. Authentication is the app-wide
 * bearer-token hook. Body: exactly `{ "kind": "es256-slhdsa" | "rs256" }`.
 */
export function registerKeyGenerateRoute(app: FastifyInstance, opts: { keysDir: string }): void {
  app.post<{ Body: unknown }>('/v1/keys/generate', async (request, reply) => {
    const body = request.body;
    if (
      !body ||
      typeof body !== 'object' ||
      Array.isArray(body) ||
      Object.keys(body).length !== 1 ||
      !KEY_KINDS.includes((body as { kind?: unknown }).kind as KeyKind)
    ) {
      return reply.status(400).send({ error: 'malformed_request' });
    }
    const kind = (body as { kind: KeyKind }).kind;

    let generated: GeneratedKey;
    try {
      generated = await generateAndStoreKey(opts.keysDir, kind);
    } catch (err) {
      request.log.error({ err, kind }, 'key generation failed');
      return reply.status(500).send({ error: 'internal_error' });
    }

    // Audit: keyId and kind only, never key material.
    request.log.info({ keyId: generated.keyId, kind }, 'key-generated');
    return reply.status(201).send(generated);
  });
}
