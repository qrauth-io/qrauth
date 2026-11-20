import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { slh_dsa_sha2_128s } from '@noble/post-quantum/slh-dsa.js';
import { decryptAtRest, encryptAtRest } from './key-at-rest.js';
import { writeNewFile } from './durable-fs.js';
import { isValidKeyId, requireMasterKey } from './tree-head-store.js';

/**
 * The platform tree-head key (ADR-0009 D7): SLH-DSA-SHA2-128s, generated on
 * the signer host by the operator command genesis-init, never over HTTP.
 * Stored as `<keyId>.treehead.enc` (64-byte secret key, encrypted at rest).
 * The suffix differs from the tenant `.slhdsa.enc` envelopes, so the
 * merkle-root signing route and the public-key route cannot load it.
 */

export const TREE_HEAD_KEY_SUFFIX = '.treehead.enc';
const SEED_BYTES = 48;
const SECRET_KEY_BYTES = 64;

export class TreeHeadKeyError extends Error {}

function keyPath(keysDir: string, keyId: string): string {
  if (!isValidKeyId(keyId)) throw new TreeHeadKeyError(`invalid keyId ${JSON.stringify(keyId)}`);
  return join(keysDir, `${keyId}${TREE_HEAD_KEY_SUFFIX}`);
}

/** FIPS 205: the SLH-DSA secret key ends with the 32-byte public key. */
export function publicKeyOf(secretKey: Uint8Array): Uint8Array {
  return secretKey.slice(32, 64);
}

export function publicKeyFingerprint(publicKey: Uint8Array): string {
  return createHash('sha256').update(publicKey).digest('hex');
}

/** Generate and store a new tree-head key. Returns its id and public key. */
export async function generateTreeHeadKey(keysDir: string): Promise<{ keyId: string; publicKey: Uint8Array }> {
  requireMasterKey();
  const keyId = `tree-head-${randomUUID()}`;
  const pair = slh_dsa_sha2_128s.keygen(randomBytes(SEED_BYTES));
  await writeNewFile(keyPath(keysDir, keyId), encryptAtRest(Buffer.from(pair.secretKey)));
  return { keyId, publicKey: new Uint8Array(pair.publicKey) };
}

export async function loadTreeHeadSecretKey(keysDir: string, keyId: string): Promise<Uint8Array> {
  requireMasterKey();
  let envelope: string;
  try {
    envelope = await readFile(keyPath(keysDir, keyId), 'utf8');
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') throw new TreeHeadKeyError(`tree-head key ${keyId} not found`);
    throw err;
  }
  const secret = new Uint8Array(decryptAtRest(envelope));
  if (secret.length !== SECRET_KEY_BYTES) throw new TreeHeadKeyError(`tree-head key ${keyId} is malformed`);
  return secret;
}

/** Ids of every tree-head key in the keys directory. */
export async function listTreeHeadKeyIds(keysDir: string): Promise<string[]> {
  const names = await readdir(keysDir).catch(() => [] as string[]);
  return names.filter((n) => n.endsWith(TREE_HEAD_KEY_SUFFIX)).map((n) => n.slice(0, -TREE_HEAD_KEY_SUFFIX.length)).sort();
}
