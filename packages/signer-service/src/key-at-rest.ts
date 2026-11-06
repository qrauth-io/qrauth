/**
 * At-rest encryption for on-disk key material (AUDIT-FINDING-016).
 *
 * The signer service and (via a mirror copy in the API package during
 * key generation) the API server write private bytes to disk. Previously
 * those bytes were stored as raw PEM or base64 — anyone with filesystem
 * read access to the signer host recovered key bytes directly. This
 * module wraps both halves in AES-256-GCM with a master key loaded from
 * `SIGNER_MASTER_KEY` at process startup. The envelope is:
 *
 *   envelope = `qrauth-kek-v1\0${base64(iv)}\0${base64(ciphertext)}\0${base64(authTag)}`
 *
 * The header tag pins the format version so a future KMS/HSM-backed
 * upgrade is a clean cutover. Envelopes without the tag are treated as
 * legacy plaintext and decrypt as-is — this is a transitional
 * convenience for pre-production. After the cutover the plaintext
 * branch should be removed.
 *
 * Master key provisioning: the env var holds a base64-encoded 32-byte
 * key today. Longer term this file is the single place to plug in an
 * AWS KMS `Decrypt` / Vault `transit/decrypt` call for the envelope
 * key, with the master key itself never leaving the KMS/HSM. The
 * module's call surface (`encrypt`/`decrypt`) stays the same.
 */
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

const FORMAT_TAG = 'qrauth-kek-v1';
const ALG = 'aes-256-gcm' as const;
const IV_BYTES = 12;
const KEY_BYTES = 32;

let cachedMasterKey: Buffer | null = null;

/**
 * Load the master key from `SIGNER_MASTER_KEY`. The value is base64 of
 * 32 raw bytes. Cached at process scope so repeated encrypt/decrypt
 * calls do not re-decode. Throws in production when missing.
 */
export function loadMasterKey(): Buffer {
  if (cachedMasterKey) return cachedMasterKey;
  const raw = process.env.SIGNER_MASTER_KEY;
  if (raw) {
    const bytes = Buffer.from(raw, 'base64');
    if (bytes.length !== KEY_BYTES) {
      throw new Error(
        `SIGNER_MASTER_KEY must decode to ${KEY_BYTES} bytes (base64 of 32 random bytes). Got ${bytes.length}.`,
      );
    }
    cachedMasterKey = bytes;
    return bytes;
  }
  if (process.env.NODE_ENV === 'production') {
    throw new Error(
      'SIGNER_MASTER_KEY is required in production (AUDIT-FINDING-016). ' +
        'Generate with `openssl rand -base64 32` and mount via the same secret-management path as JWT_SECRET.',
    );
  }
  // Dev/test fallback: deterministic-ish but still rotated per boot so
  // test runs do not share keys. Writes a warning to stderr so anyone
  // running in prod-shaped environments notices.
  process.stderr.write(
    '[signer-service] SIGNER_MASTER_KEY not set; using per-process random key. ' +
      'Dev/test only — set SIGNER_MASTER_KEY in production (AUDIT-FINDING-016).\n',
  );
  cachedMasterKey = randomBytes(KEY_BYTES);
  return cachedMasterKey;
}

/**
 * Encrypt the given bytes under the master key and return a
 * self-describing envelope string safe to write to disk.
 */
export function encryptAtRest(plaintext: Buffer): string {
  const key = loadMasterKey();
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv(ALG, key, iv);
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return [FORMAT_TAG, iv.toString('base64'), ct.toString('base64'), tag.toString('base64')].join('\0');
}

/**
 * Decrypt an envelope written by `encryptAtRest`. Throws on any input
 * that does not carry the format tag — plaintext pass-through was
 * removed at OP-3 cutover (Audit-2 N-3).
 */
export function decryptAtRest(envelope: string): Buffer {
  if (!envelope.startsWith(FORMAT_TAG + '\0')) {
    throw new Error('Malformed at-rest envelope: missing format tag');
  }
  const parts = envelope.split('\0');
  if (parts.length !== 4) {
    throw new Error('Malformed at-rest envelope');
  }
  const [, ivB64, ctB64, tagB64] = parts;
  const iv = Buffer.from(ivB64, 'base64');
  const ct = Buffer.from(ctB64, 'base64');
  const tag = Buffer.from(tagB64, 'base64');
  const key = loadMasterKey();
  const decipher = createDecipheriv(ALG, key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]);
}

/** Test-only: reset the cached master key so tests can set env afresh. */
export function __resetMasterKeyCache(): void {
  cachedMasterKey = null;
}
