import { readFile, writeFile, rename, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { timingSafeEqual, createHash, createSign, randomBytes } from 'node:crypto';
import Fastify from 'fastify';
import { slh_dsa_sha2_128s } from '@noble/post-quantum/slh-dsa.js';
import { decryptAtRest } from './key-at-rest.js';
import {
  SIGNER_ECDSA_CANONICAL_PREFIX,
  SIGNER_MERKLE_ROOT_PREFIX,
} from './domain-separation.js';

/**
 * QRAuth standalone SLH-DSA signer service (ALGORITHM.md §13.1).
 *
 * Holds the SLH-DSA private keys on its own disk. Exposes a narrow HTTP
 * surface so the API server can request signatures without ever holding
 * key bytes itself.
 *
 * Production deployment topology:
 *
 *   [ API server, public network ]   →   [ this signer, private network ]
 *      sees public keys + signatures        sees private bytes
 *      no inbound internet on the signer side
 *
 * A compromise of the API box yields zero key material because the
 * private bytes only ever live on this process's filesystem.
 *
 * Auth: Bearer token in the `Authorization` header. The token is a
 * shared secret pinned in env on both sides. mTLS is the right answer
 * for hardening but adds rotation/CA complexity that doesn't belong in
 * the same patch as the signer split. Treat this as MVP and upgrade
 * later — the wire format above stays the same.
 *
 * Audit: every sign request is logged to stderr with timestamp, keyId,
 * message hash prefix, and result. Persistent audit log is a follow-up;
 * stderr piped to journald / Docker logs is enough for MVP forensics.
 *
 * Key storage: same on-disk layout as the API server's existing
 * `${SIGNER_KEYS_DIR}/${keyId}.slhdsa.key` (base64-encoded raw secret
 * key bytes). On first prod deploy operators move the .slhdsa.key files
 * from the API server to the signer host and set SIGNER_KEYS_DIR to the
 * new location. The API server's local files can then be deleted.
 */

const PORT = Number.parseInt(process.env.SIGNER_PORT ?? '7788', 10);
const HOST = process.env.SIGNER_HOST ?? '127.0.0.1';
const KEYS_DIR = process.env.SIGNER_KEYS_DIR ?? './keys';
const TOKEN = process.env.SIGNER_TOKEN ?? '';

if (!TOKEN || TOKEN.length < 32) {
  process.stderr.write(
    '[signer-service] SIGNER_TOKEN must be set to a value at least 32 characters long. Refusing to start.\n',
  );
  process.exit(1);
}

// Audit-3 H-5: dual-token support for zero-downtime rotation.
// SIGNER_TOKEN_NEXT is optional. When set, both tokens are accepted.
// Rotation procedure:
//   1. Generate new token, set SIGNER_TOKEN_NEXT on signer, restart signer
//   2. Update API server's ECDSA_SIGNER_TOKEN / SLH_DSA_SIGNER_TOKEN to new value
//   3. Restart API server (now sends new token)
//   4. Remove SIGNER_TOKEN_NEXT, promote new token to SIGNER_TOKEN, restart signer
const TOKEN_NEXT = process.env.SIGNER_TOKEN_NEXT ?? '';
const expectedTokens: Buffer[] = [Buffer.from(TOKEN, 'utf8')];
if (TOKEN_NEXT && TOKEN_NEXT.length >= 32) {
  expectedTokens.push(Buffer.from(TOKEN_NEXT, 'utf8'));
}

// In-memory cache of loaded private keys. We accept the memory exposure
// risk on the signer host (which is what this whole service is for —
// it's the one place private bytes live) in exchange for sub-millisecond
// load latency on the hot path. The cache is per-process; restarting
// the signer reloads from disk on the next request.
const keyCache = new Map<string, Buffer>();

async function loadPrivateKey(keyId: string): Promise<Buffer> {
  const cached = keyCache.get(keyId);
  if (cached) return cached;

  // Defend against path traversal: keyIds must look like UUIDs / hex
  // strings, not paths. Anything outside [a-zA-Z0-9._-] is rejected.
  if (!/^[a-zA-Z0-9._-]+$/.test(keyId)) {
    throw new SignerError('invalid_key_id', 400);
  }

  const encPath = join(KEYS_DIR, `${keyId}.slhdsa.enc`);
  let envelope: string;
  try {
    envelope = await readFile(encPath, 'utf8');
  } catch {
    throw new SignerError('key_not_found', 404);
  }

  let secret: Buffer;
  try {
    secret = decryptAtRest(envelope.trim());
  } catch {
    throw new SignerError('key_corrupted', 500);
  }
  if (secret.length !== 64) {
    // SLH-DSA-SHA2-128s secret keys are exactly 64 bytes per FIPS 205.
    throw new SignerError('key_corrupted', 500);
  }
  keyCache.set(keyId, secret);
  return secret;
}

const ecdsaKeyCache = new Map<string, string>();

async function loadEcdsaPem(keyId: string): Promise<string> {
  const cached = ecdsaKeyCache.get(keyId);
  if (cached) return cached;

  if (!/^[a-zA-Z0-9._-]+$/.test(keyId)) {
    throw new SignerError('invalid_key_id', 400);
  }

  const encPath = join(KEYS_DIR, `${keyId}.ecdsa.enc`);
  let envelope: string;
  try {
    envelope = await readFile(encPath, 'utf8');
  } catch {
    throw new SignerError('key_not_found', 404);
  }

  let pem: string;
  try {
    pem = decryptAtRest(envelope.trim()).toString('utf8');
  } catch {
    throw new SignerError('key_corrupted', 500);
  }
  if (!pem.includes('-----BEGIN')) {
    // Treat as corrupted — plaintext PEMs round-trip here and still
    // contain the header, so anything missing it is suspect.
    throw new SignerError('key_corrupted', 500);
  }
  ecdsaKeyCache.set(keyId, pem);
  return pem;
}

class SignerError extends Error {
  constructor(public code: string, public status: number) {
    super(code);
  }
}

const app = Fastify({
  logger: {
    level: process.env.LOG_LEVEL ?? 'info',
    transport: process.env.LOG_PRETTY === 'true' ? { target: 'pino-pretty' } : undefined,
  },
});

// Auth hook: every request must carry a Bearer token matching the
// expected secret. Constant-time comparison defends against timing
// oracles even though the surface is tiny.
app.addHook('onRequest', async (request, reply) => {
  // Allow the unauthenticated health check so orchestration can probe
  // liveness without holding the token.
  if (request.url === '/healthz') return;

  const header = request.headers.authorization ?? '';
  const match = header.match(/^Bearer (.+)$/);
  if (!match) {
    return reply.status(401).send({ error: 'unauthorized' });
  }
  const provided = Buffer.from(match[1], 'utf8');

  // Audit-3 H-5: check against all accepted tokens (primary + rotation next).
  let authenticated = false;
  for (const expected of expectedTokens) {
    if (provided.length === expected.length && timingSafeEqual(provided, expected)) {
      authenticated = true;
      break;
    }
  }
  if (!authenticated) {
    return reply.status(401).send({ error: 'unauthorized' });
  }
});

app.get('/healthz', async () => ({ status: 'ok', service: 'qrauth-signer' }));

interface SignBody {
  keyId: string;
  message: string;
}

app.post<{ Body: SignBody }>('/v1/sign', async (request, reply) => {
  const { keyId, message } = request.body ?? ({} as SignBody);
  if (typeof keyId !== 'string' || typeof message !== 'string') {
    return reply.status(400).send({ error: 'malformed_request' });
  }

  let secret: Buffer;
  try {
    secret = await loadPrivateKey(keyId);
  } catch (err) {
    if (err instanceof SignerError) {
      return reply.status(err.status).send({ error: err.code });
    }
    request.log.error({ err }, 'unexpected key load failure');
    return reply.status(500).send({ error: 'internal_error' });
  }

  const messageBytes = Buffer.from(message, 'base64');
  // AUDIT-FINDING-010: sign the prefixed bytes, not the raw caller
  // input. The prefix is constant and well-known so legitimate verifiers
  // reconstruct it; an attacker who compromises the bearer token can
  // still ask the signer to sign, but only under this one domain, which
  // maps to one intended use (SLH-DSA root over a Merkle batch).
  const prefixedMessage = Buffer.concat([SIGNER_MERKLE_ROOT_PREFIX, messageBytes]);
  const signature = slh_dsa_sha2_128s.sign(prefixedMessage, secret);

  // Audit log (AUDIT-FINDING-022): enough context to reconstruct what
  // was signed without logging the key material itself. The previous
  // 16-byte messagePrefix was too short for forensic non-repudiation —
  // two colliding Merkle roots at the 128-bit prefix would be
  // indistinguishable in the log. The full SHA3-256 fingerprint is
  // 64 hex characters and adds negligible log volume.
  request.log.info(
    {
      keyId,
      messageFingerprint: createHash('sha3-256').update(messageBytes).digest('hex'),
      messageBytes: messageBytes.length,
      signatureBytes: signature.length,
    },
    'signed',
  );

  return { signature: Buffer.from(signature).toString('base64') };
});

/**
 * AUDIT-FINDING-016: ECDSA sign endpoint. Replaces the API server's
 * in-process `signCanonical` readFile path. The signer service
 * decrypts the PEM envelope, signs the caller-supplied UTF-8 message
 * with SHA-256 + ECDSA-P256, and returns a base64 DER signature.
 *
 * AUDIT-2 N-2: the signer prepends `qrauth:ecdsa-canonical:v1:` to the
 * caller-supplied message before feeding it to `createSign`. The
 * canonical form already carries an `algVersion` field, but the verify
 * path of a compromised bearer token would happily sign any UTF-8 blob
 * without this tag — a forged approval, a forged proximity JWT header,
 * anything. Pinning the domain here means the signer can only produce
 * signatures that verify against the ECDSA-canonical domain, full stop.
 */
interface SignEcdsaBody {
  keyId: string;
  message: string; // UTF-8 string — the canonical payload to sign
}

app.post<{ Body: SignEcdsaBody }>('/v1/sign-ecdsa', async (request, reply) => {
  const { keyId, message } = request.body ?? ({} as SignEcdsaBody);
  if (typeof keyId !== 'string' || typeof message !== 'string') {
    return reply.status(400).send({ error: 'malformed_request' });
  }

  let pem: string;
  try {
    pem = await loadEcdsaPem(keyId);
  } catch (err) {
    if (err instanceof SignerError) {
      return reply.status(err.status).send({ error: err.code });
    }
    request.log.error({ err }, 'unexpected ecdsa key load failure');
    return reply.status(500).send({ error: 'internal_error' });
  }

  const prefixed = SIGNER_ECDSA_CANONICAL_PREFIX + message;
  const signer = createSign('SHA256');
  signer.update(prefixed, 'utf8');
  signer.end();
  const signature = signer.sign(pem, 'base64');

  request.log.info(
    {
      keyId,
      messageFingerprint: createHash('sha3-256').update(message, 'utf8').digest('hex'),
      messageBytes: Buffer.byteLength(message, 'utf8'),
      prefixedBytes: Buffer.byteLength(prefixed, 'utf8'),
      alg: 'ES256',
    },
    'signed-ecdsa',
  );

  return { signature };
});

app.get<{ Params: { keyId: string } }>(
  '/v1/keys/:keyId/public',
  async (request, reply) => {
    const { keyId } = request.params;
    let secret: Buffer;
    try {
      secret = await loadPrivateKey(keyId);
    } catch (err) {
      if (err instanceof SignerError) {
        return reply.status(err.status).send({ error: err.code });
      }
      throw err;
    }
    // SLH-DSA secret keys embed the public key in their second half
    // (per FIPS 205 §10.2). We could re-derive via the noble library
    // but pulling the bytes directly is simpler and matches the format
    // the noble keygen already emits.
    const publicKey = secret.subarray(32, 64);
    return {
      publicKey: Buffer.from(publicKey).toString('base64'),
      algorithm: 'slh-dsa-sha2-128s',
    };
  },
);

const FORMAT_TAG = 'qrauth-kek-v1';

interface ProvisionBody {
  ecdsa?: string;
  slhdsa?: string;
}

app.post<{ Params: { keyId: string }; Body: ProvisionBody }>(
  '/v1/keys/:keyId',
  async (request, reply) => {
    const { keyId } = request.params;

    if (!/^[a-zA-Z0-9._-]+$/.test(keyId)) {
      return reply.status(400).send({ error: 'invalid_key_id' });
    }

    const { ecdsa, slhdsa } = request.body ?? ({} as ProvisionBody);
    if (typeof ecdsa !== 'string' && typeof slhdsa !== 'string') {
      return reply.status(400).send({ error: 'malformed_request', message: 'at least one of ecdsa or slhdsa must be provided' });
    }

    const provisioned: string[] = [];

    for (const [kind, envelope] of [['ecdsa', ecdsa], ['slhdsa', slhdsa]] as const) {
      if (typeof envelope !== 'string') continue;

      if (!envelope.startsWith(FORMAT_TAG + '\0')) {
        return reply.status(400).send({ error: 'malformed_envelope', message: `${kind} envelope missing format tag` });
      }

      const ext = kind === 'ecdsa' ? 'ecdsa.enc' : 'slhdsa.enc';
      const filePath = join(KEYS_DIR, `${keyId}.${ext}`);

      try {
        await stat(filePath);
        return reply.status(409).send({ error: 'key_exists', message: `${kind} key already exists for ${keyId}` });
      } catch {
        // ENOENT — file does not exist, proceed
      }

      const tmp = `${filePath}.tmp.${randomBytes(8).toString('hex')}`;
      await writeFile(tmp, envelope, { mode: 0o600 });
      await rename(tmp, filePath);
      provisioned.push(kind);
    }

    // Clear caches so next sign request loads from disk
    keyCache.delete(keyId);
    ecdsaKeyCache.delete(keyId);

    request.log.info({ keyId, provisioned }, 'key-provisioned');
    return reply.status(201).send({ provisioned });
  },
);

const start = async () => {
  try {
    await app.listen({ port: PORT, host: HOST });
    app.log.info({ port: PORT, host: HOST, keysDir: KEYS_DIR }, 'qrauth-signer ready');
  } catch (err) {
    app.log.error(err, 'failed to start');
    process.exit(1);
  }
};

start();

const shutdown = async () => {
  try {
    await app.close();
  } catch (err) {
    process.stderr.write(`shutdown error: ${err}\n`);
  }
  process.exit(0);
};
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
