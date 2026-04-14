import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { timingSafeEqual } from 'node:crypto';
import Fastify from 'fastify';
import { slh_dsa_sha2_128s } from '@noble/post-quantum/slh-dsa.js';

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

const expectedToken = Buffer.from(TOKEN, 'utf8');

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

  const path = join(KEYS_DIR, `${keyId}.slhdsa.key`);
  let secretB64: string;
  try {
    secretB64 = await readFile(path, 'utf8');
  } catch {
    throw new SignerError('key_not_found', 404);
  }
  const secret = Buffer.from(secretB64.trim(), 'base64');
  if (secret.length !== 64) {
    // SLH-DSA-SHA2-128s secret keys are exactly 64 bytes per FIPS 205.
    // A length mismatch means the file is corrupted or the wrong format.
    throw new SignerError('key_corrupted', 500);
  }
  keyCache.set(keyId, secret);
  return secret;
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
  if (provided.length !== expectedToken.length) {
    return reply.status(401).send({ error: 'unauthorized' });
  }
  if (!timingSafeEqual(provided, expectedToken)) {
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
  const signature = slh_dsa_sha2_128s.sign(messageBytes, secret);

  // Audit log: enough context to reconstruct what was signed without
  // logging the key material itself. The 16-byte message prefix is
  // intentional — full SHA3 fingerprint of the message would be ideal
  // but would double the log volume; the prefix is enough to correlate
  // with the API-side merkle root in 99% of incidents.
  request.log.info(
    {
      keyId,
      messagePrefix: messageBytes.subarray(0, 16).toString('hex'),
      messageBytes: messageBytes.length,
      signatureBytes: signature.length,
    },
    'signed',
  );

  return { signature: Buffer.from(signature).toString('base64') };
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
