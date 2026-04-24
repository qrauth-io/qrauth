import { writeFile, rename, stat } from 'node:fs/promises';
import { join } from 'node:path';
import {
  timingSafeEqual,
  createHash,
  createHmac,
  createSign,
  hkdfSync,
  randomBytes,
} from 'node:crypto';
import Fastify from 'fastify';
import { slh_dsa_sha2_128s } from '@noble/post-quantum/slh-dsa.js';
import {
  MAC_HKDF_INFO_PREFIX,
  MAC_HKDF_SALT,
  SIGNER_ECDSA_CANONICAL_PREFIX,
  SIGNER_MERKLE_ROOT_PREFIX,
} from './domain-separation.js';
import { createKeyCaches, SignerKeyError } from './key-cache.js';
import { createMacSessionRegistry } from './mac-session-registry.js';

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

// Audit-4 A4-M2 Phase 0: the signer now derives animated-QR frame
// secrets on behalf of the API. The IKM for that HKDF derivation comes
// from `ANIMATED_QR_SECRET`, which must match the value the API host
// still uses for its legacy in-process path (Phase 1+ cutover). Refuse
// to start if it's missing or too short — same failure ergonomics as
// SIGNER_TOKEN above.
const ANIMATED_QR_SECRET = process.env.ANIMATED_QR_SECRET ?? '';
if (!ANIMATED_QR_SECRET || ANIMATED_QR_SECRET.length < 32) {
  process.stderr.write(
    '[signer-service] ANIMATED_QR_SECRET must be set to a value at least 32 characters long. Refusing to start.\n',
  );
  process.exit(1);
}

// Sweeper interval for the MAC session registry. Defaults to 60s; the
// registry clamps below 5s to keep the sweep from dominating CPU on a
// large registry.
const MAC_SWEEP_INTERVAL_MS = Number.parseInt(
  process.env.MAC_SWEEP_INTERVAL_MS ?? '60000',
  10,
);
const MAC_SESSION_MAX = Number.parseInt(
  process.env.MAC_SESSION_MAX ?? '100000',
  10,
);

// Key caches are bounded (CACHE_MAX) and TTL-capped (CACHE_TTL_MS) LRUs.
// See `./key-cache.ts` for the rationale and the hit/miss/eviction
// counters consumed by the `/internal/stats` endpoint below.
const {
  keyCache,
  ecdsaKeyCache,
  loadPrivateKey,
  loadEcdsaPem,
  snapshot: cachesSnapshot,
} = createKeyCaches(KEYS_DIR);

// A4-M2 Phase 0: animated-QR MAC session registry. The new /v1/mac/*
// endpoints below populate and read this; production traffic still
// runs the API-local path until Phase 1.
const macRegistry = createMacSessionRegistry({
  maxEntries: MAC_SESSION_MAX,
  sweepIntervalMs: MAC_SWEEP_INTERVAL_MS,
});
macRegistry.startSweeper();

// Per-endpoint counters for the /internal/stats `mac` surface.
// Registry-side counters (registered, conflicts, expired, evictedFull)
// come from macRegistry.stats(); these track endpoint-layer outcomes
// the registry itself doesn't see.
const macEndpointStats = {
  signCalls: 0,
  signMissing: 0,
  verifyOk: 0,
  verifyBad: 0,
  verifyMissing: 0,
};

function macStatsSnapshot() {
  const r = macRegistry.stats();
  return {
    sessions: macRegistry.size(),
    registered: r.registered,
    conflicts: r.conflicts,
    expired: r.expired,
    evictedFull: r.evictedFull,
    signCalls: macEndpointStats.signCalls,
    signMissing: macEndpointStats.signMissing,
    verifyOk: macEndpointStats.verifyOk,
    verifyBad: macEndpointStats.verifyBad,
    verifyMissing: macEndpointStats.verifyMissing,
  };
}

function deriveFrameSecret(sessionId: string): Buffer {
  // MUST match AnimatedQRService.deriveFrameSecret byte-for-byte. The
  // API returns this as hex; here we keep the raw 32 bytes because we
  // never round-trip through the wire — HMAC computation uses the
  // Buffer directly. The parity test in mac-parity.test.ts pins a
  // specific (secret, sessionId) → derived-key vector that both sides
  // must reproduce.
  return Buffer.from(
    hkdfSync(
      'sha256',
      ANIMATED_QR_SECRET,
      MAC_HKDF_SALT,
      `${MAC_HKDF_INFO_PREFIX}${sessionId}`,
      32,
    ),
  );
}

// Process start time for the stats endpoint's `uptimeSeconds`.
const startedAtMs = Date.now();

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

/**
 * Audit-4 A4-I1: introspection endpoint for the bounded/TTL-capped key
 * caches. Lives OUTSIDE the `/v1/*` namespace — `/v1/*` is reserved for
 * the stable wire contract the API server binds to (sign-ecdsa, sign,
 * keys/:keyId/public, POST keys/:keyId). Operational/observability
 * surfaces sit under `/internal/*` so their shape can evolve without a
 * protocol-version bump. Inherits the bearer-token `onRequest` hook
 * above — no route is added to the `/healthz`-style exemption list.
 * Counters are monotonic over process lifetime.
 */
app.get('/internal/stats', async () => ({
  ...cachesSnapshot(),
  mac: macStatsSnapshot(),
  uptimeSeconds: Math.floor((Date.now() - startedAtMs) / 1000),
}));

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
    if (err instanceof SignerKeyError) {
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
    if (err instanceof SignerKeyError) {
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

/**
 * Audit-4 A4-M2 Phase 0: animated-QR MAC session registration. The API
 * posts a fresh sessionId + binding; the signer derives the frame
 * secret via HKDF over ANIMATED_QR_SECRET and holds it in-memory until
 * ttlSeconds elapses. Idempotent on exact (binding, ttlSeconds) match.
 *
 * Phase 0 note: the API does NOT call this endpoint yet — production
 * still derives frame secrets locally. Phase 1 introduces the
 * MAC_BACKEND flag that flips traffic here.
 */
interface MacSessionBody {
  sessionId: string;
  binding: string;
  ttlSeconds: number;
}

const SESSION_ID_RE = /^[A-Za-z0-9_-]{1,128}$/;

app.post<{ Body: MacSessionBody }>('/v1/mac/session', async (request, reply) => {
  const { sessionId, binding, ttlSeconds } = request.body ?? ({} as MacSessionBody);
  if (
    typeof sessionId !== 'string' ||
    !SESSION_ID_RE.test(sessionId) ||
    typeof binding !== 'string' ||
    binding.length < 1 ||
    binding.length > 256 ||
    typeof ttlSeconds !== 'number' ||
    !Number.isInteger(ttlSeconds) ||
    ttlSeconds < 60 ||
    ttlSeconds > 3600
  ) {
    return reply.status(400).send({ error: 'malformed_request' });
  }

  const key = deriveFrameSecret(sessionId);
  const result = macRegistry.register(sessionId, binding, ttlSeconds, key);
  if (!result.ok) {
    if (result.reason === 'conflict') {
      return reply.status(409).send({ error: 'session_exists' });
    }
    return reply.status(503).send({ error: 'registry_full' });
  }
  return reply.status(200).send({
    registered: true,
    expiresAt: Math.floor(result.expiresAtMs / 1000),
  });
});

/**
 * Produce an 8-byte compact HMAC-SHA256 tag (16 hex chars) for the
 * supplied payload under the session's derived key. Mirrors the
 * current frame format generated by `AnimatedQRService`.
 */
interface MacSignBody {
  sessionId: string;
  payload: string; // base64
}

app.post<{ Body: MacSignBody }>('/v1/mac/sign', async (request, reply) => {
  const { sessionId, payload } = request.body ?? ({} as MacSignBody);
  if (typeof sessionId !== 'string' || typeof payload !== 'string') {
    return reply.status(400).send({ error: 'malformed_request' });
  }

  const entry = macRegistry.get(sessionId);
  if (!entry) {
    macEndpointStats.signMissing += 1;
    return reply.status(404).send({ error: 'session_not_found' });
  }

  let payloadBytes: Buffer;
  try {
    payloadBytes = Buffer.from(payload, 'base64');
  } catch {
    return reply.status(400).send({ error: 'malformed_request' });
  }

  const tag = createHmac('sha256', entry.key)
    .update(payloadBytes)
    .digest('hex')
    .slice(0, 16); // first 8 bytes, matching frame format

  macEndpointStats.signCalls += 1;
  return { tag };
});

/**
 * Constant-time verify of a supplied tag against the expected HMAC.
 * Never returns 404 on a bad tag — only on a missing/expired session
 * — so the endpoint cannot be used as an oracle that distinguishes
 * session-gone from bad-tag by a caller who compromised the bearer.
 */
interface MacVerifyBody {
  sessionId: string;
  payload: string; // base64
  tag: string; // hex
}

app.post<{ Body: MacVerifyBody }>('/v1/mac/verify', async (request, reply) => {
  const { sessionId, payload, tag } = request.body ?? ({} as MacVerifyBody);
  if (
    typeof sessionId !== 'string' ||
    typeof payload !== 'string' ||
    typeof tag !== 'string'
  ) {
    return reply.status(400).send({ error: 'malformed_request' });
  }

  const entry = macRegistry.get(sessionId);
  if (!entry) {
    macEndpointStats.verifyMissing += 1;
    return reply.status(404).send({ error: 'session_expired' });
  }

  let payloadBytes: Buffer;
  try {
    payloadBytes = Buffer.from(payload, 'base64');
  } catch {
    macEndpointStats.verifyBad += 1;
    return { valid: false };
  }

  const expected = createHmac('sha256', entry.key)
    .update(payloadBytes)
    .digest('hex')
    .slice(0, 16);

  // Length check before timingSafeEqual — it throws on length mismatch.
  // A wrong-length tag is a bad tag, not a malformed request.
  if (tag.length !== expected.length) {
    macEndpointStats.verifyBad += 1;
    return { valid: false };
  }

  const valid = timingSafeEqual(
    Buffer.from(tag, 'utf8'),
    Buffer.from(expected, 'utf8'),
  );
  if (valid) macEndpointStats.verifyOk += 1;
  else macEndpointStats.verifyBad += 1;
  return { valid };
});

app.get<{ Params: { keyId: string } }>(
  '/v1/keys/:keyId/public',
  async (request, reply) => {
    const { keyId } = request.params;
    let secret: Buffer;
    try {
      secret = await loadPrivateKey(keyId);
    } catch (err) {
      if (err instanceof SignerKeyError) {
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
    macRegistry.stopSweeper();
    await app.close();
  } catch (err) {
    process.stderr.write(`shutdown error: ${err}\n`);
  }
  process.exit(0);
};
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
