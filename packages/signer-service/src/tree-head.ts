import { createHash } from 'node:crypto';
import type { FastifyInstance } from 'fastify';
import { constantTimeEqual, sha256Hasher, treeHeadMessage, verifyConsistency } from '@qrauth/merkle-log';
import type { SlhDsaImplementation } from './slh-dsa.js';
import {
  isValidLogId,
  MasterKeyMissingError,
  readTreeHeadState,
  TreeHeadStateError,
  writeTreeHeadState,
  type LogState,
} from './tree-head-store.js';
import { loadTreeHeadSecretKey, publicKeyOf, TreeHeadKeyError } from './tree-head-key.js';

/**
 * POST /v1/sign-tree-head (ADR-0009 D7).
 *
 * Body: exactly { logId, treeSize, rootHash, fromSize, consistencyProof }.
 * rootHash and every proof node are canonical base64 of 32 bytes.
 *
 * The signer signs only when:
 *   - fromSize equals the stored lastSize, and
 *   - treeSize == lastSize with rootHash == lastRoot and no proof (re-sign of
 *     the same head), or
 *   - lastSize == 0 (genesis): any treeSize >= 0, no proof (the empty tree is
 *     a prefix of every tree), or
 *   - treeSize > lastSize and the RFC 9162 consistency proof from
 *     (lastSize, lastRoot) to (treeSize, rootHash) verifies.
 *
 * It signs prefix || logId || u64be(treeSize) || rootHash || u64be(signedAtMs)
 * with the platform SLH-DSA key, persists the new state, and only then
 * returns { signature, signedAtMs, keyId, treeSize }. A crash after the write
 * but before the response is recovered by re-signing the same head.
 */

const ROOT_BYTES = 32;
const MAX_PROOF_NODES = 64;
const BODY_KEYS = ['consistencyProof', 'fromSize', 'logId', 'rootHash', 'treeSize'];

export interface SignTreeHeadRequest {
  logId: string;
  treeSize: number;
  rootHash: Uint8Array;
  fromSize: number;
  consistencyProof: Uint8Array[];
}

export type TreeHeadDecision =
  | { ok: true; kind: 'genesis' | 'extension' | 'resign' }
  | { ok: false; error: 'stale_from_size' | 'not_an_extension' | 'equivocation' | 'unexpected_proof' | 'inconsistent' };

function decodeHash(value: unknown): Uint8Array | null {
  if (typeof value !== 'string') return null;
  const bytes = Buffer.from(value, 'base64');
  if (bytes.length !== ROOT_BYTES || bytes.toString('base64') !== value) return null;
  return new Uint8Array(bytes);
}

function isSafeIndex(v: unknown): v is number {
  return typeof v === 'number' && Number.isSafeInteger(v) && v >= 0;
}

/** Strict body validation; null for anything malformed. */
export function parseSignTreeHeadBody(body: unknown): SignTreeHeadRequest | null {
  if (typeof body !== 'object' || body === null || Array.isArray(body)) return null;
  const b = body as Record<string, unknown>;
  const keys = Object.keys(b).sort();
  if (keys.length !== BODY_KEYS.length || keys.some((k, i) => k !== BODY_KEYS[i])) return null;
  if (!isValidLogId(b.logId) || !isSafeIndex(b.treeSize) || !isSafeIndex(b.fromSize)) return null;
  const rootHash = decodeHash(b.rootHash);
  if (!rootHash) return null;
  if (!Array.isArray(b.consistencyProof) || b.consistencyProof.length > MAX_PROOF_NODES) return null;
  const proof = b.consistencyProof.map(decodeHash);
  if (proof.some((p) => p === null)) return null;
  return { logId: b.logId, treeSize: b.treeSize, rootHash, fromSize: b.fromSize, consistencyProof: proof as Uint8Array[] };
}

/** The D7 rules, without I/O. */
export function decideTreeHead(log: LogState, req: SignTreeHeadRequest): TreeHeadDecision {
  if (req.fromSize !== log.lastSize) return { ok: false, error: 'stale_from_size' };
  if (req.treeSize < log.lastSize) return { ok: false, error: 'not_an_extension' };
  if (req.treeSize === log.lastSize) {
    if (!constantTimeEqual(req.rootHash, log.lastRoot)) return { ok: false, error: 'equivocation' };
    if (req.consistencyProof.length > 0) return { ok: false, error: 'unexpected_proof' };
    return { ok: true, kind: 'resign' };
  }
  if (log.lastSize === 0) {
    if (req.consistencyProof.length > 0) return { ok: false, error: 'unexpected_proof' };
    return { ok: true, kind: 'genesis' };
  }
  const consistent = verifyConsistency(sha256Hasher, {
    oldSize: log.lastSize,
    newSize: req.treeSize,
    oldRoot: log.lastRoot,
    newRoot: req.rootHash,
    proof: req.consistencyProof,
  });
  return consistent ? { ok: true, kind: 'extension' } : { ok: false, error: 'inconsistent' };
}

export interface TreeHeadRouteOptions {
  keysDir: string;
  slhDsa: () => SlhDsaImplementation;
  /** Test seam for the signer clock. */
  now?: () => number;
}

export function registerTreeHeadRoute(app: FastifyInstance, opts: TreeHeadRouteOptions): void {
  const now = opts.now ?? Date.now;
  const keyCache = new Map<string, Uint8Array>();
  let queue: Promise<unknown> = Promise.resolve();

  // One head at a time: read state, decide, sign, persist.
  const serialized = <T>(fn: () => Promise<T>): Promise<T> => {
    const run = queue.then(fn, fn);
    queue = run.catch(() => {});
    return run;
  };

  async function secretKey(keyId: string): Promise<Uint8Array> {
    const cached = keyCache.get(keyId);
    if (cached) return cached;
    const secret = await loadTreeHeadSecretKey(opts.keysDir, keyId);
    keyCache.set(keyId, secret);
    return secret;
  }

  app.post('/v1/sign-tree-head', async (request, reply) => {
    const req = parseSignTreeHeadBody(request.body);
    if (!req) return reply.status(400).send({ error: 'malformed_request' });

    return serialized(async () => {
      let log: LogState | undefined;
      let logs: Record<string, LogState>;
      try {
        ({ logs } = await readTreeHeadState(opts.keysDir));
        log = logs[req.logId];
      } catch (err) {
        if (err instanceof TreeHeadStateError) {
          request.log.error({ event: 'tree-head-refused', reason: err.code }, err.message);
          return reply.status(503).send({ error: err.code });
        }
        if (err instanceof MasterKeyMissingError) {
          request.log.error({ event: 'tree-head-refused', reason: 'master_key_missing' }, err.message);
          return reply.status(503).send({ error: 'master_key_missing' });
        }
        throw err;
      }
      if (!log) return reply.status(404).send({ error: 'unknown_log' });

      const decision = decideTreeHead(log, req);
      if (!decision.ok) {
        request.log.warn(
          { event: 'tree-head-refused', reason: decision.error, logId: req.logId, lastSize: log.lastSize, treeSize: req.treeSize, fromSize: req.fromSize },
          'tree head refused',
        );
        return reply.status(409).send({ error: decision.error });
      }

      const signedAtMs = now();
      if (signedAtMs < log.lastSignedAtMs) {
        request.log.error({ event: 'tree-head-refused', reason: 'clock_regressed', lastSignedAtMs: log.lastSignedAtMs, signedAtMs }, 'signer clock is behind the last signed head');
        return reply.status(503).send({ error: 'clock_regressed' });
      }

      let secret: Uint8Array;
      try {
        secret = await secretKey(log.keyId);
      } catch (err) {
        if (err instanceof TreeHeadKeyError) {
          request.log.error({ event: 'tree-head-refused', reason: 'key_unavailable', keyId: log.keyId }, err.message);
          return reply.status(503).send({ error: 'tree_head_key_unavailable' });
        }
        throw err;
      }

      const message = treeHeadMessage({ logId: req.logId, treeSize: req.treeSize, rootHash: req.rootHash, signedAtMs });
      const impl = opts.slhDsa();
      const signature = impl.sign(message, secret);
      // Never persist or return a signature that does not verify (fault check).
      if (!impl.verify(signature, message, publicKeyOf(secret))) {
        request.log.error({ event: 'tree-head-refused', reason: 'self_verify_failed', keyId: log.keyId }, 'tree-head signature failed self-verification');
        return reply.status(500).send({ error: 'signing_failed' });
      }

      await writeTreeHeadState(opts.keysDir, {
        logs: { ...logs, [req.logId]: { keyId: log.keyId, lastSize: req.treeSize, lastRoot: req.rootHash, lastSignedAtMs: signedAtMs } },
      });

      request.log.info(
        {
          event: 'tree-head-signed',
          kind: decision.kind,
          logId: req.logId,
          treeSize: req.treeSize,
          fromSize: req.fromSize,
          keyId: log.keyId,
          signedAtMs,
          headFingerprint: createHash('sha256').update(message).digest('hex'),
        },
        'tree-head-signed',
      );
      return { signature: Buffer.from(signature).toString('base64'), signedAtMs, keyId: log.keyId, treeSize: req.treeSize };
    });
  });
}
