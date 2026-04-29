/**
 * Verify hot-path micro-benchmark (AUDIT-FINDING-001).
 *
 * Measures the cryptographic cost of `verifyRowSignatures` — the decision
 * tree that runs on every `GET /:token` request after Finding-001. The
 * audit's acceptance criterion is P95 < 50 ms on a representative dev
 * machine, 1,000 iterations.
 *
 * What this measures:
 *   - HMAC-SHA3-256 MAC recomputation + constant-time compare (MAC leg)
 *   - ECDSA-P256 signature verification (ECDSA leg)
 *   - Merkle inclusion proof (sha3 walk)
 *   - SLH-DSA-SHA2-128s batch-root verification — with the process-local
 *     LRU cache enabled after the first call, mirroring steady-state.
 *
 * What this does NOT measure:
 *   - Fastify routing, JSON encoding, rate limiting, cache lookups
 *   - Prisma DB reads (the batch + signingKey rows). In production these
 *     are co-located and dominate by <1 ms; the audit budget does not
 *     include DB latency.
 *
 * Usage:
 *   cd packages/api
 *   npx tsx --env-file=.env test/bench/verify.bench.ts
 *
 * Exits with code 1 if P95 exceeds the 50 ms budget.
 */
import { generateKeyPairSync, createHmac } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import {
  verifyRowSignatures,
  type SignatureVerifyRow,
  type SignatureVerifyDeps,
} from '../../src/routes/verify-signatures.js';
import {
  slhDsaGenerateKeyPair,
  slhDsaSign,
  slhDsaVerify,
} from '../../src/services/slhdsa-adapter.js';
import {
  computeLeafHash,
  buildMerkleTree,
  getMerklePath,
  verifyMerkleProof,
  type QRPayloadInput,
} from '../../src/services/merkle-signing.js';
import { __test_signPayload as signPayload, verifySignature } from '../../src/lib/crypto.js';
import {
  canonicalizeCore,
  canonicalGeoHash,
  computeDestHash,
  ALG_VERSION_POLICY,
} from '@qrauth/shared';
import { __resetBatchRootCache } from '../../src/services/hybrid-signing.js';

const ITERATIONS = 1000;
const P95_BUDGET_MS = 50;

interface Percentiles { p50: number; p95: number; p99: number; mean: number; min: number; max: number; }

function percentiles(samples: number[]): Percentiles {
  const sorted = [...samples].sort((a, b) => a - b);
  const idx = (p: number) => sorted[Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length))];
  return {
    p50: idx(50),
    p95: idx(95),
    p99: idx(99),
    mean: sorted.reduce((a, b) => a + b, 0) / sorted.length,
    min: sorted[0],
    max: sorted[sorted.length - 1],
  };
}

async function main() {
  console.log('--- bench verify hot path (AUDIT-FINDING-001) ---');

  // 1. Mint real keys.
  const { privateKey: ecdsaPrivPem, publicKey: ecdsaPubPem } = generateKeyPairSync('ec', {
    namedCurve: 'P-256',
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    publicKeyEncoding: { type: 'spki', format: 'pem' },
  });
  const slhdsa = await slhDsaGenerateKeyPair();
  const macSecret = Buffer.from('0'.repeat(64), 'hex');

  // 2. Build a hybrid-signed QR payload end-to-end using the unified
  //    canonical core (AUDIT-FINDING-011).
  const token = 'bench-tok-1';
  const destinationUrl = 'https://bench.qrauth.test/r/abc';
  const expiresAtStr = '';
  const tenantId = 'org-bench';
  const contentType = 'url';
  const contentHashHex = '';

  const destHash = await computeDestHash(contentType, destinationUrl, contentHashHex);
  const geoHash = await canonicalGeoHash(null, null, null);
  const coreCanonical = canonicalizeCore({
    algVersion: ALG_VERSION_POLICY.hybrid,
    token,
    tenantId,
    destHash,
    geoHash,
    expiresAt: expiresAtStr,
  });
  const ecdsaSignature = signPayload(ecdsaPrivPem, coreCanonical);

  // Merkle leg: 1-leaf batch, sign the root with SLH-DSA. The leaf hash
  // agrees with the MAC/ECDSA input modulo the trailing nonce.
  const merklePayload: QRPayloadInput = {
    algVersion: ALG_VERSION_POLICY.hybrid,
    token,
    tenantId,
    contentType,
    destinationUrl,
    contentHashHex,
    lat: null,
    lng: null,
    radiusM: null,
    expiresAt: expiresAtStr,
  };
  const leafNonce = '01'.repeat(32);
  const leafHash = await computeLeafHash(merklePayload, leafNonce);
  const { root, tree } = buildMerkleTree([leafHash]);
  const merklePath = getMerklePath(tree, 0);
  const rootSignature = await slhDsaSign(slhdsa.privateKey, Buffer.from(root, 'hex'));

  // Sanity: one-shot verify end-to-end before benching.
  const preEcdsa = verifySignature(ecdsaPubPem, ecdsaSignature, coreCanonical);
  const preMerkle = verifyMerkleProof(leafHash, merklePath, root);
  const preSlh = await slhDsaVerify(slhdsa.publicKey, Buffer.from(root, 'hex'), rootSignature);
  if (!preEcdsa || !preMerkle || !preSlh) {
    console.error('pre-flight verify failed:', { preEcdsa, preMerkle, preSlh });
    process.exit(2);
  }

  // 3. MAC over the same canonical core.
  const macTokenMac = createHmac('sha3-256', macSecret)
    .update(`qrauth:mac:v1:${coreCanonical}`)
    .digest('hex');

  // 4. Build the row + deps for verifyRowSignatures.
  const row: SignatureVerifyRow = {
    token,
    organizationId: tenantId,
    macTokenMac,
    macKeyVersion: 1,
    algVersion: 'hybrid-ecdsa-slhdsa-v1',
    merkleBatchId: 'bench-batch-1',
    merkleLeafHash: leafHash,
    merklePath,
    signature: ecdsaSignature,
    signingKey: { publicKey: ecdsaPubPem },
  };

  const deps: SignatureVerifyDeps = {
    verifyMac: async ({ canonicalPayload, storedMac }) => {
      const expected = createHmac('sha3-256', macSecret)
        .update(`qrauth:mac:v1:${canonicalPayload}`)
        .digest('hex');
      if (expected.length !== storedMac.length) return false;
      return Buffer.from(expected, 'hex').equals(Buffer.from(storedMac, 'hex'));
    },
    verifyEcdsa: (pub, sig, canonical) => verifySignature(pub, sig, canonical),
    verifyHybridLeg: async ({ leafHash: lh, merklePath: path, batchId }) => {
      const merkleOk = verifyMerkleProof(lh, path, root);
      if (!merkleOk) return { ok: false, reason: 'MERKLE_PROOF_INVALID' };
      // The real service consults an in-process LRU keyed by batchId. We
      // call slhDsaVerify on the first hit only; subsequent hits skip it,
      // matching steady-state production behaviour.
      if (!cacheHit.has(batchId)) {
        const slhOk = await slhDsaVerify(
          slhdsa.publicKey,
          Buffer.from(root, 'hex'),
          rootSignature,
        );
        if (!slhOk) return { ok: false, reason: 'BATCH_SIGNATURE_INVALID' };
        cacheHit.add(batchId);
      }
      return { ok: true };
    },
  };
  const cacheHit = new Set<string>();
  __resetBatchRootCache(); // real cache isn't consulted here but keep parity

  // 5. Warm-up — not counted. Also populates the batch-root cache so the
  // measured runs reflect steady-state, which is what the 50 ms budget is
  // against. A separate cold-path measurement runs first so we can report
  // both numbers side-by-side.
  const cold = performance.now();
  const outCold = await verifyRowSignatures(row, coreCanonical, deps);
  const coldMs = performance.now() - cold;
  if (!outCold.signatureValid) {
    console.error('cold verify returned signatureValid=false:', outCold);
    process.exit(2);
  }

  for (let i = 0; i < 20; i++) {
    await verifyRowSignatures(row, coreCanonical, deps);
  }

  // 6. Bench loop.
  const samples: number[] = new Array(ITERATIONS);
  for (let i = 0; i < ITERATIONS; i++) {
    const t0 = performance.now();
    const out = await verifyRowSignatures(row, coreCanonical, deps);
    const t1 = performance.now();
    samples[i] = t1 - t0;
    if (!out.signatureValid) {
      console.error(`iteration ${i} returned signatureValid=false`);
      process.exit(2);
    }
  }

  const stats = percentiles(samples);
  console.log(`iterations:      ${ITERATIONS}`);
  console.log(`cold (1st call): ${coldMs.toFixed(3)} ms (includes SLH-DSA verify)`);
  console.log('steady-state latency (ms):');
  console.log(`  mean           ${stats.mean.toFixed(3)}`);
  console.log(`  p50            ${stats.p50.toFixed(3)}`);
  console.log(`  p95            ${stats.p95.toFixed(3)}`);
  console.log(`  p99            ${stats.p99.toFixed(3)}`);
  console.log(`  min / max      ${stats.min.toFixed(3)} / ${stats.max.toFixed(3)}`);
  console.log('--------------------------------------------');
  console.log(`budget:          p95 < ${P95_BUDGET_MS} ms`);

  if (stats.p95 > P95_BUDGET_MS) {
    console.error(`FAIL: p95 ${stats.p95.toFixed(3)} ms exceeds budget ${P95_BUDGET_MS} ms`);
    process.exit(1);
  }
  console.log('PASS');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
