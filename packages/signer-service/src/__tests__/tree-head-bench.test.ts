import { describe, it, expect } from 'vitest';
import { randomBytes } from 'node:crypto';
import { slh_dsa_sha2_128s } from '@noble/post-quantum/slh-dsa.js';
import { TRUST_LOG_ORIGIN, sha256Hasher, treeHeadMessage } from '@qrauth/merkle-log';
import { isNativeSlhDsaAvailable, nativeImplementation, nobleImplementation, type SlhDsaImplementation } from '../slh-dsa.js';

/**
 * Tree-head signing latency (ADR-0009 D7): SLH-DSA-SHA2-128s over a real
 * tree-head message, 50 signatures per implementation, p50 / p95 in ms.
 * Opt-in (RUN_TREE_HEAD_BENCH=1): CI runs it in the Node 24 step
 * (scripts/ci-verify.sh signer24), where the built-in implementation the
 * signer host uses is available. Fresh throwaway key; no state, no I/O.
 */

const RUNS = 50;
const enabled = process.env.RUN_TREE_HEAD_BENCH === '1';

function percentile(sorted: number[], p: number): number {
  return sorted[Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1)];
}

function bench(impl: SlhDsaImplementation) {
  const { secretKey, publicKey } = slh_dsa_sha2_128s.keygen(randomBytes(48));
  const timings: number[] = [];
  for (let i = 0; i < RUNS; i++) {
    const message = treeHeadMessage({
      logId: TRUST_LOG_ORIGIN,
      treeSize: 1_000_000 + i,
      rootHash: sha256Hasher.hashLeaf(randomBytes(16)),
      signedAtMs: Date.now(),
    });
    const start = process.hrtime.bigint();
    const signature = impl.sign(message, secretKey);
    timings.push(Number(process.hrtime.bigint() - start) / 1e6);
    if (i === 0) expect(impl.verify(signature, message, publicKey)).toBe(true);
  }
  const sorted = [...timings].sort((a, b) => a - b);
  return { p50: percentile(sorted, 50), p95: percentile(sorted, 95), min: sorted[0], max: sorted[sorted.length - 1] };
}

describe.skipIf(!enabled)('tree-head signing latency', () => {
  const impls: SlhDsaImplementation[] = isNativeSlhDsaAvailable() ? [nativeImplementation, nobleImplementation] : [nobleImplementation];

  it.each(impls.map((i) => [i.name, i] as const))(`%s: ${RUNS} signatures`, (name, impl) => {
    const r = bench(impl);
    const line = `[tree-head-bench] impl=${name} node=${process.versions.node} runs=${RUNS} p50=${r.p50.toFixed(1)}ms p95=${r.p95.toFixed(1)}ms min=${r.min.toFixed(1)}ms max=${r.max.toFixed(1)}ms`;
    process.stdout.write(`${line}\n`);
    expect(r.p50).toBeGreaterThan(0);
  }, 600_000);
});
