import type { FastifyInstance } from 'fastify';
import { benchmarkSignatures, type SlhDsaSelection } from './slh-dsa.js';

/** Fixed sample size: not caller-controlled, so the route cannot be used to tie up the signer. */
export const BENCH_SIGNATURES = 5;

/**
 * POST /internal/slh-dsa-bench — times BENCH_SIGNATURES signatures of the
 * fixed self-test message with the public self-test key, using the active
 * implementation. Never touches a real key. Called once after a deploy by
 * scripts/deploy-signer.sh. Behind the app-wide bearer-token hook.
 *
 * Signing is synchronous, so the sample briefly delays concurrent sign
 * requests (about 1 s with the built-in implementation, longer with the
 * pure-JS fallback).
 */
export function registerSlhDsaBenchRoute(
  app: FastifyInstance,
  getSelection: () => SlhDsaSelection,
): void {
  app.post('/internal/slh-dsa-bench', async () => {
    const { implementation, nativeAvailable } = getSelection();
    const timingsMs = benchmarkSignatures(implementation, BENCH_SIGNATURES);
    const sorted = [...timingsMs].sort((a, b) => a - b);
    return {
      implementation: implementation.name,
      nativeAvailable,
      node: process.versions.node,
      openssl: process.versions.openssl,
      timingsMs,
      medianMs: sorted[Math.floor(sorted.length / 2)],
    };
  });
}
