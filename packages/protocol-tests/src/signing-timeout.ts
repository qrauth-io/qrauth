/**
 * Per-test timeout for tests that make real pure-JS SLH-DSA signatures
 * (@noble/post-quantum). One sign takes about 2-5 s depending on the CI
 * runner, close to vitest's 5 s default. Applied per describe block, only
 * where such signing happens; every other test keeps the default.
 */
export const PQ_SIGNING_TEST_TIMEOUT_MS = 30_000;
