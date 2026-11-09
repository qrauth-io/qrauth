// Vitest setup file. Stubs the environment variables that
// `packages/api/src/lib/config.ts` parses at import time, so test files that
// transitively import API modules (signing service, hybrid service) don't
// blow up on missing real-deployment config. The values are intentionally
// fake — no test in this suite makes a real DB or Redis connection.

process.env.DATABASE_URL ??= "postgresql://test:test@localhost:5432/test";
process.env.REDIS_URL ??= "redis://localhost:6379";
process.env.JWT_SECRET ??= "test-jwt-secret-not-for-production-use-only";
process.env.NODE_ENV ??= "test";
