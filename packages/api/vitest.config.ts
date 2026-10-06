import { defineConfig } from 'vitest/config';

/**
 * Vitest config for @qrauth/api.
 *
 * `setupFiles: ['dotenv/config']` loads `.env` from the package root so
 * tests that transitively import the bootstrap module graph (Prisma,
 * config validators, etc.) don't crash on missing env vars. Mirrors what
 * the dev script does via `tsx --env-file=.env` and the production
 * `node --env-file=.env` pattern.
 *
 * Without this, `npx vitest run` requires a shell wrapper like
 * `set -a; source .env; set +a; npx vitest run` — foff
 * debugging, friction for everyone else.
 */
export default defineConfig({
  test: {
    setupFiles: ['dotenv/config'],
    environment: 'node',
    // `test/**` covers files that don't sit alongside the code they exercise
    // (the `test/unit/` tree). `src/**` covers the co-located
    // `src/**/__tests__/` and `src/**/*.test.ts` files. Bench files in
    // `test/bench/**` deliberately use `.bench.ts` so they stay outside
    // the include glob and don't run on every `vitest run`.
    include: ['src/**/*.test.ts', 'test/**/*.test.ts'],
  },
});
