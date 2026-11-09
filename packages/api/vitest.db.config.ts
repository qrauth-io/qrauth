import { defineConfig } from 'vitest/config';

/**
 * Database tests (ADR-0006 analytics SQL): run against a real, migrated
 * Postgres named by TEST_DATABASE_URL, whose database name must contain
 * "test" (the suite truncates tables). scripts/ci-verify.sh `db` stage.
 */
export default defineConfig({
  test: {
    environment: 'node',
    include: ['test/db/**/*.db-test.ts'],
    disableConsoleIntercept: true,
    fileParallelism: false,
    testTimeout: 60_000,
  },
});
