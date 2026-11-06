import { defineConfig } from 'vitest/config';

// Node-environment tests for @qrauth/shared. The same golden SVG files are
// also checked from the web package's browser-like test environment
// (packages/web/src/qr-render-golden.test.ts).
export default defineConfig({
  test: {
    environment: 'node',
    include: ['src/**/__tests__/**/*.test.ts'],
  },
});
