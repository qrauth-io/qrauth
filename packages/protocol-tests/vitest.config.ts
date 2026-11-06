import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["src/**/*.test.ts"],
    environment: "node",
    // Console output goes straight to stdout. Importing the signing service
    // pulls in queue.ts, whose BullMQ connections log Redis connection errors
    // asynchronously (no Redis in unit runs); through the intercept, a log
    // that lands while a test file is closing fails the run.
    disableConsoleIntercept: true,
    globals: false,
    setupFiles: ["./src/test-setup.ts"],
  },
});
