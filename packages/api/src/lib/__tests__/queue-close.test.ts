import { describe, it, expect, vi } from 'vitest';

/**
 * T4-A: handle cleanup. `lib/queue.ts` constructs its named BullMQ queues at
 * module load, each holding an ioredis connection. Script callers (e.g.
 * scripts/bootstrap-platform-oidc-key.ts) import the service graph transitively
 * and so open those connections; `prisma.$disconnect()` does not release them,
 * which kept the bootstrap script alive after success. `closeQueues()` is the
 * releasable handle the script calls in its finally block.
 *
 * The load-bearing assertion: `closeQueues()` must both close every queue AND
 * disconnect every underlying ioredis connection. BullMQ's `queue.close()`
 * does not disconnect a caller-supplied connection, so closing queues alone
 * leaves the connections (and the event loop) alive — the bug this fix targets.
 *
 * `bullmq` + `ioredis` are mocked so importing `queue.ts` never touches Redis.
 * Spies are shared into the mock factories via `vi.hoisted` (factories hoist
 * above normal `const`s).
 */
const { closeSpies, disconnectSpies } = vi.hoisted(() => ({
  closeSpies: [] as Array<() => Promise<void>>,
  disconnectSpies: [] as Array<() => void>,
}));

vi.mock('bullmq', () => ({
  Queue: vi.fn().mockImplementation((name: string) => {
    const close = vi.fn(async () => {});
    closeSpies.push(close);
    return { name, add: vi.fn(async () => ({ id: 'job' })), close };
  }),
}));

vi.mock('ioredis', () => ({
  Redis: vi.fn().mockImplementation(() => {
    const disconnect = vi.fn(() => {});
    disconnectSpies.push(disconnect);
    return { disconnect, quit: vi.fn(async () => {}) };
  }),
}));

import { closeQueues } from '../queue.js';

describe('closeQueues — releasable BullMQ handles (T4-A)', () => {
  it('closes every queue and disconnects every connection so callers can exit', async () => {
    // queue.ts declares six named queues, each with its own connection.
    expect(closeSpies).toHaveLength(6);
    expect(disconnectSpies).toHaveLength(6);

    await closeQueues();

    for (const close of closeSpies) {
      expect(close).toHaveBeenCalledTimes(1);
    }
    // The fix: connections are disconnected, not just queues closed.
    for (const disconnect of disconnectSpies) {
      expect(disconnect).toHaveBeenCalledTimes(1);
    }
  });
});
