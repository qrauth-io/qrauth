import { describe, expect, it } from 'vitest';

import {
  isSemaphoreBusy,
  Semaphore,
  SemaphoreAbortedError,
  SemaphoreFullError,
  SemaphoreTimeoutError,
} from '../semaphore.js';

/** A task that runs until released, recording when it started. */
function blocker(log: string[], name: string): { task: () => Promise<string>; release: () => void } {
  let release!: () => void;
  const done = new Promise<void>((r) => {
    release = r;
  });
  return {
    task: async () => {
      log.push(name);
      await done;
      return name;
    },
    release,
  };
}

const tick = (): Promise<void> => new Promise((r) => setTimeout(r, 0));

const opts = { limit: 2, maxQueue: 3, timeoutMs: 60_000 };

describe('Semaphore', () => {
  it('runs at most `limit` tasks at once, in arrival order within a lane', async () => {
    const sem = new Semaphore(opts);
    const log: string[] = [];
    const tasks = ['a', 'b', 'c', 'd'].map((n) => blocker(log, n));
    const runs = tasks.map((t) => sem.run(t.task));
    await tick();
    expect(log).toEqual(['a', 'b']);
    expect([sem.inUse, sem.queued()]).toEqual([2, 2]);
    tasks[1].release();
    await tick();
    expect(log).toEqual(['a', 'b', 'c']);
    tasks.forEach((t) => t.release());
    expect(await Promise.all(runs)).toEqual(['a', 'b', 'c', 'd']);
    expect([sem.inUse, sem.queued()]).toEqual([0, 0]);
  });

  it('serves the issue lane before the export lane', async () => {
    const sem = new Semaphore({ ...opts, limit: 1 });
    const log: string[] = [];
    const holder = blocker(log, 'holder');
    const e1 = blocker(log, 'export-1');
    const i1 = blocker(log, 'issue-1');
    const all = [
      sem.run(holder.task),
      sem.run(e1.task, { lane: 'export' }),
      sem.run(i1.task, { lane: 'issue' }),
    ];
    await tick();
    holder.release();
    await tick();
    expect(log).toEqual(['holder', 'issue-1']);
    i1.release();
    await tick();
    expect(log).toEqual(['holder', 'issue-1', 'export-1']);
    e1.release();
    await Promise.all(all);
  });

  it('refuses at once when a lane queue is full; the other lane still queues', async () => {
    const sem = new Semaphore({ ...opts, limit: 1, maxQueue: 2 });
    const log: string[] = [];
    const holder = blocker(log, 'holder');
    const waiting = [blocker(log, 'e1'), blocker(log, 'e2')];
    const runs = [sem.run(holder.task), ...waiting.map((w) => sem.run(w.task, { lane: 'export' }))];
    await tick();
    const refused = sem.run(async () => 'never', { lane: 'export' });
    await expect(refused).rejects.toBeInstanceOf(SemaphoreFullError);
    await expect(refused).rejects.toSatisfy(isSemaphoreBusy);
    const issue = blocker(log, 'i1');
    const issueRun = sem.run(issue.task, { lane: 'issue' });
    expect(sem.queued('issue')).toBe(1);
    [holder, ...waiting, issue].forEach((b) => b.release());
    await Promise.all([...runs, issueRun]);
  });

  it('a waiter that gets no slot within timeoutMs is refused and leaves the queue', async () => {
    const sem = new Semaphore({ ...opts, limit: 1, timeoutMs: 30 });
    const log: string[] = [];
    const holder = blocker(log, 'holder');
    const held = sem.run(holder.task);
    let ran = false;
    const late = sem.run(async () => {
      ran = true;
    });
    await expect(late).rejects.toBeInstanceOf(SemaphoreTimeoutError);
    await expect(late).rejects.toSatisfy(isSemaphoreBusy);
    expect(sem.queued()).toBe(0);
    holder.release();
    await held;
    expect(ran).toBe(false);
  });

  it('an aborted waiter leaves the queue without running', async () => {
    const sem = new Semaphore({ ...opts, limit: 1 });
    const log: string[] = [];
    const holder = blocker(log, 'holder');
    const held = sem.run(holder.task);
    const controller = new AbortController();
    let ran = false;
    const waiting = sem.run(async () => {
      ran = true;
    }, { signal: controller.signal });
    await tick();
    expect(sem.queued()).toBe(1);
    controller.abort();
    await expect(waiting).rejects.toBeInstanceOf(SemaphoreAbortedError);
    expect(sem.queued()).toBe(0);
    holder.release();
    await held;
    expect(ran).toBe(false);
  });

  it('an already-aborted signal is refused without queueing', async () => {
    const sem = new Semaphore(opts);
    const controller = new AbortController();
    controller.abort();
    await expect(sem.run(async () => 1, { signal: controller.signal })).rejects.toBeInstanceOf(SemaphoreAbortedError);
    expect([sem.inUse, sem.queued()]).toEqual([0, 0]);
  });

  it('releases the slot when a task throws', async () => {
    const sem = new Semaphore({ ...opts, limit: 1 });
    await expect(sem.run(async () => {
      throw new Error('boom');
    })).rejects.toThrow('boom');
    expect(sem.inUse).toBe(0);
    expect(await sem.run(async () => 'next')).toBe('next');
  });

  it.each([
    { limit: 0, maxQueue: 1, timeoutMs: 1 },
    { limit: 1.5, maxQueue: 1, timeoutMs: 1 },
    { limit: 1, maxQueue: -1, timeoutMs: 1 },
    { limit: 1, maxQueue: 1, timeoutMs: 0 },
  ])('rejects options %o', (o) => {
    expect(() => new Semaphore(o)).toThrow();
  });
});
