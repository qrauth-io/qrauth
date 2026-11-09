/**
 * In-process limiter for CPU-heavy work such as PNG rasterisation (ADR-0005
 * D7): at most `limit` tasks run at once; the rest wait.
 *
 * Policy:
 * - Two lanes. `issue` (images in create and bulk-create responses) is always
 *   served before `export` (the image endpoint), so a burst of exports cannot
 *   starve code creation.
 * - Each lane holds at most `maxQueue` waiters; a full lane refuses at once
 *   (SemaphoreFullError).
 * - A waiter that has not started after `timeoutMs` is refused
 *   (SemaphoreTimeoutError).
 * - A waiter whose `signal` aborts (the client went away) leaves the queue
 *   without running (SemaphoreAbortedError). A task that has started runs to
 *   completion.
 */

export type Lane = 'issue' | 'export';

export class SemaphoreFullError extends Error {
  constructor(readonly lane: Lane) {
    super(`render queue (${lane}) is full`);
    this.name = 'SemaphoreFullError';
  }
}

export class SemaphoreTimeoutError extends Error {
  constructor(readonly lane: Lane, readonly timeoutMs: number) {
    super(`render queue (${lane}): no slot within ${timeoutMs} ms`);
    this.name = 'SemaphoreTimeoutError';
  }
}

export class SemaphoreAbortedError extends Error {
  constructor(readonly lane: Lane) {
    super(`render queue (${lane}): request aborted while waiting`);
    this.name = 'SemaphoreAbortedError';
  }
}

/** True for the errors that mean "busy, try again later" (503 + Retry-After). */
export function isSemaphoreBusy(err: unknown): err is SemaphoreFullError | SemaphoreTimeoutError {
  return err instanceof SemaphoreFullError || err instanceof SemaphoreTimeoutError;
}

export interface SemaphoreOptions {
  readonly limit: number;
  /** Waiters per lane before new callers are refused. */
  readonly maxQueue: number;
  /** Longest a caller waits for a slot. */
  readonly timeoutMs: number;
}

export interface RunOptions {
  readonly lane?: Lane;
  readonly signal?: AbortSignal;
}

interface Waiter {
  readonly lane: Lane;
  grant: () => void;
  cancel: (err: Error) => void;
}

export class Semaphore {
  private active = 0;
  private readonly lanes: Record<Lane, Waiter[]> = { issue: [], export: [] };

  constructor(private readonly options: SemaphoreOptions) {
    const { limit, maxQueue, timeoutMs } = options;
    if (!Number.isInteger(limit) || limit < 1) throw new Error('Semaphore limit must be a positive integer');
    if (!Number.isInteger(maxQueue) || maxQueue < 0) throw new Error('Semaphore maxQueue must be a non-negative integer');
    if (!(timeoutMs > 0)) throw new Error('Semaphore timeoutMs must be positive');
  }

  /** Runs `task` once a slot is free and releases the slot when it settles. */
  async run<T>(task: () => Promise<T>, opts: RunOptions = {}): Promise<T> {
    await this.acquire(opts.lane ?? 'export', opts.signal);
    try {
      return await task();
    } finally {
      this.release();
    }
  }

  /** Holders right now, for tests and metrics. */
  get inUse(): number {
    return this.active;
  }

  /** Waiters in a lane, or in both. */
  queued(lane?: Lane): number {
    return lane ? this.lanes[lane].length : this.lanes.issue.length + this.lanes.export.length;
  }

  private acquire(lane: Lane, signal: AbortSignal | undefined): Promise<void> {
    if (signal?.aborted) return Promise.reject(new SemaphoreAbortedError(lane));
    if (this.active < this.options.limit && this.queued() === 0) {
      this.active++;
      return Promise.resolve();
    }
    const queue = this.lanes[lane];
    if (queue.length >= this.options.maxQueue) return Promise.reject(new SemaphoreFullError(lane));

    return new Promise<void>((resolve, reject) => {
      let timer: ReturnType<typeof setTimeout> | undefined;
      const cleanup = (): void => {
        if (timer) clearTimeout(timer);
        signal?.removeEventListener('abort', onAbort);
        const at = queue.indexOf(waiter);
        if (at >= 0) queue.splice(at, 1);
      };
      const waiter: Waiter = {
        lane,
        grant: () => {
          cleanup();
          this.active++;
          resolve();
        },
        cancel: (err) => {
          cleanup();
          reject(err);
        },
      };
      const onAbort = (): void => waiter.cancel(new SemaphoreAbortedError(lane));
      timer = setTimeout(() => waiter.cancel(new SemaphoreTimeoutError(lane, this.options.timeoutMs)), this.options.timeoutMs);
      signal?.addEventListener('abort', onAbort, { once: true });
      queue.push(waiter);
    });
  }

  private release(): void {
    this.active--;
    const next = this.lanes.issue[0] ?? this.lanes.export[0];
    if (next) next.grant();
  }
}
