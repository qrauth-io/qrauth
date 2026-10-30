import { Job, type JobsOptions } from 'bullmq';
import { describe, it, expect, vi } from 'vitest';

process.env.DATABASE_URL ??= 'postgresql://test:test@localhost:5432/test';
process.env.REDIS_URL ??= 'redis://localhost:6379';
process.env.JWT_SECRET ??= 'a'.repeat(32);

const { AlertService } = await import('../alerts.js');

/**
 * The fraud-alert job is checked by BullMQ's own option validation (the
 * same check Queue.add runs before writing to Redis), so an id BullMQ
 * refuses fails here instead of at scan time.
 */
const QUEUE_STUB = {
  name: 'qrauth-alerts',
  opts: {},
  keys: {},
  qualifiedName: 'bull:qrauth-alerts',
  client: Promise.resolve({}),
  toKey: (type: string) => `bull:qrauth-alerts:${type}`,
  trace: async (_kind: unknown, _name: unknown, _dest: unknown, fn: () => unknown) => fn(),
};

function bullmqValidates(name: string, opts: JobsOptions): void {
  const job = new Job(QUEUE_STUB as never, name, {}, opts);
  (job as unknown as { validateOptions(data: unknown): void }).validateOptions(job.asJSON());
}

describe('fraud alert job id', () => {
  it('BullMQ refuses ids with a colon (the check this test relies on)', () => {
    expect(() => bullmqValidates('fraud-alert', { jobId: 'fraud-alert:inc_1' })).toThrow('Custom Id cannot contain :');
  });

  it('sendFraudAlert enqueues a job BullMQ accepts, keyed by the incident', async () => {
    const add = vi.fn(async () => ({}));
    const service = new AlertService({} as never, { add } as never);

    await service.sendFraudAlert('org_1', { id: 'cmvtdw5rs00a32grf5iswa05z', type: 'PATTERN_ANOMALY', severity: 'HIGH', qrCodeId: 'qr_1' } as never);

    const [name, , opts] = add.mock.calls[0] as unknown as [string, unknown, JobsOptions];
    expect(opts.jobId).toBe('fraud-alert-cmvtdw5rs00a32grf5iswa05z');
    expect(() => bullmqValidates(name, opts)).not.toThrow();
  });
});
