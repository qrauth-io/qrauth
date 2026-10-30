import { describe, it, expect, beforeEach, vi } from 'vitest';

process.env.REDIS_URL ??= 'redis://localhost:6379';
process.env.JWT_SECRET ??= 'a'.repeat(32);
process.env.ANIMATED_QR_SECRET ??= 'a'.repeat(64);

const flagQrCode = vi.hoisted(() => vi.fn(async () => true));
vi.mock('../../services/destination-screening.js', () => ({ flagQrCode }));
vi.mock('../../lib/queue.js', () => ({ webRiskQueue: { add: vi.fn() }, createQueueConnection: vi.fn() }));

import { runDailyScan, runRecheck } from '../web-risk.js';

const log = { info: vi.fn(), warn: vi.fn() } as never;

type Row = { id: string; token: string; destinationUrl: string };

function db(rows: Row[], single?: Record<string, unknown> | null) {
  return {
    qRCode: {
      findMany: vi.fn(async (args: { take: number; cursor?: { id: string } }) => {
        const start = args.cursor ? rows.findIndex((r) => r.id === args.cursor!.id) + 1 : 0;
        return rows.slice(start, start + args.take);
      }),
      findUnique: vi.fn(async () => single ?? null),
    },
    membership: {},
  };
}

beforeEach(() => flagQrCode.mockClear());

describe('runDailyScan', () => {
  it('looks each destination up once, spaced, and flags every code that points to a listed one', async () => {
    const rows = [
      { id: '1', token: 'a', destinationUrl: 'https://bad.example/x' },
      { id: '2', token: 'b', destinationUrl: 'https://BAD.example/x#frag' },
      { id: '3', token: 'c', destinationUrl: 'https://ok.example' },
      { id: '4', token: 'd', destinationUrl: 'https://down.example' },
    ];
    const lookup = vi.fn(async (url: string) =>
      url.includes('bad') ? { verdict: 'flagged' as const, threatTypes: ['MALWARE'] }
        : url.includes('down') ? { verdict: 'unavailable' as const, detail: 'timeout' }
          : { verdict: 'clean' as const });
    const sleep = vi.fn(async () => undefined);

    const summary = await runDailyScan(db(rows) as never, log, { lookup, sleep, now: () => new Date() });

    expect(lookup).toHaveBeenCalledTimes(3);
    expect(sleep).toHaveBeenCalledTimes(2);
    expect(flagQrCode.mock.calls.map((c) => c[2])).toEqual(['a', 'b']);
    expect(summary).toEqual({ codes: 4, destinations: 3, flagged: 2, unavailable: 1 });
  });

  it('only scans ACTIVE, unexpired, unflagged URL codes', async () => {
    const d = db([]);

    await runDailyScan(d as never, log, { lookup: vi.fn(), sleep: vi.fn(), now: () => new Date('2026-10-27T00:00:00Z') });

    expect(d.qRCode.findMany.mock.calls[0][0]).toMatchObject({
      where: {
        status: 'ACTIVE',
        contentType: 'url',
        destinationFlaggedAt: null,
        OR: [{ expiresAt: null }, { expiresAt: { gt: new Date('2026-10-27T00:00:00Z') } }],
      },
    });
  });

  it('pages through more than one page of codes', async () => {
    const rows = Array.from({ length: 1201 }, (_, i) => ({ id: String(i).padStart(5, '0'), token: `t${i}`, destinationUrl: 'https://same.example' }));
    const d = db(rows);

    const summary = await runDailyScan(d as never, log, { lookup: async () => ({ verdict: 'clean' }), sleep: vi.fn(), now: () => new Date() });

    expect(d.qRCode.findMany).toHaveBeenCalledTimes(3);
    expect(summary).toMatchObject({ codes: 1201, destinations: 1 });
  });
});

describe('runRecheck', () => {
  const active = { status: 'ACTIVE', contentType: 'url', destinationUrl: 'https://x.example', destinationFlaggedAt: null };

  it('flags a code whose destination is listed', async () => {
    const result = await runRecheck(db([], active) as never, log, 'tok', { lookup: async () => ({ verdict: 'flagged', threatTypes: ['SOCIAL_ENGINEERING'] }) });

    expect(result).toBe('flagged');
    expect(flagQrCode).toHaveBeenCalledWith(expect.anything(), log, 'tok', ['SOCIAL_ENGINEERING']);
  });

  it('throws when Web Risk is unavailable, so the job is retried', async () => {
    await expect(runRecheck(db([], active) as never, log, 'tok', { lookup: async () => ({ verdict: 'unavailable', detail: 'timeout' }) }))
      .rejects.toThrow(/retry/);
  });

  it('a clean verdict changes nothing', async () => {
    expect(await runRecheck(db([], active) as never, log, 'tok', { lookup: async () => ({ verdict: 'clean' }) })).toBe('clean');
    expect(flagQrCode).not.toHaveBeenCalled();
  });

  it.each([
    ['missing', null],
    ['revoked', { ...active, status: 'REVOKED' }],
    ['already flagged', { ...active, destinationFlaggedAt: new Date() }],
    ['not a URL code', { ...active, contentType: 'vcard' }],
  ])('skips a %s code without a lookup', async (_label, row) => {
    const lookup = vi.fn();

    expect(await runRecheck(db([], row) as never, log, 'tok', { lookup })).toBe('skipped');
    expect(lookup).not.toHaveBeenCalled();
  });
});
