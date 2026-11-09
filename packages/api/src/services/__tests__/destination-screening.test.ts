import { describe, it, expect, beforeEach, vi } from 'vitest';

process.env.REDIS_URL ??= 'redis://localhost:6379';
process.env.JWT_SECRET ??= 'a'.repeat(32);
process.env.ANIMATED_QR_SECRET ??= 'a'.repeat(64);
process.env.ABUSE_NOTIFY_EMAIL = 'abuse@qrauth.test';

const sendEmail = vi.hoisted(() => vi.fn(async () => undefined));
vi.mock('../../lib/email.js', () => ({ sendDestinationFlaggedEmail: sendEmail }));
vi.mock('../../lib/cache.js', () => ({ cacheDel: vi.fn(async () => undefined), redis: {} }));
vi.mock('../../lib/queue.js', () => ({ webRiskQueue: { add: vi.fn() } }));

// Imported after the env above: config is read at import time.
const { destinationFlaggedBody, flagQrCode } = await import('../destination-screening.js');

const log = { warn: vi.fn(), info: vi.fn() } as never;

function db(updatedCount: number) {
  return {
    qRCode: {
      updateMany: vi.fn(async () => ({ count: updatedCount })),
      findUnique: vi.fn(async () => ({ destinationUrl: 'https://bad.example', organizationId: 'org_1', organization: { name: 'Acme' } })),
    },
    membership: {
      findMany: vi.fn(async () => [{ user: { email: 'owner1@acme.test' } }, { user: { email: 'owner2@acme.test' } }]),
    },
  };
}

beforeEach(() => sendEmail.mockClear());

describe('flagQrCode', () => {
  it('sets the flag only when unset, then emails the owners and the abuse inbox', async () => {
    const d = db(1);

    expect(await flagQrCode(d as never, log, 'tok', ['MALWARE', 'UNWANTED_SOFTWARE'])).toBe(true);

    expect(d.qRCode.updateMany).toHaveBeenCalledWith({
      where: { token: 'tok', destinationFlaggedAt: null },
      data: { destinationFlaggedAt: expect.any(Date), destinationFlagReason: 'MALWARE,UNWANTED_SOFTWARE' },
    });
    expect(d.membership.findMany).toHaveBeenCalledWith(expect.objectContaining({ where: { organizationId: 'org_1', role: 'OWNER' } }));
    expect(sendEmail.mock.calls.map((c) => c[0]).sort()).toEqual(['abuse@qrauth.test', 'owner1@acme.test', 'owner2@acme.test']);
  });

  it('an already flagged code is left alone and nobody is emailed again', async () => {
    const d = db(0);

    expect(await flagQrCode(d as never, log, 'tok', ['MALWARE'])).toBe(false);
    expect(sendEmail).not.toHaveBeenCalled();
  });
});

describe('destinationFlaggedBody', () => {
  it('is a 422 DestinationFlagged with the threat type', () => {
    expect(destinationFlaggedBody(['SOCIAL_ENGINEERING'])).toMatchObject({
      statusCode: 422,
      error: 'DestinationFlagged',
      threatType: 'SOCIAL_ENGINEERING',
      threatTypes: ['SOCIAL_ENGINEERING'],
    });
  });
});
