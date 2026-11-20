import { describe, it, expect, vi, beforeEach } from 'vitest';
import { createHmac } from 'node:crypto';

// Mock the BullMQ queue BEFORE importing the service so importing it never
// touches Redis. `add` is a spy the tests introspect.
vi.mock('../../lib/queue.js', () => ({
  webhookQueue: { add: vi.fn(async () => ({ id: 'job_1' })) },
}));

import { webhookQueue } from '../../lib/queue.js';
import { constantTimeEqualString } from '../../lib/constant-time.js';
import {
  generateSecurityWebhookSecret,
  signSecurityWebhookBody,
  buildSigningKeyCreatedEvent,
  enqueueSigningKeyCreatedWebhook,
  SECURITY_WEBHOOK_JOB_NAME,
  SECURITY_WEBHOOK_MAX_ATTEMPTS,
} from '../security-webhook.js';

const addSpy = vi.mocked(webhookQueue.add);

function fakeSigningKey(overrides: Record<string, unknown> = {}) {
  return {
    id: 'sk_1',
    organizationId: 'org_1',
    keyId: 'kid-abc',
    algorithm: 'ES256',
    slhdsaAlgorithm: 'slh-dsa-sha2-128s',
    status: 'ACTIVE',
    createdAt: new Date('2026-01-02T03:04:05.000Z'),
    ...overrides,
  } as any;
}

describe('signSecurityWebhookBody — HMAC-SHA3-256 lock (guards TD-7)', () => {
  // Fixed 32-byte secret, base64-encoded. Reproducible across runtimes.
  const SECRET = Buffer.alloc(32, 7).toString('base64');
  const BODY = '{"eventType":"signing-key.created","kid":"kid-abc"}';

  it('produces the canonical sha3-256=<hex> envelope over the base64-decoded key', () => {
    const expectedHex = createHmac('sha3-256', Buffer.from(SECRET, 'base64'))
      .update(BODY, 'utf8')
      .digest('hex');

    const header = signSecurityWebhookBody(SECRET, BODY);

    expect(header).toBe(`sha3-256=${expectedHex}`);
    expect(header.startsWith('sha3-256=')).toBe(true);
  });

  it('is deterministic for the same secret + body', () => {
    const first = signSecurityWebhookBody(SECRET, BODY);
    const second = signSecurityWebhookBody(SECRET, BODY);
    expect(constantTimeEqualString(first, second)).toBe(true);
  });

  it('changes when the body changes by one byte', () => {
    const a = signSecurityWebhookBody(SECRET, BODY);
    const b = signSecurityWebhookBody(SECRET, `${BODY} `);
    expect(constantTimeEqualString(a, b)).toBe(false);
  });

  it('changes when the secret changes', () => {
    const otherSecret = Buffer.alloc(32, 9).toString('base64');
    const a = signSecurityWebhookBody(SECRET, BODY);
    const b = signSecurityWebhookBody(otherSecret, BODY);
    expect(constantTimeEqualString(a, b)).toBe(false);
  });
});

describe('generateSecurityWebhookSecret', () => {
  it('returns a base64 string decoding to 32 bytes', () => {
    const secret = generateSecurityWebhookSecret();
    expect(Buffer.from(secret, 'base64').length).toBe(32);
  });

  it('returns a fresh value each call', () => {
    expect(generateSecurityWebhookSecret()).not.toBe(generateSecurityWebhookSecret());
  });
});

describe('buildSigningKeyCreatedEvent', () => {
  it('maps the SigningKey row into the pinned event shape', () => {
    const event = buildSigningKeyCreatedEvent(fakeSigningKey());

    expect(event.eventType).toBe('signing-key.created');
    expect(event.organizationId).toBe('org_1');
    expect(event.operatorIdentity).toBeNull();
    expect(event.signingKey).toEqual({
      kid: 'kid-abc',
      algorithm: 'ES256',
      slhdsaAlgorithm: 'slh-dsa-sha2-128s',
      status: 'ACTIVE',
      createdAt: '2026-01-02T03:04:05.000Z',
    });
    expect(typeof event.eventId).toBe('string');
  });

  it('coerces a missing slhdsaAlgorithm to null', () => {
    const event = buildSigningKeyCreatedEvent(fakeSigningKey({ slhdsaAlgorithm: null }));
    expect(event.signingKey.slhdsaAlgorithm).toBeNull();
  });
});

describe('enqueueSigningKeyCreatedWebhook', () => {
  beforeEach(() => addSpy.mockClear());

  it('returns null and enqueues nothing when the org has no endpoint', async () => {
    const prisma = {
      organization: {
        findUnique: vi.fn(async () => ({ securityWebhookUrl: null, securityWebhookSecret: null })),
      },
    } as any;

    const result = await enqueueSigningKeyCreatedWebhook(prisma, fakeSigningKey());

    expect(result).toBeNull();
    expect(addSpy).not.toHaveBeenCalled();
  });

  it('enqueues a job with a matching signature when configured', async () => {
    const secret = Buffer.alloc(32, 5).toString('base64');
    const prisma = {
      organization: {
        findUnique: vi.fn(async () => ({
          securityWebhookUrl: 'https://hook.example.com/qrauth',
          securityWebhookSecret: secret,
        })),
      },
    } as any;

    const result = await enqueueSigningKeyCreatedWebhook(prisma, fakeSigningKey());

    expect(result).not.toBeNull();
    expect(addSpy).toHaveBeenCalledTimes(1);

    const [jobName, jobData, opts] = addSpy.mock.calls[0];
    expect(jobName).toBe(SECURITY_WEBHOOK_JOB_NAME);
    expect(opts).toMatchObject({ attempts: SECURITY_WEBHOOK_MAX_ATTEMPTS });
    expect(jobData.url).toBe('https://hook.example.com/qrauth');

    // The header on the job must be the HMAC over the exact rawBody bytes.
    const expected = signSecurityWebhookBody(secret, jobData.rawBody);
    expect(constantTimeEqualString(jobData.signatureHeader, expected)).toBe(true);
  });

  it('swallows errors and returns null (never blocks key creation)', async () => {
    const prisma = {
      organization: {
        findUnique: vi.fn(async () => {
          throw new Error('db down');
        }),
      },
    } as any;
    const errSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

    const result = await enqueueSigningKeyCreatedWebhook(prisma, fakeSigningKey());

    expect(result).toBeNull();
    expect(addSpy).not.toHaveBeenCalled();
    errSpy.mockRestore();
  });
});
