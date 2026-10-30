import { describe, it, expect, vi } from 'vitest';

import { verifyTurnstileToken } from '../turnstile.js';

const jsonResponse = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

describe('verifyTurnstileToken', () => {
  it('posts secret, token and IP to siteverify and reports a pass', async () => {
    const fetchImpl = vi.fn(async () => jsonResponse({ success: true }));

    const result = await verifyTurnstileToken('sec', 'tok', '203.0.113.7', fetchImpl as typeof fetch);

    expect(result).toEqual({ outcome: 'passed' });
    const [url, init] = fetchImpl.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe('https://challenges.cloudflare.com/turnstile/v0/siteverify');
    expect(init.method).toBe('POST');
    const form = new URLSearchParams(init.body as URLSearchParams);
    expect(form.get('secret')).toBe('sec');
    expect(form.get('response')).toBe('tok');
    expect(form.get('remoteip')).toBe('203.0.113.7');
  });

  it('reports a failure with the error codes', async () => {
    const fetchImpl = vi.fn(async () => jsonResponse({ success: false, 'error-codes': ['timeout-or-duplicate'] }));

    const result = await verifyTurnstileToken('sec', 'tok', undefined, fetchImpl as typeof fetch);

    expect(result).toEqual({ outcome: 'failed', errorCodes: ['timeout-or-duplicate'] });
  });

  it.each([
    ['a network error', vi.fn(async () => { throw new Error('ECONNRESET'); })],
    ['an HTTP error', vi.fn(async () => jsonResponse({}, 502))],
    ['a non-JSON body', vi.fn(async () => new Response('<html>', { status: 200 }))],
  ])('reports unavailable on %s', async (_label, fetchImpl) => {
    const result = await verifyTurnstileToken('sec', 'tok', undefined, fetchImpl as typeof fetch);

    expect(result.outcome).toBe('unavailable');
  });
});
