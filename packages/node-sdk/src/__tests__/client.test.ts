import { describe, it, expect, vi, afterEach } from 'vitest';
import { QRAuth } from '../client.js';

function stubFetch(status: number, body: string | null, headers: Record<string, string> = {}) {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(body, { status, headers })));
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe('QRAuth.revoke', () => {
  it('resolves without throwing when the API replies 204 No Content', async () => {
    // Regression: res.json() on an empty 204 body threw "Unexpected end of JSON input".
    stubFetch(204, null);
    const client = new QRAuth({ apiKey: 'k', baseUrl: 'https://api.test' });

    await expect(client.revoke('tok')).resolves.toBeUndefined();
  });
});

describe('QRAuth error handling', () => {
  it('surfaces a Zod-array validation message as readable text, not "[object Object]"', async () => {
    const body = JSON.stringify({
      error: 'Validation Error',
      message: [{ path: ['body', 'destinationUrl'], message: 'Invalid url' }],
    });
    stubFetch(400, body, { 'content-type': 'application/json' });
    const client = new QRAuth({ apiKey: 'k', baseUrl: 'https://api.test' });

    await expect(client.create({ destination: 'not-a-url' })).rejects.toThrow(
      'body.destinationUrl: Invalid url',
    );
  });
});
