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

describe('QRAuth.image', () => {
  it('maps print options to the query and returns the bytes with the headers', async () => {
    const pdf = Buffer.from('%PDF-1.4 test');
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(pdf, {
        status: 200,
        headers: {
          'content-type': 'application/pdf',
          etag: '"abc"',
          'content-disposition': 'inline; filename="qrauth-tok-50mm.pdf"',
        },
      }),
    );
    vi.stubGlobal('fetch', fetchMock);
    const client = new QRAuth({ apiKey: 'k', baseUrl: 'https://api.test' });

    const image = await client.image('tok', { format: 'pdf', sizeMm: 50, marginMm: 2 });

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('https://api.test/api/v1/qrcodes/tok/image?format=pdf&size_mm=50&margin_mm=2');
    expect((init.headers as Record<string, string>)['X-API-Key']).toBe('k');
    expect(image.data.equals(pdf)).toBe(true);
    expect(image).toMatchObject({ contentType: 'application/pdf', etag: '"abc"', filename: 'qrauth-tok-50mm.pdf' });
    expect(image.px).toBeUndefined();
  });

  it('a print PNG reports the rendered width; no options asks for the default', async () => {
    const fetchMock = vi.fn().mockImplementation(
      async () => new Response(Buffer.from('png'), { status: 200, headers: { 'content-type': 'image/png', 'x-qrauth-image-px': '354' } }),
    );
    vi.stubGlobal('fetch', fetchMock);
    const client = new QRAuth({ apiKey: 'k', baseUrl: 'https://api.test' });

    expect((await client.image('tok', { sizeMm: 30, dpi: 300 })).px).toBe(354);
    expect(fetchMock.mock.calls[0][0]).toBe('https://api.test/api/v1/qrcodes/tok/image?size_mm=30&dpi=300');
    await client.image('tok');
    expect(fetchMock.mock.calls[1][0]).toBe('https://api.test/api/v1/qrcodes/tok/image');
  });

  it('a plan refusal is an AuthorizationError with the API message', async () => {
    stubFetch(403, JSON.stringify({ statusCode: 403, error: 'Forbidden', message: 'PDF export is not included in the Free plan.' }), {
      'content-type': 'application/json',
    });
    const client = new QRAuth({ apiKey: 'k', baseUrl: 'https://api.test' });

    await expect(client.image('tok', { format: 'pdf' })).rejects.toMatchObject({
      name: 'AuthorizationError',
      message: 'PDF export is not included in the Free plan.',
    });
  });

  it('needs an API key', async () => {
    const client = new QRAuth({ clientId: 'c', clientSecret: 's', baseUrl: 'https://api.test' });
    await expect(client.image('tok')).rejects.toThrow('apiKey is required');
  });
});
