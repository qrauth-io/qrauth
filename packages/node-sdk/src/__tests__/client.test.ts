import { describe, it, expect, vi, afterEach } from 'vitest';
import { QRAuth } from '../client.js';
import { QRAuthError } from '../errors.js';

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

describe('QRAuth.getHistory', () => {
  it('sends page and pageSize, and none when omitted', async () => {
    const fetchMock = vi.fn().mockImplementation(
      async () => new Response(JSON.stringify({ data: [], total: 0, page: 1, pageSize: 20, totalPages: 0 }), { status: 200 }),
    );
    vi.stubGlobal('fetch', fetchMock);
    const client = new QRAuth({ apiKey: 'k', baseUrl: 'https://api.test' });

    await client.getHistory('a/b', { page: 2, pageSize: 50 });
    await client.getHistory('tok');

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('https://api.test/api/v1/qrcodes/a%2Fb/history?page=2&pageSize=50');
    expect(init.method).toBe('GET');
    expect(fetchMock.mock.calls[1][0]).toBe('https://api.test/api/v1/qrcodes/tok/history');
  });

  it("another organization's code is a NotFoundError", async () => {
    stubFetch(404, JSON.stringify({ statusCode: 404, error: 'Not Found', message: "QR code 'tok' not found" }));
    const client = new QRAuth({ apiKey: 'k', baseUrl: 'https://api.test' });

    await expect(client.getHistory('tok')).rejects.toMatchObject({ name: 'NotFoundError', statusCode: 404 });
  });
});

describe('QRAuth.restoreDestination', () => {
  it('POSTs to the revision without a body', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({ token: 'tok' }), { status: 200 }));
    vi.stubGlobal('fetch', fetchMock);
    const client = new QRAuth({ apiKey: 'k', baseUrl: 'https://api.test' });

    await client.restoreDestination('tok', 3);

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('https://api.test/api/v1/qrcodes/tok/history/3/restore');
    expect(init.method).toBe('POST');
    expect(init.body).toBeUndefined();
    expect((init.headers as Record<string, string>)['Content-Type']).toBeUndefined();
  });

  it('a conflict keeps the API message and status', async () => {
    stubFetch(409, JSON.stringify({ statusCode: 409, error: 'Conflict', code: 'already-current', message: 'That is already the current destination.' }));
    const client = new QRAuth({ apiKey: 'k', baseUrl: 'https://api.test' });

    await expect(client.restoreDestination('tok', 2)).rejects.toMatchObject({
      statusCode: 409,
      message: 'That is already the current destination.',
    });
  });

  it.each([0, -1, 1.5, Number.NaN])('refuses revision %s without calling the API', async (revision) => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    const client = new QRAuth({ apiKey: 'k', baseUrl: 'https://api.test' });

    await expect(client.restoreDestination('tok', revision)).rejects.toThrow('revision must be a positive integer');
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe('X-Request-Id on errors', () => {
  it('every error class carries the response request id', async () => {
    const client = new QRAuth({ apiKey: 'k', baseUrl: 'https://api.test' });
    const cases: Array<[number, string]> = [
      [400, 'ValidationError'],
      [401, 'AuthenticationError'],
      [403, 'AuthorizationError'],
      [404, 'NotFoundError'],
      [409, 'ConflictError'],
      [429, 'RateLimitError'],
    ];
    for (const [status, name] of cases) {
      stubFetch(status, JSON.stringify({ message: 'nope' }), { 'x-request-id': `req-${status}` });
      await expect(client.get('tok')).rejects.toMatchObject({ name, statusCode: status, requestId: `req-${status}` });
    }
  });

  it('image() errors carry it too; absent header leaves it undefined', async () => {
    const client = new QRAuth({ apiKey: 'k', baseUrl: 'https://api.test' });

    stubFetch(403, JSON.stringify({ message: 'Free plan' }), { 'x-request-id': 'req-img' });
    await expect(client.image('tok', { format: 'pdf' })).rejects.toMatchObject({ requestId: 'req-img' });

    stubFetch(404, JSON.stringify({ message: 'nope' }));
    const err = await client.get('tok').catch((e: unknown) => e);
    expect(err).toBeInstanceOf(QRAuthError);
    expect((err as QRAuthError).requestId).toBeUndefined();
  });
});

describe('QRAuth.create with a link content type', () => {
  it('sends the content type and content, and no destinationUrl when none is given', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ token: 'tok' }), { status: 201, headers: { 'content-type': 'application/json' } }),
    );
    vi.stubGlobal('fetch', fetchMock);
    const client = new QRAuth({ apiKey: 'k', baseUrl: 'https://api.test' });

    await client.create({
      contentType: 'link-list',
      label: 'Bistro',
      content: { title: 'Bistro', links: [{ label: 'Menu', url: 'https://example.com/menu' }] },
    });

    const body = JSON.parse(fetchMock.mock.calls[0][1].body);
    expect(body).toEqual({
      label: 'Bistro',
      contentType: 'link-list',
      content: { title: 'Bistro', links: [{ label: 'Menu', url: 'https://example.com/menu' }] },
    });
  });

  it('a listed link surfaces as a 422 error naming the link', async () => {
    stubFetch(422, JSON.stringify({
      statusCode: 422,
      error: 'DestinationFlagged',
      message: 'A link in this content (https://listed.example/) is listed as dangerous by Google Web Risk and cannot be used.',
      url: 'https://listed.example/',
    }), { 'content-type': 'application/json' });
    const client = new QRAuth({ apiKey: 'k', baseUrl: 'https://api.test' });

    await expect(client.create({ contentType: 'app-link', content: { iosUrl: 'https://listed.example/', androidUrl: 'https://a.example/', fallbackUrl: 'https://b.example/' } }))
      .rejects.toMatchObject({ statusCode: 422, message: expect.stringContaining('https://listed.example/') });
  });
});

describe('SDK_VERSION', () => {
  it('matches package.json and is sent as the User-Agent', async () => {
    const { readFileSync } = await import('node:fs');
    const pkg = JSON.parse(readFileSync(new URL('../../package.json', import.meta.url), 'utf8')) as { version: string };
    const { SDK_VERSION } = await import('../index.js');
    expect(SDK_VERSION).toBe(pkg.version);

    const fetchMock = vi.fn().mockResolvedValue(new Response(null, { status: 204 }));
    vi.stubGlobal('fetch', fetchMock);
    await new QRAuth({ apiKey: 'k', baseUrl: 'https://api.test' }).revoke('tok');
    expect(fetchMock.mock.calls[0][1].headers['User-Agent']).toBe(`qrauth-node/${pkg.version}`);
  });
});
