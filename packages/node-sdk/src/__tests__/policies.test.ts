import { describe, it, expect, vi, afterEach } from 'vitest';
import { QRAuth } from '../client.js';
import { AuthorizationError, QRAuthError } from '../errors.js';
import { policyPreviewResponse, policyResponse } from './fixtures/wire.js';

const BASE = 'https://api.test';
const client = () => new QRAuth({ apiKey: 'k', baseUrl: BASE });

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
}

const call = (fetchMock: ReturnType<typeof vi.fn>, i = 0) => {
  const [url, init] = fetchMock.mock.calls[i] as [string, RequestInit];
  return { url: new URL(url), init, body: init.body ? JSON.parse(String(init.body)) : undefined };
};

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('organization policies', () => {
  it('getPolicy reads GET /api/v1/policies', async () => {
    const fetchMock = vi.fn().mockResolvedValue(json(policyResponse));
    vi.stubGlobal('fetch', fetchMock);
    expect(await client().getPolicy()).toEqual(policyResponse);
    const { url, init } = call(fetchMock);
    expect(url.pathname).toBe('/api/v1/policies');
    expect(init.method).toBe('GET');
  });

  it('updatePolicy sends the whole policy with PUT', async () => {
    const fetchMock = vi.fn().mockResolvedValue(json(policyResponse));
    vi.stubGlobal('fetch', fetchMock);
    const options = {
      allowlistMode: 'ENFORCE' as const,
      allowlist: [{ domain: 'www.example.com' }, { domain: 'münchen.de', includeSubdomains: false }],
      destinationEditMinRole: 'MANAGER' as const,
    };
    expect(await client().updatePolicy(options)).toEqual(policyResponse);
    const { url, init, body } = call(fetchMock);
    expect([init.method, url.pathname]).toEqual(['PUT', '/api/v1/policies']);
    expect(body).toEqual(options);
  });

  it('previewPolicy posts the allowlist', async () => {
    const fetchMock = vi.fn().mockResolvedValue(json(policyPreviewResponse));
    vi.stubGlobal('fetch', fetchMock);
    const preview = await client().previewPolicy([{ domain: 'www.example.com' }, { domain: 'co.uk' }]);
    expect(preview.affectedTotal).toBe(2);
    expect(preview.entries[1]).toMatchObject({ ok: false, input: 'co.uk' });
    const { url, init, body } = call(fetchMock);
    expect([init.method, url.pathname]).toEqual(['POST', '/api/v1/policies/preview']);
    expect(body).toEqual({ allowlist: [{ domain: 'www.example.com' }, { domain: 'co.uk' }] });
  });

  it('list() sends outsidePolicy as true or false', async () => {
    const fetchMock = vi.fn().mockImplementation(async () => json({ data: [], total: 0, page: 1, pageSize: 20, totalPages: 0 }));
    vi.stubGlobal('fetch', fetchMock);
    await client().list({ outsidePolicy: true });
    await client().list({ outsidePolicy: false });
    await client().list();
    expect(call(fetchMock, 0).url.searchParams.get('outsidePolicy')).toBe('true');
    expect(call(fetchMock, 1).url.searchParams.get('outsidePolicy')).toBe('false');
    expect(call(fetchMock, 2).url.searchParams.has('outsidePolicy')).toBe(false);
  });

  it('a destination outside the allowlist is a 422 QRAuthError naming the allowed domains', async () => {
    const message = "elsewhere.test is not on this organization's destination allowlist. Allowed: example.com (and subdomains).";
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(json({ statusCode: 422, error: 'Unprocessable Entity', code: 'destination-not-allowed', message }, 422)));
    const err = await client().create({ destination: 'https://elsewhere.test/' }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(QRAuthError);
    expect(err).toMatchObject({ statusCode: 422, message });
  });

  it('a restore below the minimum role is an AuthorizationError with reason destination-edit-role-required', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(json({ statusCode: 403, error: 'Forbidden', code: 'destination-edit-role-required', message: 'x', requiredRole: 'ADMIN' }, 403)));
    const err = await client().restoreDestination('tok', 2).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(AuthorizationError);
    expect((err as AuthorizationError).reason).toBe('destination-edit-role-required');
  });
});
