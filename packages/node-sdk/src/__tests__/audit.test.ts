import { describe, it, expect, vi, afterEach } from 'vitest';
import { QRAuth } from '../client.js';
import { AuthorizationError } from '../errors.js';
import type { AuditEntry } from '../types.js';
import { auditPageResponse } from './fixtures/wire.js';

const BASE = 'https://api.test';
const client = () => new QRAuth({ apiKey: 'k', baseUrl: BASE });

function json(body: unknown, status = 200, headers: Record<string, string> = {}) {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', ...headers } });
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('QRAuth.listAuditEntries', () => {
  it('sends every filter, cursor and limit, and returns the page unchanged', async () => {
    const fetchMock = vi.fn().mockResolvedValue(json(auditPageResponse));
    vi.stubGlobal('fetch', fetchMock);

    const page = await client().listAuditEntries({
      actor: 'cmuser0001',
      actorType: 'USER',
      action: 'apiKey.create',
      resourceType: 'ApiKey',
      resourceId: 'cmkey0001',
      from: new Date('2026-11-01T00:00:00.000Z'),
      to: '2026-11-03T23:59:59+02:00',
      cursor: 'abc',
      limit: 20,
    });

    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    const parsed = new URL(url);
    expect(parsed.pathname).toBe('/api/v1/audit');
    expect(Object.fromEntries(parsed.searchParams)).toEqual({
      actor: 'cmuser0001',
      actorType: 'USER',
      action: 'apiKey.create',
      resourceType: 'ApiKey',
      resourceId: 'cmkey0001',
      from: '2026-11-01T00:00:00.000Z',
      to: '2026-11-03T23:59:59+02:00',
      cursor: 'abc',
      limit: '20',
    });
    expect(init.method).toBe('GET');
    expect((init.headers as Record<string, string>)['X-API-Key']).toBe('k');
    expect(page).toEqual(auditPageResponse);
  });

  it('sends no query string without params', async () => {
    const fetchMock = vi.fn().mockResolvedValue(json({ data: [], nextCursor: null }));
    vi.stubGlobal('fetch', fetchMock);

    await client().listAuditEntries();

    expect(fetchMock.mock.calls[0][0]).toBe(`${BASE}/api/v1/audit`);
  });

  it('the actor union narrows on type', () => {
    const names = auditPageResponse.data.map((e: AuditEntry) => {
      switch (e.actor.type) {
        case 'USER':
          return e.actor.email;
        case 'API_KEY':
          return e.actor.label;
        case 'SYSTEM':
          return e.actor.id;
        case 'SUPERADMIN':
          return e.actor.name;
      }
    });
    expect(names).toEqual(['QRAuth', 'CI deploy', 'jane@example.com']);
  });
});

describe('QRAuth.iterateAuditEntries', () => {
  it('follows nextCursor until it is null, keeping the filters', async () => {
    const [first, second, third] = auditPageResponse.data;
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(json({ data: [first, second], nextCursor: 'c1' }))
      .mockResolvedValueOnce(json({ data: [third], nextCursor: null }));
    vi.stubGlobal('fetch', fetchMock);

    const ids: string[] = [];
    for await (const entry of client().iterateAuditEntries({ actorType: 'USER', limit: 2 })) ids.push(entry.id);

    expect(ids).toEqual([first.id, second.id, third.id]);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(fetchMock.mock.calls[0][0]).toBe(`${BASE}/api/v1/audit?actorType=USER&limit=2`);
    expect(fetchMock.mock.calls[1][0]).toBe(`${BASE}/api/v1/audit?actorType=USER&cursor=c1&limit=2`);
  });

  it('stops fetching when the caller breaks early', async () => {
    const fetchMock = vi.fn().mockImplementation(async () => json({ data: auditPageResponse.data, nextCursor: 'more' }));
    vi.stubGlobal('fetch', fetchMock);

    for await (const entry of client().iterateAuditEntries()) {
      expect(entry.id).toBe(auditPageResponse.data[0].id);
      break;
    }

    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});

const RANGE = { from: '2026-10-01T00:00:00Z', to: '2026-10-31T23:59:59Z' };

describe('QRAuth.exportAuditCsv', () => {
  it('sends the filters (no cursor or limit) and returns the CSV text', async () => {
    const csv = 'time,action\r\n2026-11-03T09:00:00.000Z,apiKey.create\r\n';
    const fetchMock = vi.fn().mockResolvedValue(new Response(csv, { status: 200, headers: { 'content-type': 'text/csv; charset=utf-8' } }));
    vi.stubGlobal('fetch', fetchMock);

    const text = await client().exportAuditCsv({ action: 'apiKey.create', from: new Date('2026-10-01T00:00:00.000Z'), to: '2026-10-31T23:59:59Z' });

    expect(fetchMock.mock.calls[0][0]).toBe(
      `${BASE}/api/v1/audit/export.csv?action=apiKey.create&from=2026-10-01T00%3A00%3A00.000Z&to=2026-10-31T23%3A59%3A59Z`,
    );
    expect(text).toBe(csv);
  });

  it('needs an API key', async () => {
    const sessionsOnly = new QRAuth({ clientId: 'c', clientSecret: 's', baseUrl: BASE });
    await expect(sessionsOnly.exportAuditCsv(RANGE)).rejects.toThrow('apiKey is required');
  });
});

describe('audit log refusals', () => {
  it.each([
    ['governance-plan-required', 'The audit log is included in the Business plan and above.'],
    ['audit-role-required', 'The audit log is available to organization owners and admins.'],
  ])('403 %s is an AuthorizationError with that reason', async (code, message) => {
    vi.stubGlobal('fetch', vi.fn().mockImplementation(
      async () => json({ statusCode: 403, error: 'Forbidden', code, message }, 403, { 'x-request-id': 'req-1' }),
    ));

    const list = client().listAuditEntries();
    await expect(list).rejects.toBeInstanceOf(AuthorizationError);
    await expect(list).rejects.toMatchObject({ statusCode: 403, code: 'AUTHORIZATION_ERROR', reason: code, message, requestId: 'req-1' });
    await expect(client().exportAuditCsv(RANGE)).rejects.toMatchObject({ name: 'AuthorizationError', reason: code });
  });

  it('a 403 without a code leaves reason undefined', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(json({ statusCode: 403, error: 'Forbidden', message: 'Forbidden' }, 403)));
    await expect(client().listAuditEntries()).rejects.toMatchObject({ name: 'AuthorizationError', reason: undefined });
  });

  it('an invalid cursor is a ValidationError', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(json({ statusCode: 400, error: 'Bad Request', message: 'Invalid cursor.' }, 400)));
    await expect(client().listAuditEntries({ cursor: 'bad' })).rejects.toMatchObject({ name: 'ValidationError', message: 'Invalid cursor.' });
  });
});
