import { describe, it, expect, vi, afterEach } from 'vitest';
import { QRAuth } from '../client.js';
import { QRAuthError } from '../errors.js';
import { bulkDryRunResponse, bulkExportJobResponse, bulkExportLinkResponse } from './fixtures/wire.js';

const BASE = 'https://api.test';
const client = () => new QRAuth({ apiKey: 'k', baseUrl: BASE });

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
}

const call = (fetchMock: ReturnType<typeof vi.fn>, i = 0) => {
  const [url, init] = fetchMock.mock.calls[i] as [string, RequestInit];
  return { url: new URL(url), init, headers: (init.headers ?? {}) as Record<string, string> };
};

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('bulk import', () => {
  it('bulkImportDryRun posts the file as text/csv, unchanged', async () => {
    const fetchMock = vi.fn().mockResolvedValue(json(bulkDryRunResponse, 201));
    vi.stubGlobal('fetch', fetchMock);
    const csv = Buffer.from('﻿url;label\r\nhttps://example.gr/;Καφές\r\n', 'utf8');
    const dryRun = await client().bulkImportDryRun(csv);
    expect(dryRun.totals).toMatchObject({ rows: 6, ok: 3, warning: 2, error: 1 });
    expect(dryRun.rows[1]).toMatchObject({ status: 'warning', code: 'lookalike' });
    const { url, init, headers } = call(fetchMock);
    expect([init.method, url.pathname]).toEqual(['POST', '/api/v1/bulk/imports/dry-run']);
    expect(headers['Content-Type']).toBe('text/csv');
    expect(headers['X-API-Key']).toBe('k');
    expect(init.body).toBe(csv);
    expect(url.search).toBe('');
  });

  it('bulkImportDryRun sends the time zone of date-only expiry dates', async () => {
    const fetchMock = vi.fn().mockResolvedValue(json(bulkDryRunResponse, 201));
    vi.stubGlobal('fetch', fetchMock);
    const dryRun = await client().bulkImportDryRun('url,expiresAt\n', { timezone: 'Europe/Athens' });
    expect(call(fetchMock).url.searchParams.get('timezone')).toBe('Europe/Athens');
    expect(dryRun.rows[0]).toMatchObject({ expiresAt: '2027-12-31T21:59:59.000Z', expiresDate: '2027-12-31' });
  });

  it('a refused file is a QRAuthError with the API code', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(json({ statusCode: 422, error: 'Unprocessable Entity', code: 'too-many-rows', message: 'The file has more than 1,000 data rows' }, 422)));
    const err = await client().bulkImportDryRun('url\n').catch((e: unknown) => e);
    expect(err).toBeInstanceOf(QRAuthError);
    expect(err).toMatchObject({ statusCode: 422 });
  });

  it('commitBulkImport, getBulkJob and getBulkImportResultsCsv use the job routes', async () => {
    const job = { ...bulkExportJobResponse, kind: 'IMPORT', fileBytes: null };
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(json(job, 202))
      .mockResolvedValueOnce(json(job))
      .mockResolvedValueOnce(new Response('﻿row,status\r\n2,created\r\n', { status: 200, headers: { 'content-type': 'text/csv' } }));
    vi.stubGlobal('fetch', fetchMock);
    const qrauth = client();
    expect((await qrauth.commitBulkImport('dry/run')).id).toBe(job.id);
    expect((await qrauth.getBulkJob(job.id)).status).toBe('SUCCEEDED');
    expect(await qrauth.getBulkImportResultsCsv(job.id)).toContain('2,created');
    expect(call(fetchMock, 0).url.pathname).toBe('/api/v1/bulk/imports/dry-run/dry%2Frun/commit');
    expect(call(fetchMock, 0).init.method).toBe('POST');
    expect(call(fetchMock, 1).url.pathname).toBe(`/api/v1/bulk/jobs/${job.id}`);
    expect(call(fetchMock, 2).url.pathname).toBe(`/api/v1/bulk/imports/${job.id}/results.csv`);
  });

  it('waitForBulkJob polls until the job ends', async () => {
    const running = { ...bulkExportJobResponse, status: 'RUNNING', finishedAt: null };
    const fetchMock = vi.fn().mockResolvedValueOnce(json(running)).mockResolvedValueOnce(json(bulkExportJobResponse));
    vi.stubGlobal('fetch', fetchMock);
    const job = await client().waitForBulkJob(bulkExportJobResponse.id, { intervalMs: 1 });
    expect(job.status).toBe('SUCCEEDED');
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('waitForBulkJob gives up after the timeout', async () => {
    vi.stubGlobal('fetch', vi.fn().mockImplementation(async () => json({ ...bulkExportJobResponse, status: 'QUEUED' })));
    await expect(client().waitForBulkJob('j', { intervalMs: 5, timeoutMs: 1 })).rejects.toThrow('did not finish in time');
  });
});

describe('bulk export', () => {
  it('createBulkExport sends the options as JSON', async () => {
    const fetchMock = vi.fn().mockResolvedValue(json({ ...bulkExportJobResponse, status: 'QUEUED' }, 202));
    vi.stubGlobal('fetch', fetchMock);
    const options = {
      selection: { filter: { tagIds: ['t1'], outsidePolicy: false, status: 'ACTIVE' as const } },
      formats: ['svg' as const, 'png' as const],
      png: { sizeMm: 50, dpi: 300 },
    };
    await client().createBulkExport(options);
    const { url, init } = call(fetchMock);
    expect([init.method, url.pathname]).toEqual(['POST', '/api/v1/bulk/exports']);
    expect(JSON.parse(String(init.body))).toEqual(options);
  });

  it('downloadBulkExport fetches the signed link without the API key', async () => {
    const zip = Buffer.from('PK\u0003\u0004zip');
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(json(bulkExportLinkResponse))
      .mockResolvedValueOnce(new Response(zip, { status: 200, headers: { 'content-type': 'application/zip' } }));
    vi.stubGlobal('fetch', fetchMock);
    const body = await client().downloadBulkExport(bulkExportJobResponse.id);
    expect(body.equals(zip)).toBe(true);
    expect(call(fetchMock, 0).url.pathname).toBe(`/api/v1/bulk/exports/${bulkExportJobResponse.id}/link`);
    const download = call(fetchMock, 1);
    expect(download.url.href).toBe(bulkExportLinkResponse.url);
    expect(download.headers['X-API-Key']).toBeUndefined();
  });
});
