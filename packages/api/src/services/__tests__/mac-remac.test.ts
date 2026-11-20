import { describe, it, expect, vi, beforeEach } from 'vitest';
import { MacService, computeMac } from '../mac.js';
import { buildQrCanonicalCore } from '../../lib/qr-canonical.js';

/**
 * MacService.remacOrgRows — the rotation-time re-MAC that keeps long-lived
 * QRs verifiable across MAC key rotation (incident 2026-09-03, qV2zsVQM).
 *
 * The verify route fails CLOSED on a MAC miss (AUDIT-FINDING-001), so every
 * row must always carry a MAC under a live key version. These tests pin the
 * contract: stale rows are rewritten under the ACTIVE key, rows whose stored
 * MAC does not reproduce under a surviving key are flagged and never touched,
 * and dry-run writes nothing.
 */

const ORG_ID = 'org-1';

const activeSecret = Buffer.alloc(32, 1).toString('base64');
const rotatedSecret = Buffer.alloc(32, 2).toString('base64');

const activeKey = {
  id: 'k2',
  organizationId: ORG_ID,
  version: 2,
  secret: activeSecret,
  algorithm: 'hmac-sha3-256',
  status: 'ACTIVE',
};
const rotatedKey = {
  id: 'k1',
  organizationId: ORG_ID,
  version: 1,
  secret: rotatedSecret,
  algorithm: 'hmac-sha3-256',
  status: 'ROTATED',
};

function qrRow(over: Record<string, unknown> = {}) {
  return {
    id: 'qr-1',
    token: 'tok11111',
    organizationId: ORG_ID,
    contentType: 'url',
    destinationUrl: 'https://example.com/menu',
    content: null,
    latitude: null,
    longitude: null,
    radiusM: 50,
    expiresAt: null,
    algVersion: 'hybrid-ecdsa-slhdsa-v1',
    status: 'ACTIVE',
    macKeyVersion: 1,
    macTokenMac: 'deadbeef',
    ...over,
  };
}

interface Setup {
  service: MacService;
  update: ReturnType<typeof vi.fn>;
}

function serviceWith(keys: unknown[], rows: unknown[]): Setup {
  const update = vi.fn(async () => ({}));
  const prisma = {
    orgMacKey: { findMany: vi.fn(async () => keys) },
    qRCode: { findMany: vi.fn(async () => rows), update },
  } as never;
  return { service: new MacService(prisma), update };
}

async function macFor(row: ReturnType<typeof qrRow>, secretB64: string): Promise<string> {
  const canonical = await buildQrCanonicalCore(row as never);
  return computeMac(canonical, Buffer.from(secretB64, 'base64'));
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe('MacService.remacOrgRows', () => {
  it('rewrites a stale row under the ACTIVE key when the old key is gone', async () => {
    const row = qrRow();
    const { service, update } = serviceWith([activeKey], [row]);

    const summary = await service.remacOrgRows(ORG_ID);

    expect(summary.flagged).toHaveLength(0);
    expect(summary.updated).toHaveLength(1);
    expect(summary.updated[0]).toMatchObject({
      token: 'tok11111',
      fromVersion: 1,
      toVersion: 2,
      oldMacCheck: 'key_unavailable',
    });
    const expectedMac = await macFor(row, activeSecret);
    expect(update).toHaveBeenCalledWith({
      where: { id: 'qr-1' },
      data: { macTokenMac: expectedMac, macKeyVersion: 2 },
    });
  });

  it('verifies the stored MAC under a surviving old key before rewriting', async () => {
    const row = qrRow();
    row.macTokenMac = await macFor(row, rotatedSecret);
    const { service, update } = serviceWith([activeKey, rotatedKey], [row]);

    const summary = await service.remacOrgRows(ORG_ID);

    expect(summary.updated).toHaveLength(1);
    expect(summary.updated[0].oldMacCheck).toBe('verified');
    expect(update).toHaveBeenCalledTimes(1);
  });

  it('flags and never touches a row whose MAC does not reproduce under its surviving key', async () => {
    const row = qrRow({ macTokenMac: 'ff'.repeat(32) });
    const { service, update } = serviceWith([activeKey, rotatedKey], [row]);

    const summary = await service.remacOrgRows(ORG_ID);

    expect(summary.updated).toHaveLength(0);
    expect(summary.flagged).toHaveLength(1);
    expect(summary.flagged[0]).toMatchObject({ token: 'tok11111', oldMacCheck: 'mismatch' });
    expect(update).not.toHaveBeenCalled();
  });

  it('skips rows already MACed under the ACTIVE version', async () => {
    const row = qrRow({ macKeyVersion: 2 });
    const { service, update } = serviceWith([activeKey], [row]);

    const summary = await service.remacOrgRows(ORG_ID);

    expect(summary.updated).toHaveLength(0);
    expect(summary.flagged).toHaveLength(0);
    expect(update).not.toHaveBeenCalled();
  });

  it('includes legacy rows with a null macKeyVersion', async () => {
    const row = qrRow({ macKeyVersion: null });
    const { service, update } = serviceWith([activeKey], [row]);

    const summary = await service.remacOrgRows(ORG_ID);

    expect(summary.updated).toHaveLength(1);
    expect(summary.updated[0].fromVersion).toBeNull();
    expect(update).toHaveBeenCalledTimes(1);
  });

  it('writes nothing in dry-run mode but reports what it would do', async () => {
    const row = qrRow();
    const { service, update } = serviceWith([activeKey], [row]);

    const summary = await service.remacOrgRows(ORG_ID, { dryRun: true });

    expect(summary.updated).toHaveLength(1);
    expect(update).not.toHaveBeenCalled();
  });

  it('returns empty summary when the org has no ACTIVE key', async () => {
    const { service, update } = serviceWith([rotatedKey], [qrRow()]);

    const summary = await service.remacOrgRows(ORG_ID);

    expect(summary.updated).toHaveLength(0);
    expect(summary.flagged).toHaveLength(0);
    expect(update).not.toHaveBeenCalled();
  });
});

describe('buildQrCanonicalCore', () => {
  it('binds content QRs to the content hash, not the destination URL', async () => {
    const urlRow = qrRow() as never;
    const contentRow = qrRow({
      contentType: 'coupon',
      content: { code: 'SAVE10' },
    }) as never;

    const urlCanonical = await buildQrCanonicalCore(urlRow);
    const contentCanonical = await buildQrCanonicalCore(contentRow);

    expect(urlCanonical).not.toBe(contentCanonical);
  });

  it('is stable for identical rows', async () => {
    const a = await buildQrCanonicalCore(qrRow() as never);
    const b = await buildQrCanonicalCore(qrRow() as never);
    expect(a).toBe(b);
  });
});
