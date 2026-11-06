import type { BulkJob } from '@prisma/client';
import { describe, expect, it } from 'vitest';
import { BULK_EXPORT_LINK_TTL_SECONDS } from '@qrauth/shared';

import { signExportLink, verifyExportLink } from '../bulk-jobs.js';
import { isInExportDir } from '../bulk-cleanup.js';

const job = (over: Partial<BulkJob> = {}) =>
  ({ id: 'job1', actorType: 'USER', actorUserId: 'u1', actorApiKeyId: null, ...over }) as BulkJob;

function parts(query: string): { expires: number; sig: string } {
  const p = new URLSearchParams(query);
  return { expires: Number(p.get('expires')), sig: p.get('sig')! };
}

describe('export download links', () => {
  const now = Date.UTC(2026, 10, 5, 12);

  it('verify for the job and starter they were issued to, until they expire', () => {
    const { query, expiresAt } = signExportLink(job(), now);
    const { expires, sig } = parts(query);
    expect(expiresAt.getTime()).toBe(now + BULK_EXPORT_LINK_TTL_SECONDS * 1000);
    expect(verifyExportLink(job(), expires, sig, now)).toBe(true);
    expect(verifyExportLink(job(), expires, sig, now + (BULK_EXPORT_LINK_TTL_SECONDS - 1) * 1000)).toBe(true);
    expect(verifyExportLink(job(), expires, sig, now + BULK_EXPORT_LINK_TTL_SECONDS * 1000)).toBe(false);
  });

  it('do not verify for another job, another starter, a changed expiry or signature', () => {
    const { expires, sig } = parts(signExportLink(job(), now).query);
    expect(verifyExportLink(job({ id: 'job2' }), expires, sig, now)).toBe(false);
    expect(verifyExportLink(job({ actorUserId: 'u2' }), expires, sig, now)).toBe(false);
    expect(verifyExportLink(job({ actorType: 'API_KEY', actorUserId: null, actorApiKeyId: 'u1' }), expires, sig, now)).toBe(false);
    expect(verifyExportLink(job(), expires + 60, sig, now)).toBe(false);
    expect(verifyExportLink(job(), expires, `${sig.slice(0, -1)}${sig.endsWith('A') ? 'B' : 'A'}`, now)).toBe(false);
    expect(verifyExportLink(job(), Number.NaN, sig, now)).toBe(false);
  });
});

describe('isInExportDir', () => {
  it('accepts only files directly inside the export directory', () => {
    expect(isInExportDir('/var/lib/qrauth/exports/abc.zip', '/var/lib/qrauth/exports')).toBe(true);
    expect(isInExportDir('/var/lib/qrauth/exports/../keys/k.pem', '/var/lib/qrauth/exports')).toBe(false);
    expect(isInExportDir('/var/lib/qrauth/exports/sub/abc.zip', '/var/lib/qrauth/exports')).toBe(false);
    expect(isInExportDir('/var/lib/qrauth/exports-other/abc.zip', '/var/lib/qrauth/exports')).toBe(false);
    expect(isInExportDir('/var/lib/qrauth/exports', '/var/lib/qrauth/exports')).toBe(false);
  });
});
