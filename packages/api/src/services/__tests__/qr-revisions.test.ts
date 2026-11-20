import { describe, expect, it } from 'vitest';

import { diffSnapshots, revisionContext, snapshot, TRACKED_FIELDS, type Snapshot } from '../qr-revisions.js';

const ROW = {
  destinationUrl: 'https://a.example.test/',
  content: null,
  style: { version: 2, dots: { shape: 'square' } },
  expiresAt: new Date('2027-01-02T03:04:05.678Z'),
  scanMode: 'FLASH' as const,
  status: 'ACTIVE' as const,
};

describe('snapshot', () => {
  it('holds exactly the tracked fields, dates as ISO strings', () => {
    const s = snapshot(ROW);
    expect(Object.keys(s).sort()).toEqual([...TRACKED_FIELDS].sort());
    expect(s.expiresAt).toBe('2027-01-02T03:04:05.678Z');
    expect(snapshot({ ...ROW, expiresAt: null }).expiresAt).toBeNull();
  });
});

describe('diffSnapshots', () => {
  const base: Snapshot = snapshot(ROW);

  it('is empty when nothing tracked changed', () => {
    expect(diffSnapshots(base, { ...base })).toEqual({});
  });

  it('ignores JSON key order (JSONB reorders keys)', () => {
    expect(diffSnapshots(base, { ...base, style: { dots: { shape: 'square' }, version: 2 } })).toEqual({});
  });

  it('reports each changed field with before and after', () => {
    const after = { ...base, destinationUrl: 'https://b.example.test/', status: 'REVOKED', expiresAt: null };
    expect(diffSnapshots(base, after)).toEqual({
      destinationUrl: { before: 'https://a.example.test/', after: 'https://b.example.test/' },
      expiresAt: { before: '2027-01-02T03:04:05.678Z', after: null },
      status: { before: 'ACTIVE', after: 'REVOKED' },
    });
  });
});

describe('revisionContext', () => {
  const request = (user: object) => ({ id: 'req-1', user }) as never;

  it('names the API key when one authenticated the request', () => {
    expect(revisionContext(request({ id: 'api-key', orgId: 'o', role: 'MEMBER', email: '', apiKeyId: 'key_1' }))).toEqual({
      actor: { type: 'API_KEY', apiKeyId: 'key_1' },
      requestId: 'req-1',
    });
  });

  it('names the user otherwise', () => {
    expect(revisionContext(request({ id: 'user_1', orgId: 'o', role: 'OWNER', email: 'a@b.c' }))).toEqual({
      actor: { type: 'USER', userId: 'user_1' },
      requestId: 'req-1',
    });
  });
});
