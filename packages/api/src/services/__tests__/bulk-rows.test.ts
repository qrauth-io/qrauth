import { describe, expect, it } from 'vitest';

import { checkRowFields, draftOf, dryRunRowView, parseExpiresAt, splitTags, type BulkRowDraft } from '../bulk-rows.js';

const NOW = new Date('2026-11-05T12:00:00Z');
const draft = (over: Partial<BulkRowDraft> = {}): BulkRowDraft => ({
  row: 2,
  url: 'https://example.com/a',
  label: null,
  folder: null,
  tags: [],
  expiresAt: null,
  scanMode: null,
  ...over,
});
const codes = (d: BulkRowDraft) => checkRowFields(d, NOW).issues.map((i) => i.code);

describe('parseExpiresAt', () => {
  it('reads a date as the end of that day in UTC', () => {
    expect(parseExpiresAt('2027-12-31')).toBe('2027-12-31T23:59:59.000Z');
  });

  it('reads ISO datetimes, with or without an offset', () => {
    expect(parseExpiresAt('2027-01-01T10:00:00Z')).toBe('2027-01-01T10:00:00.000Z');
    expect(parseExpiresAt('2027-01-01T12:00:00+02:00')).toBe('2027-01-01T10:00:00.000Z');
  });

  it('refuses other formats and dates that do not exist', () => {
    for (const value of ['31/12/2027', '2027-02-30', 'tomorrow', '20271231', '2027-13-01']) expect(parseExpiresAt(value)).toBeNull();
  });
});

describe('parseExpiresAt with a time zone', () => {
  it('ends a date at 23:59:59 local time in the uploader\'s zone', () => {
    expect(parseExpiresAt('2027-12-31', 'UTC')).toBe('2027-12-31T23:59:59.000Z');
    expect(parseExpiresAt('2027-12-31', 'Europe/Athens')).toBe('2027-12-31T21:59:59.000Z');
    expect(parseExpiresAt('2027-07-15', 'Europe/Athens')).toBe('2027-07-15T20:59:59.000Z');
  });

  it('uses the offset in force at the end of a DST change day', () => {
    // Athens: summer time from 28 March 2027, winter time from 31 October 2027.
    expect(parseExpiresAt('2027-03-27', 'Europe/Athens')).toBe('2027-03-27T21:59:59.000Z');
    expect(parseExpiresAt('2027-03-28', 'Europe/Athens')).toBe('2027-03-28T20:59:59.000Z');
    expect(parseExpiresAt('2027-10-30', 'Europe/Athens')).toBe('2027-10-30T20:59:59.000Z');
    expect(parseExpiresAt('2027-10-31', 'Europe/Athens')).toBe('2027-10-31T21:59:59.000Z');
    expect(parseExpiresAt('2027-03-14', 'America/New_York')).toBe('2027-03-15T03:59:59.000Z');
  });

  it('ignores the zone for datetimes, which carry their own offset', () => {
    expect(parseExpiresAt('2027-01-01T12:00:00+02:00', 'America/New_York')).toBe('2027-01-01T10:00:00.000Z');
  });

  it('keeps the written date and converts it in checkRowFields; a second check changes nothing', () => {
    const { draft: d } = draftOf(
      { row: 2, cells: { url: 'https://a.test', label: '', folder: '', tags: '', expiresAt: '2027-12-31', scanMode: '' }, fieldCountMismatch: null },
      ',',
    );
    expect(d.expiresDate).toBe('2027-12-31');
    const once = checkRowFields(d, NOW, 'Europe/Athens').draft;
    expect(once).toMatchObject({ expiresAt: '2027-12-31T21:59:59.000Z', expiresDate: '2027-12-31' });
    expect(checkRowFields(once, NOW).draft).toEqual(once);
    expect(dryRunRowView({ draft: once, issues: [], webRiskUnavailable: false })).toMatchObject({ expiresDate: '2027-12-31' });
  });

  it('marks a date that already ended in the zone as past', () => {
    const now = new Date('2026-11-05T22:30:00Z'); // 00:30 on 6 November in Athens
    expect(checkRowFields(draft({ expiresAt: '2026-11-05' }), now, 'Europe/Athens').issues.map((i) => i.code)).toEqual(['expires-past']);
    expect(checkRowFields(draft({ expiresAt: '2026-11-05' }), now, 'UTC').issues).toEqual([]);
  });
});

describe('splitTags', () => {
  it('splits on ; in a comma file and on | in a semicolon file', () => {
    expect(splitTags('menu; table-1 ;;', ',')).toEqual(['menu', 'table-1']);
    expect(splitTags('μενού|τραπέζι', ';')).toEqual(['μενού', 'τραπέζι']);
    expect(splitTags('a;b', ';')).toEqual(['a;b']);
  });

  it('drops case-insensitive duplicates, keeping the first spelling', () => {
    expect(splitTags('Menu;menu;MENU;Bar', ',')).toEqual(['Menu', 'Bar']);
  });
});

describe('checkRowFields', () => {
  it('normalises the URL with the single-create rules', () => {
    expect(checkRowFields(draft({ url: 'HTTPS://Example.COM' }), NOW).draft.url).toBe('https://example.com/');
  });

  it('refuses what single create refuses', () => {
    expect(codes(draft({ url: '' }))).toEqual(['url-required']);
    expect(codes(draft({ url: 'javascript:alert(1)' }))).toEqual(['url-invalid']);
    expect(codes(draft({ url: 'https://192.168.1.1/' }))).toEqual(['url-invalid']);
    expect(codes(draft({ url: 'https://intranet/' }))).toEqual(['url-invalid']);
    expect(codes(draft({ label: 'x'.repeat(201) }))).toEqual(['label-too-long']);
    expect(codes(draft({ scanMode: 'FAST' as never }))).toEqual(['scan-mode-invalid']);
  });

  it('checks the expiry, folder and tags', () => {
    expect(codes(draft({ expiresAt: '2026-11-04' }))).toEqual(['expires-past']);
    expect(codes(draft({ expiresAt: 'next week' }))).toEqual(['expires-invalid']);
    expect(checkRowFields(draft({ expiresAt: '2027-06-30' }), NOW).draft.expiresAt).toBe('2027-06-30T23:59:59.000Z');
    expect(codes(draft({ folder: 'f'.repeat(65) }))).toEqual(['folder-too-long']);
    expect(codes(draft({ tags: ['t'.repeat(33)] }))).toEqual(['tag-too-long']);
    expect(codes(draft({ tags: Array.from({ length: 21 }, (_, i) => `t${i}`) }))).toEqual(['too-many-tags']);
  });

  it('is idempotent, so the job can run it again on the dry run\'s output', () => {
    const once = checkRowFields(draft({ url: 'https://EXAMPLE.com/a', expiresAt: '2027-06-30', scanMode: 'PAGE' }), NOW).draft;
    expect(checkRowFields(once, NOW)).toEqual({ draft: once, issues: [] });
  });

  it('keeps formula-looking labels as written', () => {
    expect(checkRowFields(draft({ label: '=1+1' }), NOW)).toMatchObject({ draft: { label: '=1+1' }, issues: [] });
  });
});

describe('draftOf and dryRunRowView', () => {
  it('upper-cases scanMode, splits tags and reports a field-count mismatch', () => {
    const { draft: d, issues } = draftOf(
      {
        row: 4,
        cells: { url: 'https://a.test', label: '', folder: 'F', tags: 'x|y', expiresAt: '', scanMode: 'page' },
        fieldCountMismatch: { expected: 6, actual: 7 },
      },
      ';',
    );
    expect(d).toEqual({ row: 4, url: 'https://a.test', label: null, folder: 'F', tags: ['x', 'y'], expiresAt: null, expiresDate: null, scanMode: 'PAGE' });
    expect(issues.map((i) => i.code)).toEqual(['field-count']);
  });

  it('lists errors before warnings and takes the first as the row code', () => {
    const view = dryRunRowView({
      draft: draft(),
      issues: [
        { severity: 'warning', code: 'lookalike', message: 'w' },
        { severity: 'error', code: 'destination-flagged', message: 'e' },
      ],
      webRiskUnavailable: false,
    });
    expect(view).toMatchObject({ status: 'error', code: 'destination-flagged', messages: ['e', 'w'] });
  });
});
