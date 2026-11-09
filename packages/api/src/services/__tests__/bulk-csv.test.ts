import { describe, expect, it } from 'vitest';
import { BULK_IMPORT_MAX_BYTES, BULK_IMPORT_TEMPLATE_CSV } from '@qrauth/shared';

import { BulkCsvError, detectDelimiter, parseImportCsv } from '../bulk-csv.js';

const csv = (text: string) => Buffer.from(text, 'utf8');

function refusal(bytes: Buffer): BulkCsvError {
  try {
    parseImportCsv(bytes);
  } catch (err) {
    if (err instanceof BulkCsvError) return err;
    throw err;
  }
  throw new Error('expected a BulkCsvError');
}

describe('detectDelimiter', () => {
  it('picks the delimiter used in the header row', () => {
    expect(detectDelimiter('url,label,folder\nhttps://a.test;x,y')).toBe(',');
    expect(detectDelimiter('url;label;folder\nhttps://a.test,x;y')).toBe(';');
  });

  it('ignores delimiters inside quoted header names and defaults to comma for one column', () => {
    expect(detectDelimiter('"url;x",label\n')).toBe(',');
    expect(detectDelimiter('url\nhttps://a.test')).toBe(',');
  });
});

describe('parseImportCsv', () => {
  it('reads the template', () => {
    const parsed = parseImportCsv(csv(BULK_IMPORT_TEMPLATE_CSV));
    expect(parsed.delimiter).toBe(',');
    expect(parsed.columns).toEqual(['url', 'label', 'folder', 'tags', 'expiresAt', 'scanMode']);
    expect(parsed.rows).toHaveLength(2);
    expect(parsed.rows[0].cells).toMatchObject({ url: 'https://example.com/menu', tags: 'menu;table-1', scanMode: 'FLASH' });
  });

  it('accepts a UTF-8 BOM and Greek text, with a semicolon delimiter', () => {
    const parsed = parseImportCsv(csv('\uFEFFurl;label;folder\r\nhttps://example.gr/;Καλημέρα κόσμε;Φάκελος\r\n'));
    expect(parsed.delimiter).toBe(';');
    expect(parsed.columns[0]).toBe('url');
    expect(parsed.rows[0].cells).toMatchObject({ url: 'https://example.gr/', label: 'Καλημέρα κόσμε', folder: 'Φάκελος' });
  });

  it('reads quoted fields with delimiters, quotes and line breaks; row numbers count records', () => {
    const parsed = parseImportCsv(csv('url,label\n"https://a.test/x","Line one\nline two, ""quoted"""\nhttps://b.test,plain\n'));
    expect(parsed.rows.map((r) => [r.row, r.cells.label])).toEqual([
      [2, 'Line one\nline two, "quoted"'],
      [3, 'plain'],
    ]);
  });

  it('matches header names case-insensitively, in any order, and fills missing columns with blanks', () => {
    const parsed = parseImportCsv(csv('Label, URL ,SCANMODE\nhello,https://a.test,page'));
    expect(parsed.columns).toEqual(['label', 'url', 'scanMode']);
    expect(parsed.rows[0].cells).toMatchObject({ url: 'https://a.test', label: 'hello', scanMode: 'page', folder: '', tags: '' });
  });

  it('skips blank lines and all-blank rows but keeps spreadsheet row numbers', () => {
    const parsed = parseImportCsv(csv('url;label\n\nhttps://a.test;a\n;;\nhttps://b.test;b\n'));
    expect(parsed.rows.map((r) => r.row)).toEqual([3, 5]);
  });

  it('flags rows with a different number of fields than the header', () => {
    const parsed = parseImportCsv(csv('url,label\nhttps://a.test,a,extra\nhttps://b.test'));
    expect(parsed.rows[0].fieldCountMismatch).toEqual({ expected: 2, actual: 3 });
    expect(parsed.rows[1].fieldCountMismatch).toEqual({ expected: 2, actual: 1 });
  });

  it('keeps formula-looking cells as plain text', () => {
    const parsed = parseImportCsv(csv('url,label\nhttps://a.test,=HYPERLINK("http://x")\n'));
    expect(parsed.rows[0].cells.label).toBe('=HYPERLINK("http://x")');
  });

  it('refuses unknown, duplicate and missing columns', () => {
    expect(refusal(csv('url,colour\nhttps://a.test,red'))).toMatchObject({ code: 'header-unknown-columns', message: expect.stringContaining('"colour"') });
    expect(refusal(csv('url,,label\nhttps://a.test,,x')).message).toContain('(empty)');
    expect(refusal(csv('url,label,URL\nhttps://a.test,x,y'))).toMatchObject({ code: 'header-duplicate-columns' });
    expect(refusal(csv('label\nx'))).toMatchObject({ code: 'header-missing-url' });
  });

  it('refuses empty files, header-only files and malformed quoting', () => {
    expect(refusal(csv(''))).toMatchObject({ code: 'file-empty' });
    expect(refusal(csv('\uFEFF  \n'))).toMatchObject({ code: 'file-empty' });
    expect(refusal(csv('url,label\n'))).toMatchObject({ code: 'no-rows' });
    expect(refusal(csv('url,label\n"https://a.test,unterminated\n'))).toMatchObject({ code: 'csv-malformed' });
  });

  it('refuses binary files and legacy encodings with an Excel hint', () => {
    expect(refusal(Buffer.from([0x50, 0x4b, 0x03, 0x04, 0x14, 0x00, 0x00]))).toMatchObject({ code: 'file-not-text' });
    // "url\nΚαφές" in Windows-1253, as Excel's plain "CSV" saves Greek.
    const win1253 = Buffer.concat([csv('url,label\nhttps://a.test,'), Buffer.from([0xca, 0xe1, 0xf6, 0xdd, 0xf2])]);
    const err = refusal(win1253);
    expect(err.code).toBe('file-not-utf8');
    expect(err.message).toContain('CSV UTF-8');
  });

  it('refuses files over the size limit', () => {
    expect(refusal(Buffer.alloc(BULK_IMPORT_MAX_BYTES + 1, 0x61))).toMatchObject({ code: 'file-too-large' });
  });

  it('accepts 1,000 data rows and refuses 1,001', () => {
    const rows = (n: number) => csv('url\n' + Array.from({ length: n }, (_, i) => `https://a.test/${i}`).join('\n'));
    expect(parseImportCsv(rows(1000)).rows).toHaveLength(1000);
    expect(refusal(rows(1001))).toMatchObject({ code: 'too-many-rows', message: expect.stringContaining('1,000') });
  });
});
