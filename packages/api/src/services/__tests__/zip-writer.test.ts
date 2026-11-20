import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { strFromU8, unzipSync } from 'fflate';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { ZipFileWriter, ZipSizeCapError, zipEntryName } from '../zip-writer.js';

describe('zipEntryName', () => {
  it('keeps letters of any script and the token', () => {
    expect(zipEntryName('Μενού τραπέζι 1', 'AbC123', 'svg')).toBe('Μενού-τραπέζι-1_AbC123.svg');
    expect(zipEntryName(null, 'AbC123', 'png')).toBe('AbC123.png');
  });

  it('never produces a path: separators, dot segments and leading dots are removed', () => {
    for (const label of ['../../etc/passwd', '..\\..\\windows\\system32', '/abs/path', '.hidden', 'a/../../b', 'C:\\x', '\u0000nul\r\nline']) {
      const name = zipEntryName(label, 'tok', 'svg');
      expect(name).not.toMatch(/[/\\:\u0000\r\n]/);
      expect(name).not.toMatch(/^\./);
      expect(name).not.toContain('..');
      expect(name.endsWith('_tok.svg')).toBe(true);
    }
  });

  it('keeps unsafe characters out of the token and extension and caps the label part', () => {
    expect(zipEntryName('x', '../tok', '/svg')).toBe('x_tok.svg');
    expect(zipEntryName('a'.repeat(200), 't', 'svg')).toBe(`${'a'.repeat(48)}_t.svg`);
  });
});

describe('ZipFileWriter', () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'zip-writer-test-'));
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  it('writes a valid archive under its final name, with UTF-8 entry names', async () => {
    const path = join(dir, 'out.zip');
    const zip = new ZipFileWriter(path, 1024 * 1024);
    await zip.add('Καφές_t1.svg', Buffer.from('<svg/>'), true);
    await zip.add('t2.png', Buffer.from([0x89, 0x50, 0x4e, 0x47]), false);
    const size = await zip.close();
    expect(existsSync(`${path}.part`)).toBe(false);
    expect(size).toBe(readFileSync(path).length);
    const files = unzipSync(readFileSync(path));
    expect(Object.keys(files).sort()).toEqual(['t2.png', 'Καφές_t1.svg']);
    expect(strFromU8(files['Καφές_t1.svg'])).toBe('<svg/>');
  });

  it('stops at the size cap before writing the entry, and abort removes the partial file', async () => {
    const path = join(dir, 'capped.zip');
    const zip = new ZipFileWriter(path, 10);
    await zip.add('a.svg', Buffer.alloc(8, 0x61), true);
    await expect(zip.add('b.svg', Buffer.alloc(3, 0x62), true)).rejects.toBeInstanceOf(ZipSizeCapError);
    expect(zip.uncompressedBytes).toBe(8);
    await zip.abort();
    expect(existsSync(`${path}.part`)).toBe(false);
    expect(existsSync(path)).toBe(false);
  });

  it('streams large archives without holding them in memory', async () => {
    const path = join(dir, 'big.zip');
    const zip = new ZipFileWriter(path, 64 * 1024 * 1024);
    const chunk = Buffer.alloc(256 * 1024, 7);
    for (let i = 0; i < 64; i++) await zip.add(`f${i}.png`, chunk, false);
    expect(await zip.close()).toBeGreaterThan(16 * 1024 * 1024);
  });
});
