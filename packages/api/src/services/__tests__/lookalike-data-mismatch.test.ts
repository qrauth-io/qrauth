import { describe, expect, it, vi } from 'vitest';

/**
 * The startup preload when a bundled data file differs from the pinned
 * checksum (ADR-0007 D11): one comment line is appended to the Public
 * Suffix List as it is read, so the file still loads but its SHA-256
 * changes.
 */

vi.mock('node:fs', async (importOriginal) => {
  const fs = await importOriginal<typeof import('node:fs')>();
  const readFileSync = ((path: Parameters<typeof fs.readFileSync>[0], options?: unknown) => {
    const content = fs.readFileSync(path, options as never);
    return String(path).endsWith('public_suffix_list.dat') ? `${content}\n// changed\n` : content;
  }) as typeof fs.readFileSync;
  return { ...fs, default: { ...fs, readFileSync }, readFileSync };
});

const { PSL_FILE, PSL_SHA256 } = await import('../../lib/public-suffix.js');
const { preloadLookalikeData } = await import('../lookalike-data.js');

describe('startup preload with a changed data file', () => {
  it('the mock applies to the bundled PSL file', () => {
    expect(PSL_FILE.endsWith('public_suffix_list.dat')).toBe(true);
  });

  it('logs lookalike.data_checksum_mismatch as an error, with the line and the checksums', async () => {
    const info = vi.fn();
    const error = vi.fn();
    await preloadLookalikeData(async () => 251, { info, error });
    expect(info).not.toHaveBeenCalled();
    expect(error).toHaveBeenCalledTimes(1);
    const [fields, message] = error.mock.calls[0];
    expect(fields).toMatchObject({
      event: 'lookalike.data_checksum_mismatch',
      confusables: { matchesPinned: true },
      psl: { matchesPinned: false },
      references: 251,
    });
    expect(fields.psl.sha256).not.toBe(PSL_SHA256);
    expect(message).toMatch(/^Lookalike data: .*; loaded in \d+ ms .*: does not match the pinned checksums$/);
  });
});
