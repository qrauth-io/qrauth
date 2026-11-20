import { mkdtempSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../lib/queue.js', () => ({ bulkImportQueue: {}, exportQueue: {}, createQueueConnection: vi.fn() }));
vi.mock('../bulk-import.js', () => ({ runImportJob: vi.fn() }));
vi.mock('../bulk-export.js', () => ({ runExportJob: vi.fn() }));

const { checkExportDir } = await import('../bulk.js');

const log = () => ({ info: vi.fn(), error: vi.fn() }) as unknown as Parameters<typeof checkExportDir>[0] & { info: ReturnType<typeof vi.fn>; error: ReturnType<typeof vi.fn> };

describe('checkExportDir', () => {
  const root = mkdtempSync(join(tmpdir(), 'export-dir-test-'));
  afterEach(() => vi.clearAllMocks());

  it('creates a missing directory with mode 0700 and logs that it is writable', async () => {
    const dir = join(root, 'exports');
    const l = log();
    expect(await checkExportDir(l, dir)).toBe(true);
    expect(statSync(dir).mode & 0o777).toBe(0o700);
    expect(l.info).toHaveBeenCalledWith({ exportDir: dir }, 'Bulk export directory is writable');
  });

  it('logs an error, without throwing, when the path cannot be a directory', async () => {
    const file = join(root, 'a-file');
    writeFileSync(file, 'x');
    const l = log();
    expect(await checkExportDir(l, join(file, 'exports'))).toBe(false);
    expect(l.error).toHaveBeenCalledOnce();
    rmSync(root, { recursive: true, force: true });
  });
});
