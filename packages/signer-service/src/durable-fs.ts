import { randomBytes } from 'node:crypto';
import { link, open, rename, unlink } from 'node:fs/promises';
import { dirname } from 'node:path';

/**
 * Durable file writes for the keys directory: key envelopes (never
 * overwritten) and the tree-head state (replaced atomically).
 */

/** fsync a directory so a completed link, rename or unlink in it survives a crash. */
export async function syncDir(dir: string): Promise<void> {
  const handle = await open(dir, 'r');
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

async function writeTemp(path: string, contents: string): Promise<string> {
  const tmp = `${path}.tmp.${randomBytes(8).toString('hex')}`;
  const handle = await open(tmp, 'wx', 0o600);
  try {
    await handle.writeFile(contents, 'utf8');
    await handle.sync();
  } finally {
    await handle.close();
  }
  return tmp;
}

/**
 * Write a new file durably: temp file with mode 0600, fsync, hard-link to the
 * final name (fails with EEXIST instead of overwriting), remove the temp name,
 * fsync the directory. The final name must not exist yet.
 */
export async function writeNewFile(path: string, contents: string): Promise<void> {
  const tmp = await writeTemp(path, contents);
  try {
    await link(tmp, path);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'EEXIST') {
      throw new Error(`refusing to overwrite existing key file ${path}`);
    }
    throw err;
  } finally {
    await unlink(tmp).catch(() => {});
  }
  await syncDir(dirname(path));
}

/**
 * Replace a file atomically: temp file with mode 0600, fsync, rename over the
 * final name, fsync the directory. Until the rename, readers see the previous
 * contents; after it, the new ones. `beforeRename` is a test hook that
 * simulates a crash between the write and the rename.
 */
export async function replaceFile(
  path: string,
  contents: string,
  opts: { beforeRename?: () => void | Promise<void> } = {},
): Promise<void> {
  const tmp = await writeTemp(path, contents);
  try {
    await opts.beforeRename?.();
    await rename(tmp, path);
  } catch (err) {
    await unlink(tmp).catch(() => {});
    throw err;
  }
  await syncDir(dirname(path));
}

/** Remove a file and make the removal durable. */
export async function removeFile(path: string): Promise<void> {
  await unlink(path).catch(() => {});
  await syncDir(dirname(path)).catch(() => {});
}
