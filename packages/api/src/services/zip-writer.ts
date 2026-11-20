import { createWriteStream, type WriteStream } from 'node:fs';
import { rename, unlink } from 'node:fs/promises';
import { once } from 'node:events';
import { Zip, ZipDeflate, ZipPassThrough } from 'fflate';

/**
 * A streaming ZIP file for bulk exports (ADR-0008 D9): entries are written
 * to disk as they are added (fflate), with a cap on the uncompressed total,
 * and the file appears under its final name only when complete.
 */

/** The uncompressed total would pass the cap; the partial file is deleted. */
export class ZipSizeCapError extends Error {
  constructor(readonly capBytes: number) {
    super(`The export is larger than ${Math.round(capBytes / (1024 * 1024))} MB.`);
    this.name = 'ZipSizeCapError';
  }
}

/** Longest name part taken from a label. */
const LABEL_PART_MAX = 48;

/**
 * A safe entry name from a code's label and token: letters and digits of any
 * script, `.`, `_` and `-` only; anything else (path separators, `..`,
 * control characters, spaces) becomes `-`, and the name never starts with a
 * dot or dash. The token keeps names unique.
 */
export function zipEntryName(label: string | null, token: string, extension: string): string {
  const clean = (value: string) =>
    value
      .normalize('NFC')
      .replace(/[^\p{L}\p{N}._-]+/gu, '-')
      .replace(/\.{2,}/g, '.')
      .replace(/^[.-]+|[.-]+$/g, '');
  const safeToken = token.replace(/[^A-Za-z0-9_-]/g, '');
  const labelPart = clean(label ?? '').slice(0, LABEL_PART_MAX).replace(/[.-]+$/, '');
  const ext = extension.replace(/[^a-z0-9]/g, '');
  return labelPart ? `${labelPart}_${safeToken}.${ext}` : `${safeToken}.${ext}`;
}

export class ZipFileWriter {
  private readonly zip: Zip;
  private readonly out: WriteStream;
  private readonly partPath: string;
  private uncompressed = 0;
  private failure: Error | null = null;
  private readonly finished: Promise<void>;

  constructor(
    private readonly finalPath: string,
    private readonly capBytes: number,
  ) {
    this.partPath = `${finalPath}.part`;
    this.out = createWriteStream(this.partPath, { mode: 0o600 });
    let resolveDone!: () => void;
    let rejectDone!: (err: Error) => void;
    this.finished = new Promise<void>((resolve, reject) => {
      resolveDone = resolve;
      rejectDone = reject;
    });
    this.finished.catch(() => undefined);
    this.out.on('error', (err) => {
      this.failure ??= err;
      rejectDone(err);
    });
    this.zip = new Zip((err, chunk, final) => {
      if (err) {
        this.failure ??= err;
        rejectDone(err);
        return;
      }
      this.out.write(chunk);
      if (final) {
        this.out.end((endErr?: Error | null) => {
          if (endErr) {
            this.failure ??= endErr;
            rejectDone(endErr);
          } else resolveDone();
        });
      }
    });
  }

  /** Bytes added so far, before compression. */
  get uncompressedBytes(): number {
    return this.uncompressed;
  }

  /**
   * Add one entry. `compress` deflates it (SVG, CSV); PNG is stored as is.
   * Throws ZipSizeCapError, before writing anything, when the entry would
   * pass the cap. Waits for the file to drain, so memory stays bounded.
   */
  async add(name: string, body: Uint8Array, compress: boolean): Promise<void> {
    if (this.failure) throw this.failure;
    if (this.uncompressed + body.length > this.capBytes) throw new ZipSizeCapError(this.capBytes);
    this.uncompressed += body.length;
    const entry = compress ? new ZipDeflate(name, { level: 6 }) : new ZipPassThrough(name);
    this.zip.add(entry);
    entry.push(body, true);
    if (this.out.writableNeedDrain) await once(this.out, 'drain');
  }

  /** Finish the archive and move it to its final name; returns its size in bytes. */
  async close(): Promise<number> {
    if (this.failure) throw this.failure;
    this.zip.end();
    await this.finished;
    if (this.failure) throw this.failure;
    await rename(this.partPath, this.finalPath);
    return this.out.bytesWritten;
  }

  /** Stop and delete the partial file. */
  async abort(): Promise<void> {
    this.zip.terminate();
    // Wait for the stream to close: if it is still opening the file, deleting
    // first would leave the file to be created afterwards.
    if (!this.out.closed) {
      const closed = once(this.out, 'close').catch(() => undefined);
      this.out.destroy();
      await closed;
    }
    await unlink(this.partPath).catch(() => undefined);
  }
}
