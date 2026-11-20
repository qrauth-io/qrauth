import type { BulkJob, PrismaClient, QRCode } from '@prisma/client';
import type { FastifyBaseLogger } from 'fastify';
import { mkdir, unlink } from 'node:fs/promises';
import { join } from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import { BULK_EXPORT_MAX_BYTES, isIssuerVerified, type BulkExportFormat } from '@qrauth/shared';

import { CUSTOMER_LOGO_ORG_SELECT, logoEligibility } from '../config/plan-limits.js';
import { config } from '../lib/config.js';
import { CSV_UTF8_BOM, csvLine } from '../lib/csv.js';
import { buildVerificationUrl } from '../lib/qrcode-access.js';
import { isSemaphoreBusy } from '../lib/semaphore.js';
import { bulkStarterRefusal } from '../services/bulk-actor.js';
import type { ExportJobInput } from '../services/bulk-export.js';
import { finishBulkJob } from '../services/bulk-jobs.js';
import { LogoLibrary } from '../services/logo-library.js';
import { loadLogoBytes, renderExport, styleForRender, type ExportOptions } from '../services/qr-render.js';
import { ZipFileWriter, ZipSizeCapError, zipEntryName } from '../services/zip-writer.js';
import { claimJob } from './bulk-import.js';

/**
 * The bulk ZIP export job (ADR-0008 D9): renders each selected code in the
 * requested formats on the render service's export lane (issuance is served
 * first), streams the files and a manifest.csv into a ZIP in the export
 * directory, and stops at the size cap.
 */

/** Codes read from the database at once. */
const CODE_BATCH = 100;
/** Renders in flight for one export; the PNG lane allows 4 in the process. */
export const EXPORT_RENDER_CONCURRENCY = 2;
/** A busy render lane is retried this many times, waiting longer each time. */
const BUSY_RETRIES = 6;
const BUSY_BACKOFF_MS = 250;
const PROGRESS_EVERY_CODES = 25;
/** Room kept under the size cap for manifest.csv, so a full export does not fail at the last file. */
const MANIFEST_RESERVE_BYTES = 2 * 1024 * 1024;

export const MANIFEST_HEADER = ['file', 'format', 'token', 'label', 'destination', 'verifyUrl', 'status', 'note'] as const;

type CodeRow = Pick<QRCode, 'id' | 'token' | 'label' | 'destinationUrl' | 'style'>;

/** The export's absolute path for a job id (ids are cuids: no separators). */
export function exportPathFor(jobId: string): string {
  if (!/^[a-z0-9]+$/i.test(jobId)) throw new Error('Unexpected job id');
  return join(config.bulk.exportDir, `${jobId}.zip`);
}

function exportOptions(format: BulkExportFormat, png: ExportJobInput['png']): ExportOptions {
  if (format === 'svg') return { format: 'svg' };
  if (png && 'px' in png) return { format: 'png', px: png.px };
  if (png && 'sizeMm' in png) return { format: 'png', print: { sizeMm: png.sizeMm, dpi: png.dpi } };
  throw new RangeError('PNG needs a size');
}

async function renderWithRetry(run: () => Promise<Buffer>): Promise<Buffer> {
  for (let attempt = 0; ; attempt++) {
    try {
      return await run();
    } catch (err) {
      if (!isSemaphoreBusy(err) || attempt >= BUSY_RETRIES) throw err;
      await sleep(BUSY_BACKOFF_MS * 2 ** attempt);
    }
  }
}

export async function runExportJob(deps: { prisma: PrismaClient; log: FastifyBaseLogger }, jobId: string): Promise<void> {
  const { prisma, log } = deps;
  const job = await claimJob(prisma, jobId);
  if (!job) return;

  let zip: ZipFileWriter | null = null;
  try {
    const refusal = await bulkStarterRefusal(prisma, job);
    if (refusal) {
      await finishBulkJob(prisma, job, 'FAILED', { succeeded: 0, failed: 0, skipped: 0, error: refusal });
      return;
    }
    await mkdir(config.bulk.exportDir, { recursive: true, mode: 0o700 });
    const path = exportPathFor(job.id);
    zip = new ZipFileWriter(path, BULK_EXPORT_MAX_BYTES);
    const { succeeded, failed, skipped } = await writeExport(prisma, job, zip);
    const fileBytes = await zip.close();
    const recorded = await finishBulkJob(prisma, job, 'SUCCEEDED', { succeeded, failed, skipped, fileBytes, filePath: path }, { fileBytes });
    // The stale-job sweep failed it meanwhile: nothing points at the file.
    if (!recorded) await unlink(path).catch(() => undefined);
  } catch (err) {
    await zip?.abort();
    const error = err instanceof ZipSizeCapError ? `${err.message} Export fewer codes, or a smaller PNG size, at a time.` : 'The export stopped because of an internal error.';
    if (!(err instanceof ZipSizeCapError)) log.error({ err, jobId: job.id }, 'Bulk export job failed');
    const current = await prisma.bulkJob.findUnique({ where: { id: job.id } });
    await finishBulkJob(prisma, job, 'FAILED', {
      succeeded: current?.succeeded ?? 0,
      failed: current?.failed ?? 0,
      skipped: current?.skipped ?? 0,
      error,
    });
  }
}

async function writeExport(prisma: PrismaClient, job: BulkJob, zip: ZipFileWriter): Promise<{ succeeded: number; failed: number; skipped: number }> {
  const input = job.input as unknown as ExportJobInput;
  const orgId = job.organizationId;
  const org = await prisma.organization.findUniqueOrThrow({ where: { id: orgId }, select: CUSTOMER_LOGO_ORG_SELECT });
  const issuerVerified = isIssuerVerified(logoEligibility(org));
  const library = new LogoLibrary(prisma);
  // Logos are read once per job, not once per code.
  const logoCache = new Map<string, Promise<Uint8Array | null>>();
  const logos = {
    bytes: (organizationId: string, assetId: string) => {
      if (!logoCache.has(assetId)) logoCache.set(assetId, library.bytes(organizationId, assetId));
      return logoCache.get(assetId)!;
    },
  };

  const manifest: string[] = [CSV_UTF8_BOM + csvLine([...MANIFEST_HEADER])];
  let succeeded = 0;
  let failed = 0;
  let processed = 0;
  const found = new Set<string>();

  for (let start = 0; start < input.codeIds.length; start += CODE_BATCH) {
    const ids = input.codeIds.slice(start, start + CODE_BATCH);
    const rows = await prisma.qRCode.findMany({
      where: { id: { in: ids }, organizationId: orgId },
      select: { id: true, token: true, label: true, destinationUrl: true, style: true },
    });
    const byId = new Map(rows.map((r) => [r.id, r]));
    const ordered = ids.map((id) => byId.get(id)).filter((r): r is CodeRow => r !== undefined);

    // Render a few codes at a time; entries are added in selection order.
    for (let i = 0; i < ordered.length; i += EXPORT_RENDER_CONCURRENCY) {
      const group = ordered.slice(i, i + EXPORT_RENDER_CONCURRENCY);
      const rendered = await Promise.all(group.map((code) => renderCode(code, input, orgId, issuerVerified, logos)));
      for (const [k, code] of group.entries()) {
        found.add(code.id);
        const files = rendered[k];
        const ok = files.every((f) => f.body);
        for (const file of files) {
          if (file.body) {
            if (zip.uncompressedBytes + file.body.length > BULK_EXPORT_MAX_BYTES - MANIFEST_RESERVE_BYTES) throw new ZipSizeCapError(BULK_EXPORT_MAX_BYTES);
            await zip.add(file.name, file.body, file.format === 'svg');
          }
          manifest.push(
            csvLine([file.body ? file.name : '', file.format, code.token, code.label, code.destinationUrl, buildVerificationUrl(code.token), file.body ? 'ok' : 'error', file.note]),
          );
        }
        if (ok) succeeded++;
        else failed++;
        if (++processed % PROGRESS_EVERY_CODES === 0) {
          await prisma.bulkJob.update({ where: { id: job.id }, data: { processed, succeeded, failed } });
        }
      }
    }
  }

  // Codes deleted (or moved) since the export was requested.
  const skipped = input.codeIds.length - found.size;
  await zip.add('manifest.csv', Buffer.from(manifest.join(''), 'utf8'), true);
  await prisma.bulkJob.update({ where: { id: job.id }, data: { processed: input.codeIds.length, succeeded, failed, skipped } });
  return { succeeded, failed, skipped };
}

interface RenderedFile {
  name: string;
  format: BulkExportFormat;
  body: Buffer | null;
  note: string | null;
}

async function renderCode(
  code: CodeRow,
  input: ExportJobInput,
  orgId: string,
  issuerVerified: boolean,
  logos: { bytes(organizationId: string, assetId: string): Promise<Uint8Array | null> },
): Promise<RenderedFile[]> {
  const files: RenderedFile[] = [];
  for (const format of input.formats) {
    const name = zipEntryName(code.label, code.token, format);
    try {
      const style = styleForRender(code.style);
      const logo = await loadLogoBytes(style, orgId, logos);
      const opts = exportOptions(format, input.png);
      let notDrawn: readonly string[] = [];
      const body = await renderWithRetry(async () => {
        const result = await renderExport({ token: code.token, issuerVerified }, style, logo, opts, { lane: 'export' });
        notDrawn = result.notDrawn;
        return result.body;
      });
      files.push({ name, format, body, note: notDrawn.length > 0 ? `not drawn: ${notDrawn.join(', ')}` : null });
    } catch (err) {
      const note = err instanceof RangeError ? err.message : isSemaphoreBusy(err) ? 'renderer busy' : 'render failed';
      files.push({ name, format, body: null, note });
    }
  }
  return files;
}
