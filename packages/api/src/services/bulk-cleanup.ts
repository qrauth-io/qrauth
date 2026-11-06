import type { PrismaClient } from '@prisma/client';
import { readdir, stat, unlink } from 'node:fs/promises';
import { join, resolve, sep } from 'node:path';
import { BULK_ARTIFACT_TTL_HOURS } from '@qrauth/shared';

import { config } from '../lib/config.js';
import { finishBulkJob } from './bulk-jobs.js';

/**
 * Bulk job housekeeping (ADR-0008 D9), run by the hourly cleanup worker:
 *   - a RUNNING job that has not reported progress for 15 minutes, or a job
 *     QUEUED for 2 hours, was interrupted (restart, crash): FAILED, with its
 *     bulk.finish entry, so the organization can start another;
 *   - an ended job is deleted with its ZIP 24 h after it ended;
 *   - a file in the export directory with no job and older than 24 h (a
 *     crash between writing and recording) is deleted.
 */

export const STALE_RUNNING_MS = 15 * 60 * 1000;
export const STALE_QUEUED_MS = 2 * 3600 * 1000;
const ARTIFACT_TTL_MS = BULK_ARTIFACT_TTL_HOURS * 3600 * 1000;

/** True when `path` is a file directly inside the export directory (never follow a stored path elsewhere). */
export function isInExportDir(path: string, dir = config.bulk.exportDir): boolean {
  const root = resolve(dir) + sep;
  const target = resolve(path);
  return target.startsWith(root) && !target.slice(root.length).includes(sep);
}

async function removeFile(path: string | null): Promise<void> {
  if (!path || !isInExportDir(path)) return;
  await unlink(path).catch((err: NodeJS.ErrnoException) => {
    if (err.code !== 'ENOENT') throw err;
  });
  await unlink(`${path}.part`).catch(() => undefined);
}

export interface BulkSweepResult {
  interrupted: number;
  deleted: number;
  orphanFiles: number;
}

export async function sweepBulkJobs(prisma: PrismaClient, now = new Date()): Promise<BulkSweepResult> {
  const stale = await prisma.bulkJob.findMany({
    where: {
      OR: [
        { status: 'RUNNING', updatedAt: { lt: new Date(now.getTime() - STALE_RUNNING_MS) } },
        { status: 'QUEUED', updatedAt: { lt: new Date(now.getTime() - STALE_QUEUED_MS) } },
      ],
    },
  });
  let interrupted = 0;
  for (const job of stale) {
    await removeFile(job.kind === 'EXPORT' ? join(config.bulk.exportDir, `${job.id}.zip`) : null);
    const ended = await finishBulkJob(
      prisma,
      job,
      'FAILED',
      { succeeded: job.succeeded, failed: job.failed, skipped: job.skipped, error: 'The job was interrupted; start it again.' },
      { interrupted: true },
    );
    if (ended) interrupted++;
  }

  const expired = await prisma.bulkJob.findMany({
    where: { status: { in: ['SUCCEEDED', 'FAILED'] }, expiresAt: { lt: now } },
    select: { id: true, filePath: true },
  });
  for (const job of expired) await removeFile(job.filePath);
  const { count: deleted } = expired.length
    ? await prisma.bulkJob.deleteMany({ where: { id: { in: expired.map((j) => j.id) } } })
    : { count: 0 };

  return { interrupted, deleted, orphanFiles: await removeOrphanFiles(prisma, now) };
}

async function removeOrphanFiles(prisma: PrismaClient, now: Date): Promise<number> {
  let names: string[];
  try {
    names = await readdir(config.bulk.exportDir);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return 0;
    throw err;
  }
  let removed = 0;
  for (const name of names) {
    const match = /^([a-z0-9]+)\.zip(\.part)?$/i.exec(name);
    if (!match) continue;
    const path = join(config.bulk.exportDir, name);
    const info = await stat(path).catch(() => null);
    if (!info?.isFile() || now.getTime() - info.mtimeMs < ARTIFACT_TTL_MS) continue;
    const job = await prisma.bulkJob.findUnique({ where: { id: match[1] }, select: { id: true } });
    if (job) continue;
    await unlink(path).catch(() => undefined);
    removed++;
  }
  return removed;
}
