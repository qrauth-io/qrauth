import { Worker, type Job } from 'bullmq';
import { constants } from 'node:fs';
import { access, mkdir } from 'node:fs/promises';

import { config } from '../lib/config.js';

import { bulkImportQueue, createQueueConnection, exportQueue } from '../lib/queue.js';
import { runExportJob } from './bulk-export.js';
import { runImportJob, type BulkWorkerDeps } from './bulk-import.js';

/**
 * Bulk import and export workers (ADR-0008 D9). They run in the API process
 * like the others, but need the server's signing services, so server.ts
 * starts them with those after buildServer(). Each organization has at most
 * one active job per kind (bulk_jobs index); across organizations, one
 * import and one export run at a time (others wait in the queue).
 */

export interface BulkJobData {
  bulkJobId: string;
}

/** One import at a time in the process: each issues 64 codes at once (signing batch), which bounds database connections. */
const IMPORT_WORKER_CONCURRENCY = 1;
const EXPORT_WORKER_CONCURRENCY = 1;

let importWorker: Worker<BulkJobData> | undefined;
let exportWorker: Worker<BulkJobData> | undefined;

/**
 * Creates the export directory if needed (mode 0700) and checks it is
 * writable, logging the result at startup. A failure does not stop the
 * server: exports fail with an error until the directory is fixed.
 */
export async function checkExportDir(log: BulkWorkerDeps['log'], dir = config.bulk.exportDir): Promise<boolean> {
  try {
    await mkdir(dir, { recursive: true, mode: 0o700 });
    await access(dir, constants.W_OK);
    log.info({ exportDir: dir }, 'Bulk export directory is writable');
    return true;
  } catch (err) {
    log.error({ err, exportDir: dir }, 'Bulk export directory is not writable; ZIP exports will fail');
    return false;
  }
}

export function registerBulkWorkers(deps: BulkWorkerDeps): void {
  void checkExportDir(deps.log);
  importWorker = new Worker<BulkJobData>('qrauth-bulk-imports', (job: Job<BulkJobData>) => runImportJob(deps, job.data.bulkJobId), {
    connection: createQueueConnection(),
    concurrency: IMPORT_WORKER_CONCURRENCY,
  });
  exportWorker = new Worker<BulkJobData>('qrauth-exports', (job: Job<BulkJobData>) => runExportJob(deps, job.data.bulkJobId), {
    connection: createQueueConnection(),
    concurrency: EXPORT_WORKER_CONCURRENCY,
  });
  for (const worker of [importWorker, exportWorker]) {
    worker.on('failed', (job, err) => deps.log.error({ err, bulkJobId: job?.data.bulkJobId }, 'Bulk worker job failed'));
  }
}

export async function closeBulkWorkers(): Promise<void> {
  await Promise.all([importWorker?.close(), exportWorker?.close()]);
}

/** Queue a bulk job by its bulk_jobs id (the BullMQ job id too, so it is queued once). */
export async function enqueueBulkJob(kind: 'IMPORT' | 'EXPORT', bulkJobId: string): Promise<void> {
  const queue = kind === 'IMPORT' ? bulkImportQueue : exportQueue;
  await queue.add(kind === 'IMPORT' ? 'import' : 'export', { bulkJobId }, { jobId: bulkJobId });
}
