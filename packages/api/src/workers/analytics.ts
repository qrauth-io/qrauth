/**
 * Scan analytics worker (ADR-0006 D3): recomputes the daily rollups of
 * yesterday and today every 10 minutes, and runs the one-off backfill (D8)
 * when scans exist but no rollup does yet.
 */
import { Worker, type Job } from 'bullmq';
import type { PrismaClient } from '@prisma/client';

import { analyticsQueue, createQueueConnection } from '../lib/queue.js';
import { parseScanDevice } from '../lib/scan-device.js';
import { backfillAnalytics, refreshRecentRollups } from '../services/scan-analytics.js';

export const ROLLUP_REFRESH_EVERY_MS = 10 * 60 * 1000;
export const REFRESH_JOB_ID = 'analytics-rollup-refresh';
export const BACKFILL_JOB_ID = 'analytics-backfill';

export type AnalyticsJobName = 'refresh' | 'backfill';

export async function runAnalyticsJob(db: PrismaClient, name: string): Promise<unknown> {
  if (name === 'refresh') return { rows: await refreshRecentRollups(db) };
  if (name === 'backfill') {
    const result = await backfillAnalytics(db, parseScanDevice);
    console.info(`[analytics] backfill: ${result.scansEnriched} scans given device fields, ${result.days} days rolled up`);
    return result;
  }
  return undefined;
}

/** True when there are scans but no rollup row: a fresh deploy of ADR-0006. */
export async function needsBackfill(db: PrismaClient): Promise<boolean> {
  const [rollup, scan] = await Promise.all([
    db.scanDailyRollup.findFirst({ select: { qrCodeId: true } }),
    db.scan.findFirst({ select: { id: true } }),
  ]);
  return !rollup && !!scan;
}

/** Worker plus the repeating refresh (idempotent by job id) and, when needed, the backfill. */
export function createAnalyticsWorker(db: PrismaClient): Worker {
  const worker = new Worker('qrauth-analytics', (job: Job) => runAnalyticsJob(db, job.name), {
    connection: createQueueConnection(),
    concurrency: 1,
  });
  analyticsQueue
    .add('refresh', {}, { repeat: { every: ROLLUP_REFRESH_EVERY_MS }, jobId: REFRESH_JOB_ID })
    .catch((err) => console.error('[analytics] failed to schedule the rollup refresh:', err));
  needsBackfill(db)
    .then((needed) => (needed ? analyticsQueue.add('backfill', {}, { jobId: BACKFILL_JOB_ID, attempts: 1 }) : undefined))
    .catch((err) => console.error('[analytics] failed to schedule the backfill:', err));
  return worker;
}
