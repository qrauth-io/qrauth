import { Worker, type Job } from 'bullmq';
import type { FastifyBaseLogger } from 'fastify';
import type { PrismaClient } from '@prisma/client';
import { createQueueConnection, webRiskQueue } from '../lib/queue.js';
import { lookupDestination, normalizeDestination, type WebRiskVerdict } from '../lib/web-risk.js';
import { flagQrCode, type RecheckJob } from '../services/destination-screening.js';

/**
 * Web Risk re-check worker (queue `qrauth-web-risk`). Registered only when
 * WEB_RISK_API_KEY is set.
 *
 * - `recheck` {token}: screen one code now. Thrown when Web Risk is
 *   unavailable, so BullMQ retries with backoff.
 * - `daily-scan`: screen every ACTIVE, unexpired, unflagged URL code. Codes
 *   sharing a destination cost one lookup, verdicts come from the Redis cache
 *   when fresh, and API calls are spaced (LOOKUP_SPACING_MS) to stay far
 *   below the Web Risk per-minute quota.
 */

export const DAILY_SCAN_JOB_ID = 'web-risk-daily-scan';
const DAY_MS = 24 * 60 * 60 * 1000;
const PAGE_SIZE = 500;
const LOOKUP_SPACING_MS = 250;

export interface ScanDeps {
  lookup: (url: string) => Promise<WebRiskVerdict>;
  sleep: (ms: number) => Promise<void>;
  now: () => Date;
}

const defaultDeps: ScanDeps = {
  lookup: (url) => lookupDestination(url),
  sleep: (ms) => new Promise((r) => setTimeout(r, ms)),
  now: () => new Date(),
};

type ScanDb = Pick<PrismaClient, 'qRCode' | 'membership'>;

export interface DailyScanSummary {
  codes: number;
  destinations: number;
  flagged: number;
  unavailable: number;
}

export async function runDailyScan(
  prisma: ScanDb,
  log: FastifyBaseLogger,
  deps: ScanDeps = defaultDeps,
): Promise<DailyScanSummary> {
  // Group live URL codes by normalized destination.
  const byDestination = new Map<string, { url: string; tokens: string[] }>();
  let codes = 0;
  let cursor: string | undefined;
  const now = deps.now();
  for (;;) {
    const page = await prisma.qRCode.findMany({
      where: {
        status: 'ACTIVE',
        contentType: 'url',
        destinationFlaggedAt: null,
        OR: [{ expiresAt: null }, { expiresAt: { gt: now } }],
      },
      select: { id: true, token: true, destinationUrl: true },
      orderBy: { id: 'asc' },
      take: PAGE_SIZE,
      ...(cursor ? { cursor: { id: cursor }, skip: 1 } : {}),
    });
    for (const row of page) {
      const normalized = normalizeDestination(row.destinationUrl);
      if (!normalized) continue;
      codes += 1;
      const entry = byDestination.get(normalized) ?? { url: row.destinationUrl, tokens: [] };
      entry.tokens.push(row.token);
      byDestination.set(normalized, entry);
    }
    if (page.length < PAGE_SIZE) break;
    cursor = page[page.length - 1].id;
  }

  let flagged = 0;
  let unavailable = 0;
  let first = true;
  for (const { url, tokens } of byDestination.values()) {
    if (!first) await deps.sleep(LOOKUP_SPACING_MS);
    first = false;
    const verdict = await deps.lookup(url);
    if (verdict.verdict === 'unavailable') {
      unavailable += 1;
      continue;
    }
    if (verdict.verdict !== 'flagged') continue;
    for (const token of tokens) {
      if (await flagQrCode(prisma, log, token, verdict.threatTypes)) flagged += 1;
    }
  }

  const summary = { codes, destinations: byDestination.size, flagged, unavailable };
  log.info({ event: 'web_risk.daily_scan', ...summary }, 'Web Risk daily scan finished');
  return summary;
}

export async function runRecheck(
  prisma: ScanDb,
  log: FastifyBaseLogger,
  token: string,
  deps: Pick<ScanDeps, 'lookup'> = defaultDeps,
): Promise<'flagged' | 'clean' | 'skipped'> {
  const code = await prisma.qRCode.findUnique({
    where: { token },
    select: { status: true, contentType: true, destinationUrl: true, destinationFlaggedAt: true },
  });
  if (!code || code.status !== 'ACTIVE' || code.contentType !== 'url' || code.destinationFlaggedAt) return 'skipped';

  const verdict = await deps.lookup(code.destinationUrl);
  if (verdict.verdict === 'unavailable') {
    throw new Error(`Web Risk unavailable (${verdict.detail}); will retry`);
  }
  if (verdict.verdict === 'flagged') {
    await flagQrCode(prisma, log, token, verdict.threatTypes);
    return 'flagged';
  }
  return verdict.verdict === 'clean' ? 'clean' : 'skipped';
}

/** Worker plus the daily repeat schedule (idempotent by job id). */
export function createWebRiskWorker(prisma: PrismaClient, log: FastifyBaseLogger): Worker {
  const worker = new Worker(
    'qrauth-web-risk',
    async (job: Job) => {
      if (job.name === 'recheck') return runRecheck(prisma, log, (job.data as RecheckJob).token);
      if (job.name === 'daily-scan') return runDailyScan(prisma, log);
      return undefined;
    },
    { connection: createQueueConnection(), concurrency: 1 },
  );
  webRiskQueue
    .add('daily-scan', {}, { repeat: { every: DAY_MS }, jobId: DAILY_SCAN_JOB_ID })
    .catch((err) => log.error({ err }, '[web-risk] failed to schedule the daily scan'));
  return worker;
}
