import { Worker, type Job } from 'bullmq';
import type { FastifyBaseLogger } from 'fastify';
import type { PrismaClient } from '@prisma/client';
import { createQueueConnection, webRiskQueue } from '../lib/queue.js';
import { lookupDestination, normalizeDestination, type WebRiskVerdict } from '../lib/web-risk.js';
import { contentLinkUrls, isLinkedContentType, LINKED_CONTENT_TYPES } from '@qrauth/shared';
import { flagQrCode, type RecheckJob } from '../services/destination-screening.js';
import { flagContentLink } from '../services/link-screening.js';
import { DomainService, type DomainCheck } from '../services/domain.js';
import { recordLookalikeIncident } from '../services/lookalike-incidents.js';

/**
 * Web Risk re-check worker (queue `qrauth-web-risk`). Registered only when
 * WEB_RISK_API_KEY is set.
 *
 * - `recheck` {token}: screen one code now. Thrown when Web Risk is
 *   unavailable, so BullMQ retries with backoff.
 * - `daily-scan`: screen every ACTIVE, unexpired, unflagged URL code, and
 *   every link of the same smart link and link list codes (a listed link is
 *   recorded in qr_code_link_flags and hidden on the verify page; the code
 *   itself is not flagged). Codes and links sharing a URL cost one lookup, verdicts come from the Redis cache
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
  /**
   * Lookalike check of one URL for its issuing organization
   * (DomainService.checkUrlAgainstVerifiedDomains, cached). When set, the
   * scan records a HIGH fraud incident for each newly suspicious URL or
   * link (services/lookalike-incidents.ts).
   */
  lookalike?: (url: string, organizationId: string) => Promise<DomainCheck>;
}

const defaultDeps: ScanDeps = {
  lookup: (url) => lookupDestination(url),
  sleep: (ms) => new Promise((r) => setTimeout(r, ms)),
  now: () => new Date(),
};

type ScanDb = Pick<PrismaClient, 'qRCode' | 'membership' | 'qRCodeLinkFlag' | 'fraudIncident'>;

/** What a listed URL flags: a URL code itself, or one link of a code. */
type ScanTarget =
  | { kind: 'code'; token: string; code: { id: string; token: string; organizationId: string } }
  | { kind: 'link'; code: { id: string; token: string; organizationId: string }; url: string };

const SCANNED_CONTENT_TYPES = ['url', ...LINKED_CONTENT_TYPES];

function targetsOf(row: {
  id: string;
  token: string;
  organizationId: string;
  contentType: string;
  destinationUrl: string;
  content: unknown;
}): Array<{ url: string; target: ScanTarget }> {
  const code = { id: row.id, token: row.token, organizationId: row.organizationId };
  if (!isLinkedContentType(row.contentType)) {
    return [{ url: row.destinationUrl, target: { kind: 'code', token: row.token, code } }];
  }
  return contentLinkUrls(row.contentType, row.content).map((url) => ({ url, target: { kind: 'link', code, url } }));
}

async function flagTarget(prisma: ScanDb, log: FastifyBaseLogger, target: ScanTarget, threatTypes: string[]): Promise<boolean> {
  return target.kind === 'code'
    ? flagQrCode(prisma, log, target.token, threatTypes)
    : flagContentLink(prisma, log, target.code, target.url, threatTypes);
}

export interface DailyScanSummary {
  codes: number;
  destinations: number;
  flagged: number;
  unavailable: number;
  /** New lookalike fraud incidents (only when deps.lookalike is set). */
  lookalikes?: number;
}

export async function runDailyScan(
  prisma: ScanDb,
  log: FastifyBaseLogger,
  deps: ScanDeps = defaultDeps,
): Promise<DailyScanSummary> {
  // Group live URL codes, and the links of smart link and link list codes,
  // by normalized URL.
  const byDestination = new Map<string, { url: string; targets: ScanTarget[] }>();
  let codes = 0;
  let cursor: string | undefined;
  const now = deps.now();
  for (;;) {
    const page = await prisma.qRCode.findMany({
      where: {
        status: 'ACTIVE',
        contentType: { in: SCANNED_CONTENT_TYPES },
        destinationFlaggedAt: null,
        OR: [{ expiresAt: null }, { expiresAt: { gt: now } }],
      },
      select: { id: true, token: true, organizationId: true, contentType: true, destinationUrl: true, content: true },
      orderBy: { id: 'asc' },
      take: PAGE_SIZE,
      ...(cursor ? { cursor: { id: cursor }, skip: 1 } : {}),
    });
    for (const row of page) {
      let counted = false;
      for (const { url, target } of targetsOf(row)) {
        const normalized = normalizeDestination(url);
        if (!normalized) continue;
        if (!counted) codes += 1;
        counted = true;
        const entry = byDestination.get(normalized) ?? { url, targets: [] };
        entry.targets.push(target);
        byDestination.set(normalized, entry);
      }
    }
    if (page.length < PAGE_SIZE) break;
    cursor = page[page.length - 1].id;
  }

  let flagged = 0;
  let unavailable = 0;
  let first = true;
  for (const { url, targets } of byDestination.values()) {
    if (!first) await deps.sleep(LOOKUP_SPACING_MS);
    first = false;
    const verdict = await deps.lookup(url);
    if (verdict.verdict === 'unavailable') {
      unavailable += 1;
      continue;
    }
    if (verdict.verdict !== 'flagged') continue;
    for (const target of targets) {
      if (await flagTarget(prisma, log, target, verdict.threatTypes)) flagged += 1;
    }
  }

  // Lookalike re-check (ADR-0007): the same check as create, against the
  // protected set as it is today; results are cached per URL and issuer.
  let lookalikes: number | undefined;
  if (deps.lookalike) {
    lookalikes = 0;
    for (const { url, targets } of byDestination.values()) {
      for (const target of targets) {
        try {
          const check = await deps.lookalike(url, target.code.organizationId);
          const top = check.isSuspicious ? check.warnings[0] : undefined;
          if (top && (await recordLookalikeIncident(prisma, target.code.id, url, top, 'daily_rescan'))) lookalikes += 1;
        } catch (err) {
          log.warn({ err, token: target.code.token }, 'web-risk: lookalike re-check failed for one code');
        }
      }
    }
  }

  const summary = { codes, destinations: byDestination.size, flagged, unavailable, ...(lookalikes === undefined ? {} : { lookalikes }) };
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
    select: {
      id: true,
      token: true,
      organizationId: true,
      status: true,
      contentType: true,
      destinationUrl: true,
      content: true,
      destinationFlaggedAt: true,
    },
  });
  if (!code || code.status !== 'ACTIVE' || !SCANNED_CONTENT_TYPES.includes(code.contentType) || code.destinationFlaggedAt) {
    return 'skipped';
  }

  // Each URL once; a listed one is flagged even when another could not be
  // screened, and the job is then thrown so BullMQ retries the rest.
  const targets = new Map<string, { url: string; target: ScanTarget }>();
  for (const entry of targetsOf({ ...code, token })) {
    const key = normalizeDestination(entry.url) ?? entry.url;
    if (!targets.has(key)) targets.set(key, entry);
  }
  let flagged = false;
  let unavailableDetail: string | null = null;
  let clean = targets.size > 0;
  for (const { url, target } of targets.values()) {
    const verdict = await deps.lookup(url);
    if (verdict.verdict === 'unavailable') {
      unavailableDetail = verdict.detail;
      clean = false;
    } else if (verdict.verdict === 'flagged') {
      await flagTarget(prisma, log, target, verdict.threatTypes);
      flagged = true;
    } else if (verdict.verdict !== 'clean') {
      clean = false;
    }
  }
  if (unavailableDetail !== null) {
    throw new Error(`Web Risk unavailable (${unavailableDetail}); will retry`);
  }
  if (flagged) return 'flagged';
  return clean ? 'clean' : 'skipped';
}

/** Worker plus the daily repeat schedule (idempotent by job id). */
export function createWebRiskWorker(prisma: PrismaClient, log: FastifyBaseLogger): Worker {
  const worker = new Worker(
    'qrauth-web-risk',
    async (job: Job) => {
      if (job.name === 'recheck') return runRecheck(prisma, log, (job.data as RecheckJob).token);
      if (job.name === 'daily-scan') {
        const domains = new DomainService(prisma, log);
        return runDailyScan(prisma, log, {
          ...defaultDeps,
          lookalike: (url, organizationId) => domains.checkUrlAgainstVerifiedDomains(url, organizationId),
        });
      }
      return undefined;
    },
    { connection: createQueueConnection(), concurrency: 1 },
  );
  webRiskQueue
    .add('daily-scan', {}, { repeat: { every: DAY_MS }, jobId: DAILY_SCAN_JOB_ID })
    .catch((err) => log.error({ err }, '[web-risk] failed to schedule the daily scan'));
  return worker;
}
