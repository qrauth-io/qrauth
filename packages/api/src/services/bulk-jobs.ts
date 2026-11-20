import { Prisma, type BulkJob, type PrismaClient } from '@prisma/client';
import { createHmac, hkdfSync, randomBytes } from 'node:crypto';
import {
  BULK_ARTIFACT_TTL_HOURS,
  BULK_DRY_RUN_TTL_SECONDS,
  BULK_EXPORT_LINK_TTL_SECONDS,
  type BulkDryRunView,
  type BulkJobKind,
  type BulkJobView,
} from '@qrauth/shared';

import { cacheDel, cacheGet, cacheSet } from '../lib/cache.js';
import { config } from '../lib/config.js';
import { constantTimeEqualString } from '../lib/constant-time.js';
import { recordAudit, type AuditContext } from './audit.js';
import type { BulkRowDraft } from './bulk-rows.js';
import type { RevisionContext } from './qr-revisions.js';

/**
 * Bulk jobs (ADR-0008 D9): stored dry runs, the bulk_jobs rows, who may see
 * them, and export download links. A dry run, a job and its ZIP belong to
 * the member or API key that started them; anyone else (another member, the
 * same member in another organization) gets 404, as for a missing id.
 */

/** Who started a dry run or job. */
export type BulkActor = { type: 'USER'; userId: string } | { type: 'API_KEY'; apiKeyId: string };

/** The actor of a request's audit context; null for actors that cannot own bulk jobs (superadmin, system). */
export function bulkActorOf(ctx: AuditContext): BulkActor | null {
  if (ctx.actor.type === 'USER') return { type: 'USER', userId: ctx.actor.userId };
  if (ctx.actor.type === 'API_KEY') return { type: 'API_KEY', apiKeyId: ctx.actor.apiKeyId };
  return null;
}

function sameActor(a: BulkActor, b: BulkActor): boolean {
  return a.type === 'USER' ? b.type === 'USER' && a.userId === b.userId : b.type === 'API_KEY' && a.apiKeyId === b.apiKeyId;
}

function actorOfJob(job: Pick<BulkJob, 'actorType' | 'actorUserId' | 'actorApiKeyId'>): BulkActor {
  return job.actorType === 'API_KEY' ? { type: 'API_KEY', apiKeyId: job.actorApiKeyId! } : { type: 'USER', userId: job.actorUserId! };
}

// ---------------------------------------------------------------------------
// Dry runs (Redis, 1 hour)
// ---------------------------------------------------------------------------

export interface StoredDryRun {
  view: BulkDryRunView;
  organizationId: string;
  actor: BulkActor;
  /** Rows without an error, as validated: the input of a commit. */
  drafts: BulkRowDraft[];
}

const dryRunKey = (id: string) => `bulk:dry-run:${id}`;

/** An unguessable id (128 bits). */
export function newOpaqueId(): string {
  return randomBytes(16).toString('base64url');
}

export async function saveDryRun(run: StoredDryRun): Promise<void> {
  await cacheSet(dryRunKey(run.view.id), run, BULK_DRY_RUN_TTL_SECONDS);
}

/** The dry run when it exists and belongs to this organization and actor; otherwise null. */
export async function loadDryRun(id: string, organizationId: string, actor: BulkActor): Promise<StoredDryRun | null> {
  const run = await cacheGet<StoredDryRun>(dryRunKey(id));
  if (!run || run.organizationId !== organizationId || !sameActor(run.actor, actor)) return null;
  return run;
}

export function dropDryRun(id: string): Promise<void> {
  return cacheDel(dryRunKey(id));
}

// ---------------------------------------------------------------------------
// Jobs
// ---------------------------------------------------------------------------

/** Another job of this kind is queued or running in the organization (409). */
export class BulkJobActiveError extends Error {
  constructor(readonly activeJobId: string | null) {
    super('Another bulk job of this kind is already running in this organization.');
    this.name = 'BulkJobActiveError';
  }
}

export interface NewBulkJob {
  organizationId: string;
  kind: BulkJobKind;
  input: Prisma.InputJsonValue;
  total: number;
  /** Extra fields of the bulk.start audit entry. */
  auditMetadata: Record<string, unknown>;
}

function isUniqueViolation(err: unknown): boolean {
  return err instanceof Prisma.PrismaClientKnownRequestError && err.code === 'P2002';
}

/**
 * Create a QUEUED job and its bulk.start audit entry in one transaction.
 * Throws BulkJobActiveError when the organization already has an active job
 * of this kind (the partial unique index decides, so two commits at once
 * cannot both start).
 */
export async function createBulkJob(prisma: PrismaClient, ctx: AuditContext, job: NewBulkJob): Promise<BulkJob> {
  const actor = bulkActorOf(ctx);
  if (!actor) throw new Error('Bulk jobs are started by a member or an API key');
  try {
    return await prisma.$transaction(async (tx) => {
      const row = await tx.bulkJob.create({
        data: {
          organizationId: job.organizationId,
          kind: job.kind,
          actorType: actor.type,
          actorUserId: actor.type === 'USER' ? actor.userId : null,
          actorApiKeyId: actor.type === 'API_KEY' ? actor.apiKeyId : null,
          requestId: ctx.requestId,
          ipAddress: ctx.ip,
          userAgent: ctx.userAgent,
          input: job.input,
          total: job.total,
        },
      });
      await recordAudit(tx, ctx, {
        organizationId: job.organizationId,
        action: 'bulk.start',
        resource: 'BulkJob',
        resourceId: row.id,
        metadata: { jobId: row.id, kind: job.kind, total: job.total, ...job.auditMetadata },
      });
      return row;
    });
  } catch (err) {
    if (!isUniqueViolation(err)) throw err;
    const active = await prisma.bulkJob.findFirst({
      where: { organizationId: job.organizationId, kind: job.kind, status: { in: ['QUEUED', 'RUNNING'] } },
      select: { id: true },
    });
    throw new BulkJobActiveError(active?.id ?? null);
  }
}

/** The job when it belongs to this organization and actor (and kind, when given); otherwise null. */
export async function loadJobFor(
  prisma: PrismaClient,
  id: string,
  organizationId: string,
  actor: BulkActor,
  kind?: BulkJobKind,
): Promise<BulkJob | null> {
  const job = await prisma.bulkJob.findFirst({ where: { id, organizationId, ...(kind ? { kind } : {}) } });
  if (!job || !sameActor(actorOfJob(job), actor)) return null;
  return job;
}

export function jobView(job: BulkJob): BulkJobView {
  return {
    id: job.id,
    kind: job.kind,
    status: job.status,
    total: job.total,
    processed: job.processed,
    succeeded: job.succeeded,
    failed: job.failed,
    skipped: job.skipped,
    error: job.error,
    createdAt: job.createdAt.toISOString(),
    startedAt: job.startedAt?.toISOString() ?? null,
    finishedAt: job.finishedAt?.toISOString() ?? null,
    expiresAt: job.expiresAt?.toISOString() ?? null,
    fileBytes: job.fileBytes,
  };
}

/** The job's starter as the audit and revision contexts of the work it does. */
export function jobAuditContext(job: BulkJob): AuditContext {
  const actor = actorOfJob(job);
  return {
    actor: actor.type === 'USER' ? { type: 'USER', userId: actor.userId } : { type: 'API_KEY', apiKeyId: actor.apiKeyId },
    requestId: job.requestId,
    ip: job.ipAddress,
    userAgent: job.userAgent,
  };
}

export function jobRevisionContext(job: BulkJob): RevisionContext {
  const actor = actorOfJob(job);
  return { actor, requestId: job.requestId };
}

/** When a job that ends now is deleted with its results and ZIP. */
export function artifactExpiry(finishedAt: Date): Date {
  return new Date(finishedAt.getTime() + BULK_ARTIFACT_TTL_HOURS * 3600 * 1000);
}

export interface BulkJobSummary {
  succeeded: number;
  failed: number;
  skipped: number;
  error?: string | null;
  fileBytes?: number | null;
  filePath?: string | null;
}

/**
 * Mark a job ended (SUCCEEDED, or FAILED with `error`) and record bulk.finish
 * in the same transaction. Only a job still QUEUED or RUNNING is changed, so
 * a late worker and the stale-job sweep cannot both finish it; returns false
 * when it had already ended.
 */
export async function finishBulkJob(
  prisma: PrismaClient,
  job: BulkJob,
  status: 'SUCCEEDED' | 'FAILED',
  summary: BulkJobSummary,
  extraAudit: Record<string, unknown> = {},
): Promise<boolean> {
  const finishedAt = new Date();
  return prisma.$transaction(async (tx) => {
    const { count } = await tx.bulkJob.updateMany({
      where: { id: job.id, status: { in: ['QUEUED', 'RUNNING'] } },
      data: {
        status,
        succeeded: summary.succeeded,
        failed: summary.failed,
        skipped: summary.skipped,
        error: summary.error ?? null,
        fileBytes: summary.fileBytes ?? null,
        filePath: summary.filePath ?? null,
        finishedAt,
        expiresAt: artifactExpiry(finishedAt),
      },
    });
    if (count === 0) return false;
    await recordAudit(tx, jobAuditContext(job), {
      organizationId: job.organizationId,
      action: 'bulk.finish',
      resource: 'BulkJob',
      resourceId: job.id,
      metadata: {
        jobId: job.id,
        kind: job.kind,
        status,
        total: job.total,
        succeeded: summary.succeeded,
        failed: summary.failed,
        skipped: summary.skipped,
        ...(summary.error ? { error: summary.error } : {}),
        ...extraAudit,
      },
    });
    return true;
  });
}

// ---------------------------------------------------------------------------
// Export download links
// ---------------------------------------------------------------------------

/** The link key, derived from JWT_SECRET for this one purpose (rotating JWT_SECRET voids open links). */
function linkKey(): Buffer {
  return Buffer.from(hkdfSync('sha256', config.auth.jwtSecret, Buffer.alloc(0), 'qrauth/bulk-export-link/v1', 32));
}

function actorKey(actor: BulkActor): string {
  return actor.type === 'USER' ? `user:${actor.userId}` : `key:${actor.apiKeyId}`;
}

function linkSignature(jobId: string, actor: BulkActor, expires: number): string {
  return createHmac('sha256', linkKey()).update(`${jobId}\n${actorKey(actor)}\n${expires}`).digest('base64url');
}

/** Query string of a download link for the job's starter, valid BULK_EXPORT_LINK_TTL_SECONDS. */
export function signExportLink(job: BulkJob, now = Date.now()): { query: string; expiresAt: Date } {
  const expires = Math.floor(now / 1000) + BULK_EXPORT_LINK_TTL_SECONDS;
  const sig = linkSignature(job.id, actorOfJob(job), expires);
  return { query: `expires=${expires}&sig=${sig}`, expiresAt: new Date(expires * 1000) };
}

/** True when `sig` was issued for this job's starter and has not expired. */
export function verifyExportLink(job: BulkJob, expires: number, sig: string, now = Date.now()): boolean {
  if (!Number.isInteger(expires) || expires * 1000 <= now) return false;
  // A link is never valid longer than the TTL, whatever `expires` says.
  if (expires * 1000 > now + BULK_EXPORT_LINK_TTL_SECONDS * 1000 + 1000) return false;
  return constantTimeEqualString(linkSignature(job.id, actorOfJob(job), expires), sig);
}
