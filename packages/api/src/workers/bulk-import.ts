import type { BulkJob, Prisma, PrismaClient } from '@prisma/client';
import type { FastifyBaseLogger } from 'fastify';
import { isIssuerVerified } from '@qrauth/shared';

import { CUSTOMER_LOGO_ORG_SELECT, logoEligibility } from '../config/plan-limits.js';
import { mapLimit } from '../lib/map-limit.js';
import type { BatchSigner } from '../services/batch-signer.js';
import { bulkStarterRefusal } from '../services/bulk-actor.js';
import { validateDrafts } from '../services/bulk-import.js';
import type { ImportJobInput, StoredImportResult, ValidatedRow } from '../services/bulk-rows.js';
import { finishBulkJob, jobAuditContext, jobRevisionContext } from '../services/bulk-jobs.js';
import { enqueueDestinationRecheck } from '../services/destination-screening.js';
import { DomainService } from '../services/domain.js';
import { GeoService } from '../services/geo.js';
import { HybridSigningService } from '../services/hybrid-signing.js';
import { MacService } from '../services/mac.js';
import { PolicyRefusalError } from '../services/org-policy.js';
import { generateQRCode } from '../services/qr-create.js';
import {
  createFolder,
  createTag,
  organizeAudit,
  OrganizeLimitError,
  OrganizeNameTakenError,
} from '../services/qr-organize.js';
import type { SigningService } from '../services/signing.js';
import { TransparencyLogService } from '../services/transparency.js';
import { UsageService } from '../services/usage.js';

/**
 * The bulk import job (ADR-0008 D9): re-validates the dry run's rows as of
 * now, creates missing folders and tags, issues the valid rows through the
 * single-create core (generateQRCode) and skips the rest, recording one
 * result per row as it goes.
 */

/** Codes issued at once: concurrent issues share SLH-DSA batch signatures (BatchSigner, up to 64 per batch). */
export const IMPORT_CONCURRENCY = 64;
/** Progress is written at least this often (rows), and the stale-job sweep watches updatedAt. */
const PROGRESS_EVERY_ROWS = 25;

export interface BulkWorkerDeps {
  prisma: PrismaClient;
  log: FastifyBaseLogger;
  signingService: SigningService;
  batchSigner: BatchSigner;
}

type Counters = { succeeded: number; failed: number; skipped: number };

function counters(results: readonly StoredImportResult[]): Counters {
  return {
    succeeded: results.filter((r) => r.status === 'created').length,
    failed: results.filter((r) => r.status === 'failed').length,
    skipped: results.filter((r) => r.status === 'skipped').length,
  };
}

const firstError = (row: ValidatedRow) => row.issues.find((i) => i.severity === 'error');

/**
 * Folder and tag ids by lower-cased name, creating the missing ones (audited
 * as folder.create / tag.create by the job's starter). A name that hits the
 * organization's limit maps to null, and its rows are skipped.
 */
async function resolveOrganize(
  prisma: PrismaClient,
  job: BulkJob,
  newFolders: readonly string[],
  newTags: readonly string[],
): Promise<{ folders: Map<string, string | null>; tags: Map<string, string | null> }> {
  const ctx = jobAuditContext(job);
  const orgId = job.organizationId;
  const folders = new Map<string, string | null>();
  const tags = new Map<string, string | null>();
  for (const name of newFolders) {
    try {
      await createFolder(prisma, orgId, name, organizeAudit(ctx, orgId, 'folder.create', 'Folder'));
    } catch (err) {
      if (err instanceof OrganizeLimitError) folders.set(name.toLowerCase(), null);
      else if (!(err instanceof OrganizeNameTakenError)) throw err; // created meanwhile: found below
    }
  }
  for (const name of newTags) {
    try {
      await createTag(prisma, orgId, { name, color: 'grey' }, organizeAudit(ctx, orgId, 'tag.create', 'Tag'));
    } catch (err) {
      if (err instanceof OrganizeLimitError) tags.set(name.toLowerCase(), null);
      else if (!(err instanceof OrganizeNameTakenError)) throw err;
    }
  }
  const [folderRows, tagRows] = await Promise.all([
    prisma.qRFolder.findMany({ where: { organizationId: orgId }, select: { id: true, name: true } }),
    prisma.tag.findMany({ where: { organizationId: orgId }, select: { id: true, name: true } }),
  ]);
  for (const f of folderRows) if (!folders.has(f.name.toLowerCase())) folders.set(f.name.toLowerCase(), f.id);
  for (const t of tagRows) if (!tags.has(t.name.toLowerCase())) tags.set(t.name.toLowerCase(), t.id);
  return { folders, tags };
}

/** Claim a QUEUED job; false when another worker or the sweep got it first. */
export async function claimJob(prisma: PrismaClient, jobId: string): Promise<BulkJob | null> {
  const { count } = await prisma.bulkJob.updateMany({
    where: { id: jobId, status: 'QUEUED' },
    data: { status: 'RUNNING', startedAt: new Date() },
  });
  if (count === 0) return null;
  return prisma.bulkJob.findUnique({ where: { id: jobId } });
}

export async function runImportJob(deps: BulkWorkerDeps, jobId: string): Promise<void> {
  const { prisma, log } = deps;
  const job = await claimJob(prisma, jobId);
  if (!job) return;
  const input = job.input as unknown as ImportJobInput;
  const results: StoredImportResult[] = input.refused.map((r) => ({
    row: r.row,
    status: 'skipped',
    token: null,
    error: r.error,
    url: r.url,
    label: null,
  }));

  // Saves run one after another, so an older snapshot never lands last.
  let saving: Promise<void> = Promise.resolve();
  const write = async () => {
    const snapshot = [...results];
    await prisma.bulkJob.update({
      where: { id: job.id },
      data: { processed: snapshot.length, ...counters(snapshot), results: snapshot as unknown as Prisma.InputJsonValue },
    });
  };
  const save = (): Promise<void> => (saving = saving.then(write, write));

  try {
    const refusal = await bulkStarterRefusal(prisma, job);
    if (refusal) {
      await finishBulkJob(prisma, job, 'FAILED', { ...counters(results), error: refusal });
      return;
    }

    const org = await prisma.organization.findUniqueOrThrow({ where: { id: job.organizationId }, select: CUSTOMER_LOGO_ORG_SELECT });
    const usage = new UsageService(prisma, log);
    const domainService = new DomainService(prisma, log);
    const validated = await validateDrafts(
      { prisma, domainService, usage },
      job.organizationId,
      org.plan,
      input.drafts.map((draft) => ({ draft })),
    );
    for (const row of validated.rows) {
      const error = firstError(row);
      if (error) results.push({ row: row.draft.row, status: 'skipped', token: null, error: error.message, url: row.draft.url, label: row.draft.label });
    }
    await save();

    const organize = await resolveOrganize(prisma, job, validated.newFolders, validated.newTags);
    const hybrid = new HybridSigningService(prisma, deps.signingService, deps.batchSigner);
    const services = {
      mac: new MacService(prisma),
      geo: new GeoService(prisma),
      transparency: new TransparencyLogService(prisma),
    };
    const issuerVerified = isIssuerVerified(logoEligibility(org));
    const revision = jobRevisionContext(job);
    let sinceSave = 0;

    const toCreate = validated.rows.filter((r) => !firstError(r));
    await mapLimit(toCreate, IMPORT_CONCURRENCY, async ({ draft, webRiskUnavailable }) => {
      const base = { row: draft.row, url: draft.url, label: draft.label };
      // A missing id (undefined) or a name refused at the limit (null) skips the row.
      const folderId = draft.folder ? organize.folders.get(draft.folder.toLowerCase()) : null;
      const tagIds = draft.tags.map((t) => organize.tags.get(t.toLowerCase()));
      if ((draft.folder && !folderId) || tagIds.some((id) => !id)) {
        results.push({ ...base, status: 'skipped', token: null, error: 'The folder or a tag could not be created (organization limit).' });
      } else {
        try {
          const created = await generateQRCode(
            { prisma, log },
            deps.signingService,
            hybrid,
            services.mac,
            services.geo,
            services.transparency,
            domainService,
            job.organizationId,
            {
              destinationUrl: draft.url,
              label: draft.label ?? undefined,
              expiresAt: draft.expiresAt ?? undefined,
              scanMode: draft.scanMode ?? undefined,
              issuerVerified,
              revision,
              renderImage: false,
              organize: { folderId: folderId ?? null, tagIds: tagIds as string[] },
            },
          );
          if (webRiskUnavailable) await enqueueDestinationRecheck(created.token, log);
          results.push({ ...base, status: 'created', token: created.token, error: null });
        } catch (err) {
          if (err instanceof PolicyRefusalError) {
            results.push({ ...base, status: 'skipped', token: null, error: err.refusal.body.message });
          } else {
            log.warn({ err, jobId: job.id, row: draft.row }, 'Bulk import: issuing a row failed');
            results.push({ ...base, status: 'failed', token: null, error: 'The code could not be created; try this row again.' });
          }
        }
      }
      if (++sinceSave >= PROGRESS_EVERY_ROWS) {
        sinceSave = 0;
        // A failed progress write must not stop the rows in flight (they are
        // issuing codes); the final save records every result.
        await save().catch((err: unknown) => log.warn({ err, jobId: job.id }, 'Bulk import: progress not saved'));
      }
    });

    results.sort((a, b) => a.row - b.row);
    await save();
    await finishBulkJob(prisma, job, 'SUCCEEDED', counters(results), { newFolders: validated.newFolders.length, newTags: validated.newTags.length });
  } catch (err) {
    log.error({ err, jobId: job.id }, 'Bulk import job failed');
    results.sort((a, b) => a.row - b.row);
    await save().catch(() => undefined);
    await finishBulkJob(prisma, job, 'FAILED', { ...counters(results), error: 'The import stopped because of an internal error.' });
  }
}
