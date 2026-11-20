import type { BulkJob } from '@prisma/client';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { createReadStream } from 'node:fs';
import { stat } from 'node:fs/promises';
import { z } from 'zod';
import {
  BULK_IMPORT_MAX_BYTES,
  BULK_IMPORT_TEMPLATE_CSV,
  BULK_DRY_RUN_TTL_SECONDS,
  BULK_IMPORT_DEFAULT_TIMEZONE,
  isValidTimeZone,
  bulkExportRequestSchema,
  planAllowsGovernance,
  type BulkDryRunView,
  type BulkExportRequest,
} from '@qrauth/shared';

import { GOVERNANCE_PLAN_REQUIRED_CODE, exportGateMessage, gateRefusalBody } from '../config/plan-limits.js';
import { authorize } from '../middleware/authorize.js';
import { rateLimitAuth, rateLimitBulk, rateLimitPublic } from '../middleware/rateLimit.js';
import { zodValidator } from '../middleware/validate.js';
import { config } from '../lib/config.js';
import { CSV_UTF8_BOM, csvLine } from '../lib/csv.js';
import { sendOrganizeError } from '../lib/organize-errors.js';
import { buildVerificationUrl } from '../lib/qrcode-access.js';
import { verifiedEmailGuard } from '../lib/verified-actor.js';
import { auditContext } from '../services/audit.js';
import { BulkCsvError, parseImportCsv } from '../services/bulk-csv.js';
import { ExportSelectionError, resolveExportSelection, type ExportJobInput } from '../services/bulk-export.js';
import { validateDrafts } from '../services/bulk-import.js';
import { draftOf, dryRunRowView, dryRunTotals, type ImportJobInput, type StoredImportResult } from '../services/bulk-rows.js';
import {
  BulkJobActiveError,
  bulkActorOf,
  createBulkJob,
  dropDryRun,
  finishBulkJob,
  jobView,
  loadDryRun,
  loadJobFor,
  newOpaqueId,
  saveDryRun,
  signExportLink,
  verifyExportLink,
  type BulkActor,
} from '../services/bulk-jobs.js';
import { isInExportDir } from '../services/bulk-cleanup.js';
import { DomainService } from '../services/domain.js';
import { QuotaUnavailableError, UsageService } from '../services/usage.js';
import { enqueueBulkJob } from '../workers/bulk.js';

/**
 * Bulk operations (ADR-0008 D9) under /api/v1/bulk: CSV import of URL codes
 * (dry run, then a job) and ZIP export of rendered codes (a job, then a
 * short-lived download link). Business plan and above (D5). Dry runs, jobs
 * and ZIPs belong to the member or API key that started them.
 */

const IMPORT_ROLES = ['OWNER', 'ADMIN', 'MANAGER', 'MEMBER'] as const;
const EXPORT_ROLES = ['OWNER', 'ADMIN', 'MANAGER', 'MEMBER', 'VIEWER'] as const;
/** Content types a CSV upload may carry (Windows browsers label .csv files as Excel). */
const CSV_CONTENT_TYPES = ['text/csv', 'text/plain', 'application/csv', 'application/vnd.ms-excel', 'application/octet-stream'];
const BULK_PLAN_MESSAGE = 'Bulk import and export are available on the Business plan and above.';
const QUOTA_RETRY_AFTER_SECONDS = 30;
const ENQUEUE_TIMEOUT_MS = 5000;

/** `promise`, or a rejection after `ms` (the promise itself keeps running). */
function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => reject(new Error(`Timed out after ${ms} ms`)), ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

const idParams = z.object({ id: z.string().min(1).max(64) });
/** POST /imports/dry-run?timezone=Europe/Athens: the zone of date-only expiry dates (default UTC). */
const dryRunQuery = z.object({ timezone: z.string().max(64).optional() });
const downloadQuery = z.object({ expires: z.coerce.number().int(), sig: z.string().min(1).max(128) });

const notFound = (reply: FastifyReply, what: string) =>
  reply.status(404).send({ statusCode: 404, error: 'Not Found', message: `${what} not found.` });

function sendCode(reply: FastifyReply, status: number, code: string, message: string, extra: Record<string, unknown> = {}) {
  const error = status === 409 ? 'Conflict' : status === 410 ? 'Gone' : status === 403 ? 'Forbidden' : 'Unprocessable Entity';
  return reply.status(status).send({ statusCode: status, error, code, message, ...extra });
}

/** The caller as a job owner; superadmin and system contexts never reach these routes. */
function actorOf(request: FastifyRequest): BulkActor {
  const actor = bulkActorOf(auditContext(request));
  if (!actor) throw new Error('Bulk routes need a member or an API key');
  return actor;
}

/** Results CSV of an import: one line per row of the file, in file order. */
export function importResultsCsv(results: readonly StoredImportResult[]): string {
  const lines = [CSV_UTF8_BOM + csvLine(['row', 'status', 'token', 'verifyUrl', 'url', 'label', 'error'])];
  for (const r of [...results].sort((a, b) => a.row - b.row)) {
    lines.push(csvLine([r.row, r.status, r.token, r.token ? buildVerificationUrl(r.token) : null, r.url, r.label, r.error]));
  }
  return lines.join('');
}

export default async function bulkRoutes(fastify: FastifyInstance): Promise<void> {
  const { authenticate, prisma } = fastify;
  const requireVerifiedEmail = verifiedEmailGuard(prisma);

  /** onRequest/preHandler: 403 governance-plan-required below Business (before an upload is read). */
  async function requireBulkPlan(request: FastifyRequest, reply: FastifyReply): Promise<FastifyReply | undefined> {
    if (reply.sent || !request.user) return undefined;
    const org = await prisma.organization.findUnique({ where: { id: request.user.orgId }, select: { plan: true } });
    if (planAllowsGovernance(org?.plan ?? 'FREE')) return undefined;
    return reply.status(403).send(gateRefusalBody({ code: GOVERNANCE_PLAN_REQUIRED_CODE, message: BULK_PLAN_MESSAGE }));
  }

  const importGuards = [authenticate, authorize(...IMPORT_ROLES), requireBulkPlan];
  const exportGuards = [authenticate, authorize(...EXPORT_ROLES), requireBulkPlan];

  // -------------------------------------------------------------------------
  // GET /imports/template.csv — the import template (any plan, so it can be read before upgrading)
  // -------------------------------------------------------------------------
  fastify.get('/imports/template.csv', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate],
  }, async (_request, reply) =>
    reply
      .header('Content-Type', 'text/csv; charset=utf-8')
      .header('Content-Disposition', 'attachment; filename="qrauth-import-template.csv"')
      .send(BULK_IMPORT_TEMPLATE_CSV));

  // -------------------------------------------------------------------------
  // POST /imports/dry-run — validate a CSV file (raw body, at most 1 MB)
  // -------------------------------------------------------------------------
  await fastify.register(async (upload) => {
    upload.addContentTypeParser(CSV_CONTENT_TYPES, { parseAs: 'buffer', bodyLimit: BULK_IMPORT_MAX_BYTES }, (_req, body, done) => done(null, body));
    upload.post('/imports/dry-run', {
      config: { rateLimit: rateLimitBulk },
      bodyLimit: BULK_IMPORT_MAX_BYTES,
      // Checked before the body is read: an anonymous, under-privileged or
      // lower-plan caller never uploads the file. Fastify stops reading at
      // bodyLimit (413), so an oversized upload is not buffered.
      onRequest: [...importGuards, requireVerifiedEmail],
      preValidation: zodValidator({ querystring: dryRunQuery }),
    }, async (request, reply) => {
      const timeZone = (request.query as { timezone?: string }).timezone ?? BULK_IMPORT_DEFAULT_TIMEZONE;
      if (!isValidTimeZone(timeZone)) {
        return sendCode(reply, 422, 'timezone-invalid', 'timezone must be an IANA time zone name, such as Europe/Athens or UTC.');
      }
      if (!Buffer.isBuffer(request.body)) {
        return sendCode(reply, 422, 'file-not-text', 'Send the CSV file as the request body (Content-Type: text/csv).');
      }
      const orgId = request.user!.orgId;
      let parsed;
      try {
        parsed = parseImportCsv(request.body);
      } catch (err) {
        if (err instanceof BulkCsvError) return sendCode(reply, 422, err.code, err.message);
        throw err;
      }

      const org = await prisma.organization.findUniqueOrThrow({ where: { id: orgId }, select: { plan: true } });
      const usage = new UsageService(prisma, request.log);
      const domainService = new DomainService(prisma, request.log);
      let validated;
      try {
        validated = await validateDrafts(
          { prisma, domainService, usage, timeZone },
          orgId,
          org.plan,
          parsed.rows.map((row) => draftOf(row, parsed.delimiter)),
        );
      } catch (err) {
        if (!(err instanceof QuotaUnavailableError)) throw err;
        return reply.status(503).header('Retry-After', QUOTA_RETRY_AFTER_SECONDS).send({ statusCode: 503, error: 'Service Unavailable', message: err.message });
      }

      const rows = validated.rows.map(dryRunRowView);
      const view: BulkDryRunView = {
        id: newOpaqueId(),
        expiresAt: new Date(Date.now() + BULK_DRY_RUN_TTL_SECONDS * 1000).toISOString(),
        delimiter: parsed.delimiter,
        columns: parsed.columns,
        timezone: timeZone,
        totals: dryRunTotals(rows, validated.newFolders, validated.newTags),
        rows,
      };
      await saveDryRun({
        view,
        organizationId: orgId,
        actor: actorOf(request),
        drafts: validated.rows.filter((r) => !r.issues.some((i) => i.severity === 'error')).map((r) => r.draft),
      });
      return reply.status(201).send(view);
    });
  });

  // -------------------------------------------------------------------------
  // GET /imports/dry-run/:id
  // -------------------------------------------------------------------------
  fastify.get('/imports/dry-run/:id', {
    config: { rateLimit: rateLimitAuth },
    preHandler: importGuards,
    preValidation: zodValidator({ params: idParams }),
  }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const run = await loadDryRun(id, request.user!.orgId, actorOf(request));
    return run ? reply.send(run.view) : notFound(reply, 'Dry run');
  });

  // -------------------------------------------------------------------------
  // POST /imports/dry-run/:id/commit — start the import job
  // -------------------------------------------------------------------------
  fastify.post('/imports/dry-run/:id/commit', {
    config: { rateLimit: rateLimitBulk },
    preHandler: [...importGuards, requireVerifiedEmail],
    preValidation: zodValidator({ params: idParams }),
  }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const orgId = request.user!.orgId;
    const run = await loadDryRun(id, orgId, actorOf(request));
    if (!run) return notFound(reply, 'Dry run');
    if (run.drafts.length === 0) return sendCode(reply, 422, 'nothing-to-import', 'Every row of the dry run has an error; nothing to import.');

    const input: ImportJobInput = {
      drafts: run.drafts,
      refused: run.view.rows.filter((r) => r.status === 'error').map((r) => ({ row: r.row, url: r.url, error: r.messages[0] ?? 'Invalid row' })),
    };
    let job: BulkJob;
    try {
      job = await createBulkJob(prisma, auditContext(request), {
        organizationId: orgId,
        kind: 'IMPORT',
        input: input as never,
        total: run.view.totals.rows,
        auditMetadata: { dryRunId: id, ok: run.view.totals.ok, warning: run.view.totals.warning, error: run.view.totals.error },
      });
    } catch (err) {
      if (err instanceof BulkJobActiveError) {
        return sendCode(reply, 409, 'bulk-job-active', 'An import is already running in this organization; wait for it to finish.', { activeJobId: err.activeJobId });
      }
      throw err;
    }
    const started = await startJob(reply, job);
    // The dry run is used up once its job is queued. A cache failure here is
    // only logged: the dry run expires within the hour anyway, and committing
    // it again meets the job (409) while it runs.
    if (reply.statusCode === 202) await dropDryRun(id).catch((err: unknown) => reply.log.warn({ err, dryRunId: id }, 'Could not delete a committed dry run'));
    return started;
  });

  /** Queue a created job; if the queue is down, the job is failed (with bulk.finish) and 503 sent. */
  async function startJob(reply: FastifyReply, job: BulkJob) {
    try {
      // BullMQ waits for Redis indefinitely; give up after a few seconds so
      // the job is failed (freeing the organization's slot) instead of hanging.
      await withTimeout(enqueueBulkJob(job.kind, job.id), ENQUEUE_TIMEOUT_MS);
    } catch (err) {
      reply.log.error({ err, jobId: job.id }, 'Bulk job could not be queued');
      await finishBulkJob(prisma, job, 'FAILED', { succeeded: 0, failed: 0, skipped: 0, error: 'The job could not be queued.' });
      return reply.status(503).header('Retry-After', '30').send({ statusCode: 503, error: 'Service Unavailable', message: 'The job could not be started; try again shortly.' });
    }
    return reply.status(202).send(jobView(job));
  }

  // -------------------------------------------------------------------------
  // GET /jobs/:id — progress of an import or export
  // -------------------------------------------------------------------------
  fastify.get('/jobs/:id', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate, authorize(...EXPORT_ROLES)],
    preValidation: zodValidator({ params: idParams }),
  }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const job = await loadJobFor(prisma, id, request.user!.orgId, actorOf(request));
    return job ? reply.send(jobView(job)) : notFound(reply, 'Job');
  });

  // -------------------------------------------------------------------------
  // GET /imports/:id/results.csv
  // -------------------------------------------------------------------------
  fastify.get('/imports/:id/results.csv', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate, authorize(...IMPORT_ROLES)],
    preValidation: zodValidator({ params: idParams }),
  }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const job = await loadJobFor(prisma, id, request.user!.orgId, actorOf(request), 'IMPORT');
    if (!job) return notFound(reply, 'Import');
    const results = (job.results ?? []) as unknown as StoredImportResult[];
    return reply
      .header('Content-Type', 'text/csv; charset=utf-8')
      .header('Content-Disposition', `attachment; filename="qrauth-import-${job.id}.csv"`)
      .header('Cache-Control', 'no-store')
      .send(importResultsCsv(results));
  });

  // -------------------------------------------------------------------------
  // POST /exports — start a ZIP export
  // -------------------------------------------------------------------------
  fastify.post('/exports', {
    config: { rateLimit: rateLimitBulk },
    preHandler: exportGuards,
    preValidation: zodValidator({ body: bulkExportRequestSchema }),
  }, async (request, reply) => {
    const body = request.body as BulkExportRequest;
    const orgId = request.user!.orgId;
    const org = await prisma.organization.findUniqueOrThrow({ where: { id: orgId }, select: { plan: true } });
    if (body.png && 'sizeMm' in body.png) {
      const gate = exportGateMessage(org.plan, { format: 'png', isPrintSize: true });
      if (gate) return reply.status(403).send(gateRefusalBody({ message: gate }));
    }
    let codeIds: string[];
    try {
      codeIds = await resolveExportSelection(prisma, orgId, actorOf(request), body.selection);
    } catch (err) {
      if (err instanceof ExportSelectionError) return sendCode(reply, err.code === 'export-import-not-found' ? 404 : 422, err.code, err.message);
      if (sendOrganizeError(err, reply)) return reply;
      throw err;
    }
    const input: ExportJobInput = { codeIds, formats: body.formats, png: body.png ?? null };
    const selection = 'tokens' in body.selection ? 'tokens' : 'importJobId' in body.selection ? 'import' : 'filter';
    let job: BulkJob;
    try {
      job = await createBulkJob(prisma, auditContext(request), {
        organizationId: orgId,
        kind: 'EXPORT',
        input: input as never,
        total: codeIds.length,
        auditMetadata: { selection, formats: body.formats, png: body.png ?? null },
      });
    } catch (err) {
      if (err instanceof BulkJobActiveError) {
        return sendCode(reply, 409, 'bulk-job-active', 'An export is already running in this organization; wait for it to finish.', { activeJobId: err.activeJobId });
      }
      throw err;
    }
    return startJob(reply, job);
  });

  // -------------------------------------------------------------------------
  // POST /exports/:id/link — a download link for the starter, valid 5 minutes
  // -------------------------------------------------------------------------
  fastify.post('/exports/:id/link', {
    config: { rateLimit: rateLimitAuth },
    preHandler: exportGuards,
    preValidation: zodValidator({ params: idParams }),
  }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const job = await loadJobFor(prisma, id, request.user!.orgId, actorOf(request), 'EXPORT');
    if (!job) return notFound(reply, 'Export');
    if (job.status !== 'SUCCEEDED' || !job.filePath) {
      return sendCode(reply, 409, 'export-not-ready', job.status === 'FAILED' ? 'The export failed; start a new one.' : 'The export is not ready yet.');
    }
    if (job.expiresAt && job.expiresAt <= new Date()) return sendCode(reply, 410, 'export-expired', 'The export was deleted 24 hours after it finished; start a new one.');
    const { query, expiresAt } = signExportLink(job);
    const base = config.server.isDev ? `http://localhost:${config.server.port}` : config.webauthn.origin;
    return reply.send({ url: `${base}/api/v1/bulk/exports/${job.id}/download?${query}`, expiresAt: expiresAt.toISOString() });
  });

  // -------------------------------------------------------------------------
  // GET /exports/:id/download?expires=&sig= — the ZIP (no session: the link is the credential)
  // -------------------------------------------------------------------------
  fastify.get('/exports/:id/download', {
    config: { rateLimit: rateLimitPublic },
    preValidation: zodValidator({ params: idParams, querystring: downloadQuery }),
  }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const { expires, sig } = request.query as { expires: number; sig: string };
    const job = await prisma.bulkJob.findUnique({ where: { id } });
    // One answer for every refusal, so a link reveals nothing about other jobs.
    const refuse = () => sendCode(reply, 403, 'link-invalid', 'This download link is invalid or has expired; create a new one from the export.');
    if (!job || job.kind !== 'EXPORT' || !verifyExportLink(job, expires, sig)) return refuse();
    if (job.status !== 'SUCCEEDED' || !job.filePath || !isInExportDir(job.filePath)) return refuse();
    if (job.expiresAt && job.expiresAt <= new Date()) return refuse();
    const info = await stat(job.filePath).catch(() => null);
    if (!info?.isFile()) return refuse();
    return reply
      .header('Content-Type', 'application/zip')
      .header('Content-Length', String(info.size))
      .header('Content-Disposition', `attachment; filename="qrauth-export-${job.id}.zip"`)
      .header('Cache-Control', 'no-store')
      .header('Referrer-Policy', 'no-referrer')
      .send(createReadStream(job.filePath));
  });
}
