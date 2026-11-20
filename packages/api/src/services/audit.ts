import { Prisma, type PrismaClient } from '@prisma/client';
import type { FastifyRequest } from 'fastify';
import { AUDIT_RETENTION_DAYS, type AuditActorType, type AuditLogAction } from '@qrauth/shared';

/**
 * Organization audit log (Milestone 2, ADR-0008). Every mutating route
 * records one entry, in the same transaction as the change, through
 * `recordAudit`. QR code changes are not written here: they are the QR edit
 * history (services/qr-revisions.ts), merged in by services/audit-query.ts.
 *
 * The table is append-only (trigger in migration 20261103120000). Only the
 * retention job and GDPR erasure may delete or clear rows, inside
 * `withAuditMaintenance`.
 *
 * SOC 2 CC7.2 / ISO 27001 A.12.4.1: logging of security-relevant events.
 */

export type AuditActor =
  | { type: 'USER'; userId: string }
  | { type: 'SUPERADMIN'; userId: string }
  | { type: 'API_KEY'; apiKeyId: string }
  | { type: 'SYSTEM'; system: string };

export interface AuditContext {
  actor: AuditActor;
  requestId: string | null;
  ip: string | null;
  userAgent: string | null;
}

export interface AuditEvent {
  organizationId: string;
  action: AuditLogAction;
  resource: string;
  resourceId: string;
  metadata?: Record<string, unknown>;
}

/** A client or an interactive transaction; pass the transaction that makes the change. */
export type AuditDb = Pick<Prisma.TransactionClient, 'auditLog'>;

export const USER_AGENT_MAX = 512;

function userAgentOf(request: FastifyRequest): string | null {
  const ua = request.headers['user-agent'];
  return typeof ua === 'string' && ua.length > 0 ? ua.slice(0, USER_AGENT_MAX) : null;
}

/**
 * Who made a request: the API key when one authenticated it, else the
 * signed-in user. Superadmin routes pass `superadmin: true`.
 */
export function auditContext(request: FastifyRequest, opts: { superadmin?: boolean } = {}): AuditContext {
  const user = request.user!;
  let actor: AuditActor;
  if (user.apiKeyId) actor = { type: 'API_KEY', apiKeyId: user.apiKeyId };
  else if (opts.superadmin) actor = { type: 'SUPERADMIN', userId: user.id };
  else actor = { type: 'USER', userId: user.id };
  return { actor, requestId: request.id, ip: request.ip ?? null, userAgent: userAgentOf(request) };
}

/** A request whose actor is a user who is not (yet) on request.user, e.g. at sign-up or OAuth callback. */
export function userAuditContext(request: FastifyRequest, userId: string): AuditContext {
  return { actor: { type: 'USER', userId }, requestId: request.id, ip: request.ip ?? null, userAgent: userAgentOf(request) };
}

/** A worker, webhook or job; `request` when it runs inside one (e.g. the Stripe webhook). */
export function systemAuditContext(system: string, request?: FastifyRequest): AuditContext {
  return {
    actor: { type: 'SYSTEM', system },
    requestId: request?.id ?? null,
    ip: null,
    userAgent: null,
  };
}

function actorColumns(actor: AuditActor): { actorType: AuditActorType; actorId: string; userId: string | null } {
  switch (actor.type) {
    case 'USER':
    case 'SUPERADMIN':
      return { actorType: actor.type, actorId: actor.userId, userId: actor.userId };
    case 'API_KEY':
      return { actorType: 'API_KEY', actorId: actor.apiKeyId, userId: null };
    case 'SYSTEM':
      return { actorType: 'SYSTEM', actorId: actor.system, userId: null };
  }
}

/** Records one audit entry. Call with the transaction that makes the change. */
export async function recordAudit(db: AuditDb, ctx: AuditContext, event: AuditEvent): Promise<void> {
  await db.auditLog.create({
    data: {
      organizationId: event.organizationId,
      action: event.action,
      resource: event.resource,
      resourceId: event.resourceId,
      metadata: (event.metadata ?? undefined) as Prisma.InputJsonValue | undefined,
      ipAddress: ctx.ip,
      userAgent: ctx.userAgent,
      requestId: ctx.requestId,
      ...actorColumns(ctx.actor),
    },
  });
}

/** Records the same event in several organizations (e.g. an account deleted while a member of each). */
export async function recordAuditInOrgs(
  db: AuditDb,
  ctx: AuditContext,
  organizationIds: readonly string[],
  event: Omit<AuditEvent, 'organizationId'>,
): Promise<void> {
  for (const organizationId of new Set(organizationIds)) {
    await recordAudit(db, ctx, { ...event, organizationId });
  }
}

// ---------------------------------------------------------------------------
// Maintenance: the only writes the append-only triggers allow
// ---------------------------------------------------------------------------

export type AuditMaintenance = 'retention' | 'erasure';
type MaintenanceTx = Prisma.TransactionClient;

/**
 * Runs `fn` in a transaction with qrauth.audit_maintenance set (transaction
 * local), which the append-only triggers on audit_logs and
 * qr_code_revisions check. Pass `tx` to join a transaction already open.
 */
export async function withAuditMaintenance<T>(
  db: PrismaClient | MaintenanceTx,
  mode: AuditMaintenance,
  fn: (tx: MaintenanceTx) => Promise<T>,
): Promise<T> {
  const run = async (tx: MaintenanceTx) => {
    await tx.$executeRaw`SELECT set_config('qrauth.audit_maintenance', ${mode}, true)`;
    const result = await fn(tx);
    // Clear it for the rest of a joined transaction. On failure the
    // transaction is aborted and rolls back, which ends the setting too.
    await tx.$executeRaw`SELECT set_config('qrauth.audit_maintenance', '', true)`;
    return result;
  };
  return '$transaction' in db ? (db as PrismaClient).$transaction(run) : run(db);
}

/** Deletes audit entries past retention, by the database clock (the trigger checks the same clock). */
export async function purgeExpiredAuditLogs(db: PrismaClient): Promise<number> {
  return withAuditMaintenance(db, 'retention', (tx) =>
    tx.$executeRaw`
      DELETE FROM "audit_logs"
      WHERE "createdAt" < now() - make_interval(days => ${AUDIT_RETENTION_DAYS}::int)`,
  );
}

/**
 * GDPR erasure of an account (Art. 17), in the account-deletion
 * transaction. Clears IP and user agent of every entry the user made, in
 * person or with an API key they created; in every entry, replaces the
 * user's email address in metadata (compared case-insensitively) with
 * "[redacted]" and drops ipCountry. The append-only trigger allows exactly
 * this update (migrations 20261103140000 and 20261103150000), using the
 * same audit_redact_subject function.
 */
export async function eraseAuditPersonalData(
  tx: MaintenanceTx,
  subject: { userId: string; email: string | null },
): Promise<number> {
  const email = subject.email ?? '';
  return withAuditMaintenance(tx, 'erasure', async (t) => {
    await t.$executeRaw`SELECT set_config('qrauth.erasure_subject', ${email}, true)`;
    const count = await t.$executeRaw`
      WITH own AS (
        SELECT a."id" FROM "audit_logs" a
        WHERE a."userId" = ${subject.userId}
           OR (a."actorType" = 'API_KEY'
               AND a."actorId" IN (SELECT k."id" FROM "api_keys" k WHERE k."createdByUserId" = ${subject.userId}))
      )
      UPDATE "audit_logs" l SET
        "ipAddress" = CASE WHEN l."id" IN (SELECT "id" FROM own) THEN NULL ELSE l."ipAddress" END,
        "userAgent" = CASE WHEN l."id" IN (SELECT "id" FROM own) THEN NULL ELSE l."userAgent" END,
        "metadata"  = audit_redact_subject(l."metadata", ${email})
      WHERE l."id" IN (SELECT "id" FROM own)
         OR (${email} <> '' AND l."metadata" IS NOT NULL AND strpos(lower(l."metadata"::text), lower(to_jsonb(${email}::text)::text)) > 0)`;
    await t.$executeRaw`SELECT set_config('qrauth.erasure_subject', '', true)`;
    return count;
  });
}

