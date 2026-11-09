import type { App } from '@prisma/client';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import type { AuditLogAction } from '@qrauth/shared';
import { zodValidator } from '../middleware/validate.js';
import { authorize } from '../middleware/authorize.js';
import { createAppSchema, updateAppSchema } from '@qrauth/shared';
import { AppService, type AppAuditHook } from '../services/app.js';
import { auditContext, recordAudit } from '../services/audit.js';
import { rateLimitAuth } from '../middleware/rateLimit.js';
import { invalidateAllowedAppOrigins } from '../lib/cors-origins.js';
import { config } from '../lib/config.js';
import { LEGACY_APP_FREEZE_MESSAGE, appCreationBlockedByFreeze } from '../lib/legacy-app-freeze.js';

/** App fields shown in audit entries (never the secret hash). */
const APP_AUDIT_FIELDS = ['name', 'slug', 'description', 'redirectUrls', 'webhookUrl', 'allowedScopes', 'logoUrl', 'status'] as const;

function sameValue(a: unknown, b: unknown): boolean {
  return JSON.stringify(a ?? null) === JSON.stringify(b ?? null);
}

/** `{ field: { before, after } }` for each audited field that changed. */
export function appFieldChanges(before: App, after: App): Record<string, { before: unknown; after: unknown }> {
  return Object.fromEntries(
    APP_AUDIT_FIELDS
      .filter((f) => !sameValue(before[f], after[f]))
      .map((f) => [f, { before: before[f] ?? null, after: after[f] ?? null }]),
  );
}

function appAuditMetadata(action: AuditLogAction, before: App | null, after: App): Record<string, unknown> {
  const base = { name: after.name, clientId: after.clientId };
  if (action === 'app.create') {
    return { ...base, redirectUrls: after.redirectUrls, allowedScopes: after.allowedScopes, webhookUrl: after.webhookUrl };
  }
  if (action === 'app.update' && before) return { ...base, changes: appFieldChanges(before, after) };
  return base;
}

/** Audit hook writing `action` for the request's actor, in the app's transaction. */
function appAudit(request: FastifyRequest, action: AuditLogAction): AppAuditHook {
  const ctx = auditContext(request);
  return async (tx, { before, after }) => {
    // An update that changed nothing writes no entry.
    if (action === 'app.update' && before && Object.keys(appFieldChanges(before, after)).length === 0) return;
    await recordAudit(tx, ctx, {
      organizationId: after.organizationId,
      action,
      resource: 'App',
      resourceId: after.id,
      metadata: appAuditMetadata(action, before, after),
    });
  };
}

export default async function appRoutes(fastify: FastifyInstance): Promise<void> {
  const { authenticate } = fastify;
  const appService = new AppService(fastify.prisma);

  // ---------------------------------------------------------------------------
  // POST / — Create app
  // ---------------------------------------------------------------------------

  fastify.post('/', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate, authorize('OWNER', 'ADMIN')],
    preValidation: zodValidator({ body: createAppSchema }),
  }, async (request, reply) => {
    // ADR-0004 freeze, when the operator has switched it on.
    if (config.legacy.appFreeze) {
      const org = await fastify.prisma.organization.findUnique({
        where: { id: request.user!.orgId },
        select: { slug: true },
      });
      if (appCreationBlockedByFreeze({ freezeEnabled: true, organizationSlug: org?.slug })) {
        return reply.status(403).send({
          statusCode: 403,
          error: 'Forbidden',
          code: 'LEGACY_APP_FREEZE',
          message: LEGACY_APP_FREEZE_MESSAGE,
        });
      }
    }

    const body = request.body as any;
    const result = await appService.createApp(request.user!.orgId, body, appAudit(request, 'app.create'));
    invalidateAllowedAppOrigins();

    // Return with clientSecret visible (only time it's shown)
    return reply.status(201).send({
      id: result.id,
      name: result.name,
      slug: result.slug,
      clientId: result.clientId,
      clientSecret: result.clientSecret, // SHOWN ONCE
      redirectUrls: result.redirectUrls,
      webhookUrl: result.webhookUrl,
      allowedScopes: result.allowedScopes,
      status: result.status,
      createdAt: result.createdAt,
    });
  });

  // ---------------------------------------------------------------------------
  // GET / — List apps
  // ---------------------------------------------------------------------------

  fastify.get('/', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate, authorize('OWNER', 'ADMIN', 'MANAGER')],
  }, async (request, reply) => {
    const apps = await appService.listApps(request.user!.orgId);
    return reply.send({ data: apps });
  });

  // ---------------------------------------------------------------------------
  // GET /:id — Get app details
  // ---------------------------------------------------------------------------

  fastify.get('/:id', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate, authorize('OWNER', 'ADMIN', 'MANAGER')],
  }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const app = await appService.getApp(id, request.user!.orgId);
    if (!app) {
      return reply.status(404).send({ statusCode: 404, error: 'Not Found', message: 'App not found' });
    }
    return reply.send(app);
  });

  // ---------------------------------------------------------------------------
  // PATCH /:id — Update app
  // ---------------------------------------------------------------------------

  fastify.patch('/:id', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate, authorize('OWNER', 'ADMIN')],
    preValidation: zodValidator({ body: updateAppSchema }),
  }, async (request, reply) => {
    const { id } = request.params as { id: string };
    try {
      const app = await appService.updateApp(id, request.user!.orgId, request.body as any, appAudit(request, 'app.update'));
      invalidateAllowedAppOrigins();
      return reply.send(app);
    } catch (err: any) {
      return reply.status(404).send({ statusCode: 404, error: 'Not Found', message: err.message });
    }
  });

  // ---------------------------------------------------------------------------
  // DELETE /:id — Soft delete app
  // ---------------------------------------------------------------------------

  fastify.delete('/:id', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate, authorize('OWNER', 'ADMIN')],
  }, async (request, reply) => {
    const { id } = request.params as { id: string };
    try {
      await appService.deleteApp(id, request.user!.orgId, appAudit(request, 'app.delete'));
      invalidateAllowedAppOrigins();
      return reply.status(204).send();
    } catch (err: any) {
      return reply.status(404).send({ statusCode: 404, error: 'Not Found', message: err.message });
    }
  });

  // ---------------------------------------------------------------------------
  // POST /:id/rotate-secret — Rotate client secret
  // ---------------------------------------------------------------------------

  fastify.post('/:id/rotate-secret', {
    config: { rateLimit: rateLimitAuth },
    preHandler: [authenticate, authorize('OWNER', 'ADMIN')],
  }, async (request, reply) => {
    const { id } = request.params as { id: string };
    try {
      const result = await appService.rotateSecret(id, request.user!.orgId, appAudit(request, 'app.rotateSecret'));
      return reply.send({
        clientSecret: result.clientSecret, // SHOWN ONCE
        message: 'Secret rotated. Store this value securely — it will not be shown again.',
      });
    } catch (err: any) {
      return reply.status(404).send({ statusCode: 404, error: 'Not Found', message: err.message });
    }
  });
}
