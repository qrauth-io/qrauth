import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { z } from 'zod';

import { CUSTOMER_LOGO_ORG_SELECT, customerLogoGate, gateRefusalBody, logoEligibility } from '../config/plan-limits.js';
import { notFoundError } from '../lib/responses.js';
import { verifiedEmailGuard } from '../lib/verified-actor.js';
import { API_KEY_PRINCIPAL_ID } from '../middleware/auth.js';
import { authorize } from '../middleware/authorize.js';
import { rateLimitGenerate } from '../middleware/rateLimit.js';
import { zodValidator } from '../middleware/validate.js';
import { AuditLogService } from '../services/audit.js';
import { cleanLogoName, LOGO_MAX_PER_ORG, LogoLibrary, type LogoAuditHook } from '../services/logo-library.js';
import {
  LOGO_UPLOAD_MAX_BYTES,
  LOGO_UPLOAD_TYPES,
  LogoRejectedError,
  normaliseLogo,
  type LogoRejection,
} from '../services/logo-normalise.js';

/**
 * The organization logo library (ADR-0005 D6), mounted at /api/v1/assets.
 *
 * - POST   /logos      raw PNG, JPEG or WebP body (at most 1 MiB); paid plans
 *                       with a verified issuer
 * - GET    /logos      the organization's logos
 * - GET    /logos/:id  the normalised PNG
 * - DELETE /logos/:id  refused (409) while a code draws the logo
 *
 * Logos are never served publicly. Another organization's id answers like a
 * missing one (404), so ids cannot be probed.
 */

const READ_ROLES = ['OWNER', 'ADMIN', 'MANAGER', 'MEMBER', 'VIEWER'] as const;
/** The roles that can create QR codes (routes/qrcodes.ts). */
const UPLOAD_ROLES = ['OWNER', 'ADMIN', 'MANAGER', 'MEMBER'] as const;
const DELETE_ROLES = ['OWNER', 'ADMIN', 'MANAGER'] as const;

/**
 * A logo's bytes never change for an id, but a browser copy should not
 * outlive a deleted logo or a member's access by long: one day, private.
 */
export const LOGO_CACHE_CONTROL = 'private, max-age=86400';

const idParamsSchema = z.object({ id: z.string().min(1).max(64) }).strict();
const uploadQuerySchema = z.object({ name: z.string().max(200).optional() }).strict();

/** Status for each rejection: wrong type 415, too large 413, an unusable image 422. */
const REJECTION_STATUS: Readonly<Record<LogoRejection, number>> = {
  'unsupported-type': 415,
  'svg-not-accepted': 415,
  'too-large': 413,
  animated: 422,
  dimensions: 422,
  unreadable: 422,
  'too-complex': 422,
};

const STATUS_ERROR: Readonly<Record<number, string>> = {
  413: 'Payload Too Large',
  415: 'Unsupported Media Type',
  422: 'Unprocessable Entity',
};

function sendRejection(reply: FastifyReply, err: LogoRejectedError): FastifyReply {
  const statusCode = REJECTION_STATUS[err.code];
  return reply.status(statusCode).send({ statusCode, error: STATUS_ERROR[statusCode], code: err.code, message: err.message });
}

const UNSUPPORTED = new LogoRejectedError('unsupported-type', 'Upload a PNG, JPEG or WebP image.');

/** Audit-log actions of the logo library (services/audit.ts conventions). */
export const LOGO_AUDIT_ACTION = { upload: 'logo.upload', delete: 'logo.delete' } as const;

/**
 * The audit-log entry for a logo change by the request's actor, written in
 * the transaction that makes the change. An AuditLog row names a user (a
 * foreign key), so a change made with an API key, which has none, is
 * recorded in the request log only.
 */
function logoAudit(request: FastifyRequest, action: string): LogoAuditHook | undefined {
  const actor = request.user!;
  if (actor.id === API_KEY_PRINCIPAL_ID) return undefined;
  return (tx, { assetId, sizeBytes }) =>
    new AuditLogService(tx).log({
      organizationId: actor.orgId,
      userId: actor.id,
      action,
      resource: 'ContentAsset',
      resourceId: assetId,
      metadata: { kind: 'LOGO', sizeBytes },
      ipAddress: request.ip,
    });
}

export default async function assetRoutes(fastify: FastifyInstance): Promise<void> {
  const { authenticate } = fastify;
  const library = new LogoLibrary(fastify.prisma);

  // The upload route has its own encapsulated context, so the raw image
  // parser applies to it alone.
  await fastify.register(async (upload) => {
    upload.addContentTypeParser(
      [...LOGO_UPLOAD_TYPES],
      { parseAs: 'buffer', bodyLimit: LOGO_UPLOAD_MAX_BYTES },
      (_request, body, done) => done(null, body),
    );

    upload.post('/logos', {
      bodyLimit: LOGO_UPLOAD_MAX_BYTES,
      config: { rateLimit: rateLimitGenerate },
      // Authentication reads only headers, so it runs before the body is
      // read: an anonymous upload is 401 without buffering up to 1 MiB.
      onRequest: [authenticate],
      preHandler: [authorize(...UPLOAD_ROLES), verifiedEmailGuard(fastify.prisma)],
      preValidation: zodValidator({ querystring: uploadQuerySchema }),
    }, async (request: FastifyRequest, reply: FastifyReply) => {
      const orgId = request.user!.orgId;
      const org = await fastify.prisma.organization.findUnique({ where: { id: orgId }, select: CUSTOMER_LOGO_ORG_SELECT });
      // A paid plan and a verified issuer (ADR-0005 D9, amended 2026-10-29).
      const refusal = customerLogoGate(logoEligibility(org));
      if (refusal) return reply.status(403).send(gateRefusalBody(refusal));

      // A JSON or form body reaches here parsed; only the raw image parser yields a Buffer.
      if (!Buffer.isBuffer(request.body)) return sendRejection(reply, UNSUPPORTED);

      let logo;
      try {
        logo = await normaliseLogo(new Uint8Array(request.body));
      } catch (err) {
        if (err instanceof LogoRejectedError) return sendRejection(reply, err);
        throw err;
      }

      const { name } = request.query as z.infer<typeof uploadQuerySchema>;
      const result = await library.create(orgId, logo, cleanLogoName(name), logoAudit(request, LOGO_AUDIT_ACTION.upload));
      if (result.outcome === 'limit_reached') {
        return reply.status(409).send({
          statusCode: 409,
          error: 'Conflict',
          message: `An organization can keep up to ${LOGO_MAX_PER_ORG} logos. Delete one to upload another.`,
        });
      }
      request.log.info({ orgId, actor: request.user!.id, assetId: result.logo.id, sizeBytes: result.logo.sizeBytes }, 'logo uploaded');
      return reply.status(201).send(result.logo);
    });
  });

  fastify.get('/logos', {
    preHandler: [authenticate, authorize(...READ_ROLES)],
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    return reply.send({ data: await library.list(request.user!.orgId) });
  });

  fastify.get('/logos/:id', {
    preHandler: [authenticate, authorize(...READ_ROLES)],
    preValidation: zodValidator({ params: idParamsSchema }),
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    const { id } = request.params as { id: string };
    const bytes = await library.bytes(request.user!.orgId, id);
    if (!bytes) return reply.status(404).send(notFoundError('Logo', id));
    return reply
      .header('Cache-Control', LOGO_CACHE_CONTROL)
      .type('image/png')
      .send(Buffer.from(bytes));
  });

  fastify.delete('/logos/:id', {
    preHandler: [authenticate, authorize(...DELETE_ROLES)],
    preValidation: zodValidator({ params: idParamsSchema }),
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    const { id } = request.params as { id: string };
    const result = await library.delete(request.user!.orgId, id, logoAudit(request, LOGO_AUDIT_ACTION.delete));
    if (result.outcome === 'not_found') return reply.status(404).send(notFoundError('Logo', id));
    if (result.outcome === 'in_use') {
      const codes = result.count === 1 ? '1 QR code uses' : `${result.count} QR codes use`;
      return reply.status(409).send({
        statusCode: 409,
        error: 'Conflict',
        message: `${codes} this logo. Choose another logo for ${result.count === 1 ? 'it' : 'them'} before deleting.`,
        count: result.count,
      });
    }
    request.log.info({ orgId: request.user!.orgId, actor: request.user!.id, assetId: id, sizeBytes: result.sizeBytes }, 'logo deleted');
    return reply.status(204).send();
  });
}
