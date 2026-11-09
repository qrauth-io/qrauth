import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import {
  createFolderSchema,
  createTagSchema,
  updateFolderSchema,
  updateTagSchema,
  type CreateFolderInput,
  type CreateTagInput,
  type AuditLogAction,
  type UpdateTagInput,
} from '@qrauth/shared';
import { z } from 'zod';

import { authorize } from '../middleware/authorize.js';
import { zodValidator } from '../middleware/validate.js';
import { rateLimitAuth } from '../middleware/rateLimit.js';
import { sendOrganizeError } from '../lib/organize-errors.js';
import { auditContext } from '../services/audit.js';
import {
  createFolder,
  createTag,
  deleteFolder,
  deleteTag,
  listFolders,
  listTags,
  renameFolder,
  updateTag,
  organizeAudit,
} from '../services/qr-organize.js';

/**
 * Tags (/api/v1/tags) and folders (/api/v1/folders) of the caller's
 * organization (Milestone 1). Every role reads; MEMBER+ writes. Ids of other
 * organizations are 404. Assigning them to codes is POST
 * /api/v1/qrcodes/bulk-tag and /bulk-move.
 */

const READ_ROLES = ['OWNER', 'ADMIN', 'MANAGER', 'MEMBER', 'VIEWER'];
const WRITE_ROLES = ['OWNER', 'ADMIN', 'MANAGER', 'MEMBER'];
const idParams = z.object({ id: z.string().min(1).max(64) });

/** The audit entry for a tag or folder change by the request's actor. */
const audit = (request: FastifyRequest, action: AuditLogAction, resource: 'Tag' | 'Folder') =>
  organizeAudit(auditContext(request), request.user!.orgId, action, resource);

async function run(reply: FastifyReply, status: number, action: () => Promise<unknown>) {
  try {
    const body = await action();
    return status === 204 ? reply.status(204).send() : reply.status(status).send(body);
  } catch (err) {
    if (sendOrganizeError(err, reply)) return reply;
    throw err;
  }
}

export async function tagRoutes(fastify: FastifyInstance): Promise<void> {
  const { authenticate } = fastify;
  const read = { config: { rateLimit: rateLimitAuth }, preHandler: [authenticate, authorize(...READ_ROLES)] };
  const write = { config: { rateLimit: rateLimitAuth }, preHandler: [authenticate, authorize(...WRITE_ROLES)] };

  fastify.get('/', read, async (request, reply) =>
    run(reply, 200, async () => ({ data: await listTags(fastify.prisma, request.user!.orgId) })));

  fastify.post('/', { ...write, preValidation: zodValidator({ body: createTagSchema }) }, async (request, reply) =>
    run(reply, 201, () => createTag(fastify.prisma, request.user!.orgId, request.body as CreateTagInput, audit(request, 'tag.create', 'Tag'))));

  fastify.patch('/:id', { ...write, preValidation: zodValidator({ params: idParams, body: updateTagSchema }) }, async (request, reply) => {
    const { id } = request.params as { id: string };
    return run(reply, 200, () => updateTag(fastify.prisma, request.user!.orgId, id, request.body as UpdateTagInput, audit(request, 'tag.update', 'Tag')));
  });

  fastify.delete('/:id', { ...write, preValidation: zodValidator({ params: idParams }) }, async (request, reply) => {
    const { id } = request.params as { id: string };
    return run(reply, 204, () => deleteTag(fastify.prisma, request.user!.orgId, id, audit(request, 'tag.delete', 'Tag')));
  });
}

export async function folderRoutes(fastify: FastifyInstance): Promise<void> {
  const { authenticate } = fastify;
  const read = { config: { rateLimit: rateLimitAuth }, preHandler: [authenticate, authorize(...READ_ROLES)] };
  const write = { config: { rateLimit: rateLimitAuth }, preHandler: [authenticate, authorize(...WRITE_ROLES)] };

  fastify.get('/', read, async (request, reply) =>
    run(reply, 200, async () => {
      const { folders, unfiledCount } = await listFolders(fastify.prisma, request.user!.orgId);
      return { data: folders, unfiledCount };
    }));

  fastify.post('/', { ...write, preValidation: zodValidator({ body: createFolderSchema }) }, async (request, reply) =>
    run(reply, 201, () => createFolder(fastify.prisma, request.user!.orgId, (request.body as CreateFolderInput).name, audit(request, 'folder.create', 'Folder'))));

  fastify.patch('/:id', { ...write, preValidation: zodValidator({ params: idParams, body: updateFolderSchema }) }, async (request, reply) => {
    const { id } = request.params as { id: string };
    return run(reply, 200, () =>
      renameFolder(fastify.prisma, request.user!.orgId, id, (request.body as CreateFolderInput).name, audit(request, 'folder.update', 'Folder')));
  });

  fastify.delete('/:id', { ...write, preValidation: zodValidator({ params: idParams }) }, async (request, reply) => {
    const { id } = request.params as { id: string };
    return run(reply, 204, () => deleteFolder(fastify.prisma, request.user!.orgId, id, audit(request, 'folder.delete', 'Folder')));
  });
}
