import type { FastifyReply } from 'fastify';

import {
  OrganizeLimitError,
  OrganizeNameTakenError,
  OrganizeNotFoundError,
  isUniqueViolation,
} from '../services/qr-organize.js';
import { notFoundError } from './responses.js';

/**
 * Sends the response for a tag or folder error and returns true, or returns
 * false for any other error (the caller rethrows it).
 *   not found (incl. another org's id) → 404
 *   per-org cap reached                  → 409 limit-reached
 *   name already used                    → 409 name-taken
 */
export function sendOrganizeError(err: unknown, reply: FastifyReply): boolean {
  if (err instanceof OrganizeNotFoundError) {
    reply.status(404).send(notFoundError(err.resource, err.id));
    return true;
  }
  if (err instanceof OrganizeLimitError) {
    reply.status(409).send({ statusCode: 409, error: 'Conflict', code: 'limit-reached', message: err.message });
    return true;
  }
  if (err instanceof OrganizeNameTakenError || isUniqueViolation(err)) {
    const message = err instanceof OrganizeNameTakenError ? err.message : 'That name is already used.';
    reply.status(409).send({ statusCode: 409, error: 'Conflict', code: 'name-taken', message });
    return true;
  }
  return false;
}
