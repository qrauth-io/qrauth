import type { FastifyReply, FastifyRequest } from 'fastify';

export function authorize(...allowedRoles: string[]) {
  return async function authorizeHandler(
    request: FastifyRequest,
    reply: FastifyReply,
  ): Promise<void> {
    if (!request.user) {
      return reply.status(401).send({
        statusCode: 401,
        error: 'Unauthorized',
        message: 'Authentication required.',
      });
    }
    if (!allowedRoles.includes(request.user.role)) {
      return reply.status(403).send({
        statusCode: 403,
        error: 'Forbidden',
        message: 'Insufficient permissions.',
      });
    }
  };
}
