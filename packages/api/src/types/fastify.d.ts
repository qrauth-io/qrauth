import type { PrismaClient } from '@prisma/client';
import type { Redis } from 'ioredis';

// ---------------------------------------------------------------------------
// Request-scoped user context
// ---------------------------------------------------------------------------

export interface UserContext {
  id: string;       // userId (or 'api-key' for API key auth)
  orgId: string;    // active organizationId
  role: string;     // MembershipRole value
  email: string;
}

// ---------------------------------------------------------------------------
// Module augmentation
// ---------------------------------------------------------------------------

declare module 'fastify' {
  interface FastifyInstance {
    prisma: PrismaClient;
    redis: Redis;
    authenticate: (
      request: FastifyRequest,
      reply: FastifyReply,
    ) => Promise<void>;
  }
}

declare module '@fastify/jwt' {
  interface FastifyJWT {
    payload: { userId: string; orgId: string; role: string; email: string };
    user: UserContext;
  }
}
