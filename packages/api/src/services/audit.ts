import type { PrismaClient } from '@prisma/client';

// ---------------------------------------------------------------------------
// Audit Log Service
// ---------------------------------------------------------------------------

/**
 * Provides consistent audit logging for sensitive operations.
 * Every mutation that touches PII, credentials, access control, or billing
 * should call this service so there is a single, queryable trail.
 *
 * SOC 2 CC7.2 / ISO 27001 A.12.4.1: Logging of security-relevant events.
 */
export class AuditLogService {
  constructor(private readonly prisma: PrismaClient) {}

  /**
   * Record a single audit event.
   *
   * @param organizationId – Org context (every event belongs to an org).
   * @param userId         – The actor who performed the action.
   * @param action         – Verb describing the event, e.g. "user.delete",
   *                         "apiKey.create", "member.role.update".
   * @param resource       – Resource type, e.g. "User", "ApiKey", "Membership".
   * @param resourceId     – ID of the affected resource.
   * @param metadata       – Free-form details (previous values, reason, etc.).
   * @param ipAddress      – Originating IP (hashed if available).
   */
  async log(params: {
    organizationId: string;
    userId: string;
    action: string;
    resource: string;
    resourceId: string;
    metadata?: Record<string, unknown>;
    ipAddress?: string;
  }): Promise<void> {
    await this.prisma.auditLog.create({
      data: {
        organizationId: params.organizationId,
        userId: params.userId,
        action: params.action,
        resource: params.resource,
        resourceId: params.resourceId,
        metadata: (params.metadata ?? undefined) as any,
        ipAddress: params.ipAddress ?? null,
      },
    });
  }
}
