import type { PrismaClient } from '@prisma/client';

/**
 * The first-party App the OpenID Provider uses to create auth-sessions
 * scan-approval sessions for OP-hosted login (ADR-0003 Slice 3b.2).
 * Provisioned by migration 20260531200000_provision_qrauth_op_app on the
 * QRAuth Platform org.
 */
export const QRAUTH_OP_CLIENT_ID = 'qrauth-op' as const;

/** Thrown when the qrauth-op App row is absent (migration not applied). */
export class OpAppNotProvisionedError extends Error {
  constructor() {
    super(
      `The "${QRAUTH_OP_CLIENT_ID}" App is not provisioned. Apply migration ` +
        '20260531200000_provision_qrauth_op_app (runs automatically on deploy).',
    );
    this.name = 'OpAppNotProvisionedError';
  }
}

// The App.id is immutable once provisioned, so we memoise it per process to
// avoid a DB round-trip on every /login.
let cachedOpAppId: string | null = null;

/**
 * Resolve the qrauth-op App.id, the `appId` passed to
 * `AuthSessionService.createSession`. Throws {@link OpAppNotProvisionedError}
 * if the App row is missing.
 */
export async function getOpAppId(prisma: PrismaClient): Promise<string> {
  if (cachedOpAppId) return cachedOpAppId;
  const app = await prisma.app.findUnique({
    where: { clientId: QRAUTH_OP_CLIENT_ID },
    select: { id: true },
  });
  if (!app) throw new OpAppNotProvisionedError();
  cachedOpAppId = app.id;
  return app.id;
}

/** Test-only: reset the memoised App.id. */
export function __resetOpAppIdCache(): void {
  cachedOpAppId = null;
}
