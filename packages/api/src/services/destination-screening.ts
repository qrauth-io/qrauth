import type { FastifyBaseLogger } from 'fastify';
import type { PrismaClient } from '@prisma/client';
import { cacheDel } from '../lib/cache.js';
import { config } from '../lib/config.js';
import { sendDestinationFlaggedEmail } from '../lib/email.js';
import { webRiskQueue } from '../lib/queue.js';
import { lookupDestination, type WebRiskVerdict } from '../lib/web-risk.js';

/**
 * Destination screening for QR codes (Google Web Risk).
 *
 * - Create, bulk create and destination edits screen the URL first: a hit is
 *   refused (422 DestinationFlagged); an API error or timeout lets the request
 *   through and queues an immediate re-check.
 * - The re-check worker (workers/web-risk.ts) flags a code it finds on a
 *   threat list: destinationFlaggedAt/destinationFlagReason are set, the
 *   verify page shows the code as UNTRUSTED, and the org owners plus the
 *   abuse inbox are emailed. A later clean verdict does not clear the flag.
 */

export const DESTINATION_FLAGGED_ERROR = 'DestinationFlagged';

export function screenDestination(url: string): Promise<WebRiskVerdict> {
  return lookupDestination(url);
}

/** 422 body for a destination on a threat list. */
export function destinationFlaggedBody(threatTypes: string[]) {
  return {
    statusCode: 422,
    error: DESTINATION_FLAGGED_ERROR,
    message: 'This destination is listed as dangerous by Google Web Risk and cannot be used.',
    threatType: threatTypes[0] ?? 'UNKNOWN',
    threatTypes,
  };
}

export interface RecheckJob {
  token: string;
}

/** Queue an immediate re-check of one code (best effort). */
export async function enqueueDestinationRecheck(token: string, log: FastifyBaseLogger): Promise<void> {
  try {
    await webRiskQueue.add('recheck', { token } satisfies RecheckJob, {
      attempts: 5,
      backoff: { type: 'exponential', delay: 30_000 },
    });
  } catch (err) {
    log.warn({ err, token }, 'destination-screening: could not queue re-check; the daily scan will cover it');
  }
}

type ScreeningDb = Pick<PrismaClient, 'qRCode' | 'membership'>;

/**
 * Flags a code whose destination is on a threat list. Only the first flag
 * emails anyone; a code that is already flagged is left as it is.
 * Returns true when this call set the flag.
 */
export async function flagQrCode(
  prisma: ScreeningDb,
  log: FastifyBaseLogger,
  token: string,
  threatTypes: string[],
): Promise<boolean> {
  const reason = threatTypes.join(',');
  const { count } = await prisma.qRCode.updateMany({
    where: { token, destinationFlaggedAt: null },
    data: { destinationFlaggedAt: new Date(), destinationFlagReason: reason },
  });
  if (count === 0) return false;

  try {
    await cacheDel(`verify:${token}`);
  } catch {
    // the verify path reads the flag from the database
  }

  const code = await prisma.qRCode.findUnique({
    where: { token },
    select: { destinationUrl: true, organizationId: true, organization: { select: { name: true } } },
  });
  if (!code) return true;

  const owners = await prisma.membership.findMany({
    where: { organizationId: code.organizationId, role: 'OWNER' },
    select: { user: { select: { email: true } } },
  });
  const recipients = new Set(owners.map((o) => o.user.email).filter(Boolean));
  if (config.abuse.notifyEmail) recipients.add(config.abuse.notifyEmail);

  const flag = { token, organizationName: code.organization.name, destinationUrl: code.destinationUrl, threatTypes };
  await Promise.all(
    [...recipients].map((to) =>
      sendDestinationFlaggedEmail(to, flag).catch((err: unknown) =>
        log.warn({ err, token }, 'destination-screening: flag email not sent'),
      ),
    ),
  );
  log.warn({ event: 'qr.destination_flagged', token, threatTypes }, 'QR destination flagged by Web Risk');
  return true;
}
