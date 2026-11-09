import { createHash } from 'node:crypto';
import { Prisma, type PrismaClient } from '@prisma/client';
import type { DomainCheck } from './domain.js';

export type LookalikeIncidentSource = 'create' | 'update' | 'daily_rescan';

/**
 * Records a lookalike destination or link as a HIGH fraud incident. The one
 * path for every writer: create and PATCH (routes/qrcodes.ts) and the daily
 * re-scan, which catches a code that became a lookalike after it was issued
 * (a new verified organization or protected entry). One incident per code,
 * URL and protected domain, whichever path saw it first:
 * - the database enforces it through `dedupeKey` (unique per code), so
 *   concurrent writers record one incident;
 * - incidents written before that (no `dedupeKey`; `link` for links, only
 *   `destinationDomain`, with or without www., for destinations) count as
 *   the same incident.
 * Returns true when an incident was created.
 */
export async function recordLookalikeIncident(
  db: Pick<PrismaClient, 'fraudIncident'>,
  qrCodeId: string,
  url: string,
  warning: DomainCheck['warnings'][number],
  source: LookalikeIncidentSource,
): Promise<boolean> {
  const host = safeHost(url);
  const legacyHosts = host ? [host, `www.${host}`] : [];
  const existing = await db.fraudIncident.findFirst({
    where: {
      qrCodeId,
      AND: [
        { details: { path: ['reason'], equals: 'suspicious_domain' } },
        { details: { path: ['similarTo'], equals: warning.domain } },
        {
          OR: [
            { details: { path: ['url'], equals: url } },
            { details: { path: ['link'], equals: url } },
            ...legacyHosts.map((h) => ({
              AND: [{ details: { path: ['destinationDomain'], equals: h } }, { details: { path: ['url'], equals: Prisma.AnyNull } }],
            })),
          ],
        },
      ],
    },
    select: { id: true },
  });
  if (existing) return false;
  try {
    await db.fraudIncident.create({
      data: {
        qrCodeId,
        type: 'MANUAL_REPORT',
        severity: 'HIGH',
        dedupeKey: lookalikeDedupeKey(url, warning.domain),
        details: {
          reason: 'suspicious_domain',
          source,
          url,
          destinationDomain: host,
          similarTo: warning.domain,
          verifiedOrg: warning.verifiedOrgName,
          similarity: warning.similarity,
          lookalikeReason: warning.reason,
        },
      },
    });
  } catch (err) {
    // Another writer recorded the same incident first.
    if (err instanceof Prisma.PrismaClientKnownRequestError && err.code === 'P2002') return false;
    throw err;
  }
  return true;
}

/** The incident's identity: URL and protected domain (hashed: URLs can be long). */
export function lookalikeDedupeKey(url: string, similarTo: string): string {
  return `lookalike:${createHash('sha256').update(`${url}\u0000${similarTo}`).digest('hex')}`;
}

/** The URL's host without www. (as destinationDomain is recorded). */
function safeHost(url: string): string | null {
  try {
    return new URL(url).hostname.toLowerCase().replace(/^www\./, '');
  } catch {
    return null;
  }
}
