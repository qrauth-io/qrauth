import type { PrismaClient } from '@prisma/client';

/**
 * Inserts `count` QR code rows for one organization in a single SQL
 * statement, for search performance work (Milestone 1: p95 under 50 ms at
 * 10k codes per org). Rows are realistic for search, not for scanning: the
 * signature is a placeholder, so they never verify.
 *
 * Shapes: labels from a word pool with a running number, ~40 destination
 * hosts with paths, a mix of content types and statuses, creation times
 * spread over a year. Tokens are `${tokenPrefix}${n}`.
 *
 * Used by test/db/qr-organize.db-test.ts and scripts/seed-qr-organize-dev.ts.
 */
export async function seedQrVolume(
  db: PrismaClient,
  opts: { orgId: string; signingKeyId: string; count: number; tokenPrefix: string },
): Promise<void> {
  await db.$executeRaw`
    INSERT INTO "qr_codes" (
      "id", "token", "organizationId", "signingKeyId", "destinationUrl", "label",
      "contentType", "signature", "algVersion", "status", "source", "createdAt", "updatedAt"
    )
    SELECT
      ${opts.tokenPrefix} || 'id' || n,
      ${opts.tokenPrefix} || n,
      ${opts.orgId},
      ${opts.signingKeyId},
      'https://' || (ARRAY['shop','menu','events','tickets','parking','museum','library','gym','hotel','cafe'])[1 + n % 10]
        || '.' || (ARRAY['example.com','thessaloniki.gr','progressnet.io','acme.test'])[1 + (n / 10) % 4]
        || '/p/' || n || '?ref=poster',
      (ARRAY['Poster','Flyer','Table card','Window sticker','Menu','Ticket','Badge','Receipt'])[1 + n % 8]
        || ' ' || (ARRAY['north','south','harbour','centre','airport','campus'])[1 + n % 6] || ' #' || n,
      (ARRAY['url','url','url','url','vcard','coupon','event','pdf','feedback'])[1 + n % 9],
      'seed-placeholder',
      'test',
      (CASE WHEN n % 17 = 0 THEN 'REVOKED' WHEN n % 23 = 0 THEN 'EXPIRED' ELSE 'ACTIVE' END)::"QRCodeStatus",
      'seed',
      now() - (n % 365) * interval '1 day' - (n % 1440) * interval '1 minute',
      now()
    FROM generate_series(1, ${opts.count}) AS n`;
}
