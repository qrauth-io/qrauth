import type { FastifyBaseLogger } from 'fastify';
import type { PrismaClient } from '@prisma/client';
import { z } from 'zod';
import { redis } from '../lib/cache.js';
import { config } from '../lib/config.js';
import { sendAbuseReportEmail } from '../lib/email.js';

/** Reasons offered on the report form (lowercase on the wire). */
export const ABUSE_REASONS = ['phishing', 'malware', 'impersonation', 'spam', 'other'] as const;

const optionalText = (max: number) =>
  z
    .string()
    .trim()
    .max(max)
    .optional()
    .transform((v) => (v ? v : undefined));

/** Body of POST /v/:token/report, JSON or form-encoded. Unknown fields are ignored. */
export const abuseReportSchema = z.object({
  reason: z.enum(ABUSE_REASONS),
  comment: optionalText(500),
  reporterEmail: z
    .string()
    .trim()
    .max(254)
    .optional()
    .transform((v) => (v ? v : undefined))
    .refine((v) => v === undefined || z.string().email().safeParse(v).success, {
      message: 'reporterEmail must be an email address',
    }),
  turnstileToken: optionalText(2048),
  // The Turnstile widget's own form field.
  'cf-turnstile-response': optionalText(2048),
});

export type AbuseReportInput = z.infer<typeof abuseReportSchema>;

/** At most one notification email per QR code per hour. */
const NOTIFY_THROTTLE_SECONDS = 60 * 60;

type AbuseDb = Pick<PrismaClient, 'qRCode' | 'abuseReport'>;

/**
 * Stores a report for an existing code and notifies the abuse inbox.
 * Returns false for an unknown token: nothing is stored, and the caller
 * answers exactly as for a stored report, so existence is not revealed.
 */
export async function submitAbuseReport(
  prisma: AbuseDb,
  log: FastifyBaseLogger,
  token: string,
  input: AbuseReportInput,
  ipHash: string,
): Promise<boolean> {
  const qrCode = await prisma.qRCode.findUnique({
    where: { token },
    select: { token: true, organizationId: true, destinationUrl: true, organization: { select: { name: true } } },
  });
  if (!qrCode) return false;

  const report = await prisma.abuseReport.create({
    data: {
      token: qrCode.token,
      organizationId: qrCode.organizationId,
      reason: input.reason.toUpperCase() as Uppercase<(typeof ABUSE_REASONS)[number]>,
      comment: input.comment ?? null,
      reporterEmail: input.reporterEmail ?? null,
      ipHash,
    },
  });

  void notifyAbuseInbox(log, {
    reportId: report.id,
    token: qrCode.token,
    reason: report.reason,
    comment: report.comment,
    reporterEmail: report.reporterEmail,
    organizationId: qrCode.organizationId,
    organizationName: qrCode.organization.name,
    destinationUrl: qrCode.destinationUrl,
  });
  return true;
}

async function notifyAbuseInbox(
  log: FastifyBaseLogger,
  report: Parameters<typeof sendAbuseReportEmail>[1],
): Promise<void> {
  const to = config.abuse.notifyEmail;
  if (!to) return;
  try {
    // SET NX: only the first report for this token in the window sends mail.
    const first = await redis.set(`qrauth:abuse-notify:${report.token}`, '1', 'EX', NOTIFY_THROTTLE_SECONDS, 'NX');
    if (first !== 'OK') return;
    await sendAbuseReportEmail(to, report);
  } catch (err) {
    log.warn({ err, reportId: report.reportId }, 'abuse-report: notification email not sent');
  }
}
