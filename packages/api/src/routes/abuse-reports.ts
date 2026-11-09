import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { z } from 'zod';
import { rateLimitPublic, rateLimitReport } from '../middleware/rateLimit.js';
import { config } from '../lib/config.js';
import { hashIp } from '../lib/ip-hash.js';
import { checkTurnstile } from '../lib/turnstile.js';
import { abuseReportSchema, submitAbuseReport } from '../services/abuse-report.js';
import {
  renderReportForm,
  renderReportProblem,
  renderReportReceived,
  reportPageCsp,
  type ReportPage,
} from '../renderers/report-page.js';

/**
 * "Report this code" (registered under /v):
 *   GET  /:token/report  the form (rendered for any token)
 *   POST /:token/report  JSON or form-encoded; 202 whether or not the token
 *                        exists, so the endpoint does not reveal which codes
 *                        exist. Per-network rate limit that fails closed, and
 *                        Turnstile when configured.
 */

const tokenParams = z.object({ token: z.string().min(1).max(64) });

const RECEIVED = { status: 'received' } as const;

function sendPage(request: FastifyRequest, reply: FastifyReply, page: ReportPage, statusCode = 200) {
  (request as FastifyRequest & { cspOverride?: string }).cspOverride = reportPageCsp(
    page.nonce,
    config.turnstile.enabled,
  );
  return reply.status(statusCode).type('text/html').send(page.html);
}

function isFormPost(request: FastifyRequest): boolean {
  return (request.headers['content-type'] ?? '').startsWith('application/x-www-form-urlencoded');
}

export default async function abuseReportRoutes(fastify: FastifyInstance): Promise<void> {
  fastify.get('/:token/report', { config: { rateLimit: rateLimitPublic } }, async (request, reply) => {
    const params = tokenParams.safeParse(request.params);
    if (!params.success) return reply.status(404).send({ statusCode: 404, error: 'Not Found' });
    const siteKey = config.turnstile.enabled ? config.turnstile.siteKey : null;
    return sendPage(request, reply, renderReportForm({ token: params.data.token, siteKey }));
  });

  fastify.post('/:token/report', { config: { rateLimit: rateLimitReport } }, async (request, reply) => {
    const params = tokenParams.safeParse(request.params);
    if (!params.success) return reply.status(404).send({ statusCode: 404, error: 'Not Found' });
    const { token } = params.data;
    const html = isFormPost(request);
    const raw = (request.body ?? {}) as Record<string, unknown>;

    const parsed = abuseReportSchema.safeParse(raw);
    if (!parsed.success) {
      const message = 'Choose a reason, keep the details under 500 characters, and check the email address.';
      if (!html) {
        return reply.status(400).send({ statusCode: 400, error: 'Bad Request', message, issues: parsed.error.issues });
      }
      const siteKey = config.turnstile.enabled ? config.turnstile.siteKey : null;
      const values = {
        reason: typeof raw.reason === 'string' ? raw.reason : undefined,
        comment: typeof raw.comment === 'string' ? raw.comment.slice(0, 500) : undefined,
        reporterEmail: typeof raw.reporterEmail === 'string' ? raw.reporterEmail.slice(0, 254) : undefined,
      };
      return sendPage(request, reply, renderReportForm({ token, siteKey, error: message, values }), 400);
    }
    const input = parsed.data;

    if (config.turnstile.enabled) {
      const captcha = input.turnstileToken ?? input['cf-turnstile-response'];
      const refused = await checkTurnstile(captcha, request.ip, request.log, 'abuse_report');
      if (refused) {
        return html
          ? sendPage(request, reply, renderReportProblem(token, refused.message), refused.statusCode)
          : reply.status(refused.statusCode).send(refused);
      }
    }

    await submitAbuseReport(fastify.prisma, request.log, token, input, hashIp(request.ip));

    return html
      ? sendPage(request, reply, renderReportReceived(token), 202)
      : reply.status(202).send(RECEIVED);
  });
}
