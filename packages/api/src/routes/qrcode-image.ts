import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { isIssuerVerified } from '@qrauth/shared';
import { z } from 'zod';

import { exportGateMessage, gateRefusalBody } from '../config/plan-limits.js';
import { authorize } from '../middleware/authorize.js';
import { rateLimitRender } from '../middleware/rateLimit.js';
import { zodValidator } from '../middleware/validate.js';
import { notFoundError } from '../lib/responses.js';
import { isSemaphoreBusy, SemaphoreAbortedError } from '../lib/semaphore.js';
import { LogoLibrary } from '../services/logo-library.js';
import {
  inchesToMm,
  PDF_MARGIN_MM_MAX,
  PDF_MARGIN_MM_MIN,
  PRINT_DPI_DEFAULT,
  PRINT_DPI_MAX,
  PRINT_DPI_MIN,
  PRINT_SIZE_IN_MAX,
  PRINT_SIZE_IN_MIN,
  PRINT_SIZE_MM_DEFAULT,
  PRINT_SIZE_MM_MAX,
  PRINT_SIZE_MM_MIN,
  PrintSizeError,
  roundMm,
  type PrintSize,
} from '../services/print-size.js';
import {
  effectivePx,
  exportEtag,
  IMAGE_PX_MAX,
  IMAGE_PX_MIN,
  loadLogoBytes,
  QR_IMAGE_URL_PX,
  RENDER_RETRY_AFTER_SECONDS,
  renderExport,
  styleForRender,
  type ExportFormat,
  type ExportOptions,
} from '../services/qr-render.js';

/**
 * GET /api/v1/qrcodes/:token/image — the code drawn with its stored style
 * (ADR-0005 D7). SVG or PNG at screen sizes (`px`), and print sizes (PR 6):
 * PNG at `size_mm` (or `size_in`) and `dpi`, a vector PDF at `size_mm` with
 * an optional `margin_mm`, and SVG at `size_mm` (width and height in mm).
 * Print PNG and PDF need a paid plan (D9); SVG and PNG up to 1024 px are on
 * every plan.
 *
 * Renders whatever the code's state (revoked, expired, flagged destination,
 * suspended organization): the image encodes only the verification URL, and
 * every one of those decisions is made when the code is scanned.
 *
 * The badge template's mark follows the organization's issuer status at
 * render time ("Verified by QRAuth" or "Signed with QRAuth", ADR-0005 D9,
 * 2026-10-30); the ETag includes it, so a change in verification is a new
 * image.
 */

const paramsSchema = z.object({ token: z.string().min(1).max(64) }).strict();

/** Finite decimal in [min, max]; `1e3`, `Infinity` and `NaN` included only as their value allows. */
function decimal(min: number, max: number, unit: string): z.ZodType<number | undefined> {
  return z.coerce
    .number()
    .refine(Number.isFinite, 'must be a number')
    .refine((v) => v >= min && v <= max, `must be from ${min} to ${max} ${unit}`)
    .optional();
}

const querySchema = z
  .object({
    format: z.enum(['svg', 'png', 'pdf']).default('png'),
    px: z.coerce.number().int().min(IMAGE_PX_MIN).max(IMAGE_PX_MAX).optional(),
    size_mm: decimal(PRINT_SIZE_MM_MIN, PRINT_SIZE_MM_MAX, 'mm'),
    size_in: decimal(PRINT_SIZE_IN_MIN, PRINT_SIZE_IN_MAX, 'in'),
    dpi: z.coerce.number().int().min(PRINT_DPI_MIN).max(PRINT_DPI_MAX).optional(),
    margin_mm: decimal(PDF_MARGIN_MM_MIN, PDF_MARGIN_MM_MAX, 'mm'),
    download: z.enum(['0', '1']).optional(),
  })
  .strict()
  .superRefine((q, ctx) => {
    const issue = (path: string, message: string): void => {
      ctx.addIssue({ code: 'custom', path: [path], message });
    };
    const hasPrintSize = q.size_mm !== undefined || q.size_in !== undefined || q.dpi !== undefined;
    if (q.size_mm !== undefined && q.size_in !== undefined) issue('size_in', 'size_mm and size_in are mutually exclusive');
    if (q.px !== undefined && hasPrintSize) issue('px', 'px (screen size) and size_mm, size_in or dpi (print size) are mutually exclusive');
    if (q.format === 'pdf' && q.px !== undefined) issue('px', 'PDF is sized with size_mm or size_in, not px');
    if (q.format !== 'png' && q.dpi !== undefined) issue('dpi', 'dpi applies to PNG only');
    if (q.format !== 'pdf' && q.margin_mm !== undefined) issue('margin_mm', 'margin_mm applies to PDF only');
  });

type ImageQuery = z.infer<typeof querySchema>;

/** The print size a query asks for, normalised to 0.1 mm, or undefined for a screen size. */
function printSizeOf(query: ImageQuery): PrintSize | undefined {
  const isPrint = query.format === 'pdf' || query.size_mm !== undefined || query.size_in !== undefined || query.dpi !== undefined;
  if (!isPrint) return undefined;
  const sizeMm =
    query.size_mm !== undefined ? roundMm(query.size_mm) : query.size_in !== undefined ? inchesToMm(query.size_in) : PRINT_SIZE_MM_DEFAULT;
  return {
    sizeMm,
    ...(query.format === 'png' ? { dpi: query.dpi ?? PRINT_DPI_DEFAULT } : {}),
    ...(query.format === 'pdf' ? { marginMm: roundMm(query.margin_mm ?? 0) } : {}),
  };
}

/**
 * An SVG opened directly from the API origin can run nothing: no script, no
 * external loads, sandboxed, and it cannot be framed (D7). Only `data:` images, which is all the
 * renderer emits.
 */
export const SVG_EXPORT_CSP = "default-src 'none'; img-src data:; style-src 'unsafe-inline'; sandbox; frame-ancestors 'none'";

const CACHE_CONTROL = 'private, no-cache';

/** The width actually rendered, in px (raised to the minimum module size when needed). */
export const IMAGE_PX_HEADER = 'X-QRAuth-Image-Px';

const EXTENSIONS: Readonly<Record<ExportFormat, string>> = { svg: 'svg', png: 'png', pdf: 'pdf' };

/**
 * Size part of the download name: `-{px}px` for screen sizes,
 * `-{size}mm` for a print SVG or PDF and `-{size}mm-{dpi}dpi` for a print
 * PNG (a size in inches is named by its mm value).
 */
function filenameSize(opts: ExportOptions): string {
  if (opts.print) {
    const dpi = opts.format === 'png' && opts.print.dpi !== undefined ? `-${opts.print.dpi}dpi` : '';
    return `-${opts.print.sizeMm}mm${dpi}`;
  }
  return opts.px !== undefined ? `-${opts.px}px` : '';
}

function contentDisposition(token: string, opts: ExportOptions, download: boolean): string {
  const safeToken = token.replace(/[^A-Za-z0-9_-]/g, '');
  const filename = `qrauth-${safeToken}${filenameSize(opts)}.${EXTENSIONS[opts.format]}`;
  return `${download ? 'attachment' : 'inline'}; filename="${filename}"`;
}

/** 400 (above the raster caps, the message states the maximum) or 422 (modules too small, it states the minimum). */
function sendPrintSizeError(reply: FastifyReply, err: PrintSizeError): FastifyReply {
  return reply.status(err.status).send({
    statusCode: err.status,
    error: err.status === 400 ? 'Bad Request' : 'Unprocessable Entity',
    code: err.code,
    message: err.message,
  });
}

/** If-None-Match matches `etag`: `*`, or any listed tag (weak comparison, RFC 9110 13.1.2). */
function matchesIfNoneMatch(header: string | undefined, etag: string): boolean {
  if (!header) return false;
  if (header.trim() === '*') return true;
  return header.split(',').some((tag) => tag.trim().replace(/^W\//, '') === etag);
}

export default async function qrCodeImageRoutes(fastify: FastifyInstance): Promise<void> {
  const { authenticate } = fastify;
  const logos = new LogoLibrary(fastify.prisma);

  fastify.get('/:token/image', {
    config: { rateLimit: rateLimitRender },
    preHandler: [authenticate, authorize('OWNER', 'ADMIN', 'MANAGER', 'MEMBER', 'VIEWER')],
    preValidation: zodValidator({ params: paramsSchema, querystring: querySchema }),
  }, async (request: FastifyRequest, reply: FastifyReply) => {
    const { token } = request.params as { token: string };
    const query = request.query as ImageQuery;

    const qrCode = await fastify.prisma.qRCode.findUnique({
      where: { token },
      select: { token: true, organizationId: true, style: true },
    });
    // Another organization's code answers exactly like a missing one, so
    // tokens cannot be probed for existence through this route.
    if (!qrCode || qrCode.organizationId !== request.user!.orgId) {
      return reply.status(404).send(notFoundError('QR code', token));
    }

    const org = await fastify.prisma.organization.findUnique({
      where: { id: qrCode.organizationId },
      select: { domainVerified: true, kycStatus: true, plan: true },
    });
    const print = printSizeOf(query);
    // Print PNG and PDF are paid (D9); refused before anything is rendered.
    const gate = exportGateMessage(org?.plan ?? 'FREE', { format: query.format, isPrintSize: print !== undefined });
    if (gate) return reply.status(403).send(gateRefusalBody({ message: gate }));

    const renderable = {
      token: qrCode.token,
      issuerVerified: isIssuerVerified({ domainVerified: org?.domainVerified === true, kycStatus: org?.kycStatus ?? 'PENDING' }),
    };

    const style = styleForRender(qrCode.style);
    // A customer logo is the organization's own (its stored style keeps
    // rendering after a downgrade, D9); a missing one leaves its area empty.
    const logoBytes = await loadLogoBytes(style, qrCode.organizationId, logos);
    const requested: ExportOptions = print
      ? { format: query.format, print }
      : { format: query.format, px: query.format === 'png' ? (query.px ?? QR_IMAGE_URL_PX) : query.px };
    // A screen width below the minimum module size is raised to it; the
    // ETag, the filename and X-QRAuth-Image-Px describe the image actually
    // sent. A print size is never changed: one the code cannot be printed
    // at is refused.
    let px: number | undefined;
    try {
      px = effectivePx(renderable, style, requested);
    } catch (err) {
      if (err instanceof PrintSizeError) return sendPrintSizeError(reply, err);
      throw err;
    }
    const opts: ExportOptions = print ? requested : { format: requested.format, px };
    const etag = exportEtag(renderable, style, logoBytes, opts);

    reply
      .header('ETag', etag)
      .header('Cache-Control', CACHE_CONTROL)
      .header('Content-Disposition', contentDisposition(qrCode.token, opts, query.download === '1'));
    if (px !== undefined) reply.header(IMAGE_PX_HEADER, String(px));

    if (matchesIfNoneMatch(request.headers['if-none-match'], etag)) {
      return reply.status(304).send();
    }

    // A client that disconnects while its PNG or PDF waits for a slot leaves
    // the queue without being rendered.
    const disconnected = new AbortController();
    const onClose = (): void => {
      if (!reply.raw.writableFinished) disconnected.abort();
    };
    reply.raw.once('close', onClose);

    let result;
    try {
      result = await renderExport(renderable, style, logoBytes, opts, { lane: 'export', signal: disconnected.signal });
    } catch (err) {
      if (!isSemaphoreBusy(err) && !(err instanceof SemaphoreAbortedError)) throw err;
      if (err instanceof SemaphoreAbortedError) {
        // Nobody reads this reply: the client is gone and nothing was rendered.
        request.log.info({ token }, 'image export dropped: client disconnected while queued');
      }
      reply.removeHeader('ETag');
      reply.removeHeader('Content-Disposition');
      reply.removeHeader(IMAGE_PX_HEADER);
      return reply
        .status(503)
        .header('Retry-After', String(RENDER_RETRY_AFTER_SECONDS))
        .header('Cache-Control', 'no-store')
        .send({ statusCode: 503, error: 'Service Unavailable', message: 'Image rendering is busy; retry shortly.' });
    } finally {
      reply.raw.removeListener('close', onClose);
    }
    if (opts.format === 'svg') {
      (request as unknown as { cspOverride?: string }).cspOverride = SVG_EXPORT_CSP;
    }
    return reply.type(result.contentType).header('X-Content-Type-Options', 'nosniff').send(result.body);
  });
}
