import { createHash } from 'node:crypto';
import type { FastifyBaseLogger } from 'fastify';
import type { PrismaClient } from '@prisma/client';
import { contentLinkUrls, getContentType, isLinkedContentType } from '@qrauth/shared';
import { cacheDel } from '../lib/cache.js';
import { config } from '../lib/config.js';
import { sendLinkFlaggedEmail } from '../lib/email.js';
import { normalizeDestination, type WebRiskVerdict } from '../lib/web-risk.js';
import { destinationFlaggedBody, screenDestination } from './destination-screening.js';

/**
 * Web Risk screening of the links inside smart link and link list codes.
 *
 * - Create and content edits screen every link: one listed link refuses the
 *   request (422 DestinationFlagged, naming the link). Unlike a URL code,
 *   a link that cannot be screened also refuses the request (503 with
 *   Retry-After): a VERIFIED smart link continues to its link on its own,
 *   so no link goes live unscreened.
 * - The re-check and the daily scan (workers/web-risk.ts) record a listed
 *   link in qr_code_link_flags. The verify page hides that entry with a
 *   warning; the rest of the code keeps working. The first flag of a link
 *   emails the org owners and the abuse inbox.
 * - An edit drops the flags of links it removes and of links it screens
 *   clean; a flag whose link is kept but not screened (Web Risk not
 *   configured) stays.
 */

/** SHA-256 hex of the normalized URL: the key of a link flag. */
export function linkUrlHash(url: string): string {
  return createHash('sha256').update(normalizeDestination(url) ?? url).digest('hex');
}

export interface LinkScreening {
  /** Links Web Risk lists, in content order (one entry per distinct URL). */
  flagged: Array<{ url: string; threatTypes: string[] }>;
  /** Hashes of the links screened clean. */
  cleanHashes: Set<string>;
  /** At least one link could not be screened. */
  unavailable: boolean;
  /** At least one link got no verdict because Web Risk is not configured. */
  unscreened: boolean;
}

/** Web Risk lookups in flight at once for one request. */
export const LINK_SCREENING_CONCURRENCY = 4;

/**
 * Screens each distinct link once, at most LINK_SCREENING_CONCURRENCY at a
 * time (each lookup is cached). Stops starting new lookups at the first
 * flagged or unavailable verdict, since either refuses the request: the
 * worst case is then one lookup timeout per in-flight slot, not one per link.
 */
export async function screenLinks(
  urls: string[],
  lookup: (url: string) => Promise<WebRiskVerdict> = screenDestination,
): Promise<LinkScreening> {
  const distinct = new Map<string, string>();
  for (const url of urls) {
    const hash = linkUrlHash(url);
    if (!distinct.has(hash)) distinct.set(hash, url);
  }
  const queue = [...distinct];
  const verdicts: Array<{ hash: string; url: string; verdict: WebRiskVerdict }> = [];
  let refused = false;
  const worker = async () => {
    for (let next = queue.shift(); next && !refused; next = queue.shift()) {
      const [hash, url] = next;
      const verdict = await lookup(url);
      verdicts.push({ hash, url, verdict });
      if (verdict.verdict === 'flagged' || verdict.verdict === 'unavailable') refused = true;
    }
  };
  await Promise.all(Array.from({ length: Math.min(LINK_SCREENING_CONCURRENCY, queue.length) }, worker));
  // Report in content order (the first listed link screened is named).
  const order = [...distinct.keys()];
  verdicts.sort((a, b) => order.indexOf(a.hash) - order.indexOf(b.hash));
  const result: LinkScreening = { flagged: [], cleanHashes: new Set(), unavailable: false, unscreened: false };
  for (const { hash, url, verdict } of verdicts) {
    if (verdict.verdict === 'flagged') result.flagged.push({ url, threatTypes: verdict.threatTypes });
    else if (verdict.verdict === 'clean') result.cleanHashes.add(hash);
    else if (verdict.verdict === 'unavailable') result.unavailable = true;
    else if (verdict.verdict === 'skipped') result.unscreened = true;
  }
  return result;
}

/** 422 body for content with a listed link: the URL code body plus the link. */
export function linkFlaggedBody(flagged: { url: string; threatTypes: string[] }) {
  return {
    ...destinationFlaggedBody(flagged.threatTypes),
    message: `A link in this content (${flagged.url}) is listed as dangerous by Google Web Risk and cannot be used.`,
    url: flagged.url,
  };
}

/** Seconds a client should wait before retrying when links cannot be screened. */
export const SCREENING_RETRY_AFTER_SECONDS = 30;

export type ContentCheck =
  /** `content` is what to store: schema-parsed (URLs normalized) for smart link and link list, as sent otherwise. */
  | { ok: true; urls: string[]; screening: LinkScreening | null; content: unknown }
  | { ok: false; status: 400 | 422 | 503; body: Record<string, unknown>; /** Worth retrying shortly (Retry-After). */ retryable?: boolean };

/**
 * Validates non-URL content against its type's schema and, for smart link
 * and link list, screens every link. Run before anything is signed or
 * stored, on create and on a content edit.
 */
export async function checkContent(
  contentType: string,
  content: unknown,
  allowUnscreened: boolean = config.webRisk.allowUnscreenedLinks,
): Promise<ContentCheck> {
  const def = getContentType(contentType);
  if (!def) {
    return { ok: false, status: 400, body: { statusCode: 400, error: 'Bad Request', message: `Unknown content type: ${contentType}` } };
  }
  if (contentType === 'url') return { ok: true, urls: [], screening: null, content };
  // Other types without content are stored without it, as before.
  if (!content && !isLinkedContentType(contentType)) return { ok: true, urls: [], screening: null, content };

  const parsed = def.schema.safeParse(content);
  if (!parsed.success) {
    return {
      ok: false,
      status: 400,
      body: {
        statusCode: 400,
        error: 'Bad Request',
        message: `Invalid content for type ${contentType}: ${parsed.error.issues.map((i) => `${i.path.join('.') || 'content'}: ${i.message}`).join('; ')}`,
      },
    };
  }
  if (!isLinkedContentType(contentType)) return { ok: true, urls: [], screening: null, content };

  // Store what the schema parsed: every link in its normalized form.
  const normalized = parsed.data;
  const urls = contentLinkUrls(contentType, normalized);
  const screening = await screenLinks(urls);
  if (screening.flagged.length > 0) {
    return { ok: false, status: 422, body: linkFlaggedBody(screening.flagged[0]) };
  }
  // Web Risk not configured (development and test only; production refuses
  // to start without it): links are saved unscreened only when allowed.
  if (screening.unscreened && !allowUnscreened) {
    return {
      ok: false,
      status: 503,
      body: {
        statusCode: 503,
        error: 'Service Unavailable',
        message: 'Link screening is not configured on this server, so smart link and link list codes cannot be saved.',
      },
    };
  }
  if (screening.unavailable) {
    return {
      ok: false,
      status: 503,
      body: {
        statusCode: 503,
        error: 'Service Unavailable',
        message: 'The links cannot be screened right now. Try again shortly; nothing was changed.',
      },
      retryable: true,
    };
  }
  return { ok: true, urls, screening, content: normalized };
}

type FlagDb = Pick<PrismaClient, 'qRCode' | 'qRCodeLinkFlag' | 'membership'>;

/**
 * After a content edit: keep only the flags of links that are still in the
 * content and were not screened clean this time.
 */
export async function pruneLinkFlags(
  db: Pick<PrismaClient, 'qRCodeLinkFlag'>,
  qrCodeId: string,
  urls: string[],
  screening: LinkScreening | null,
): Promise<void> {
  const keep = urls.map(linkUrlHash).filter((hash) => !screening?.cleanHashes.has(hash));
  await db.qRCodeLinkFlag.deleteMany({ where: { qrCodeId, urlHash: { notIn: keep } } });
}

/**
 * Records a listed link of a code. Only the first flag of a link emails
 * anyone. Returns true when this call created the flag.
 */
export async function flagContentLink(
  db: FlagDb,
  log: FastifyBaseLogger,
  code: { id: string; token: string; organizationId: string },
  url: string,
  threatTypes: string[],
): Promise<boolean> {
  const { count } = await db.qRCodeLinkFlag.createMany({
    data: [{ qrCodeId: code.id, urlHash: linkUrlHash(url), url, threatTypes: threatTypes.join(',').slice(0, 255) }],
    skipDuplicates: true,
  });
  if (count === 0) return false;

  try {
    await cacheDel(`verify:${code.token}`);
  } catch {
    // the verify path reads flags from the database
  }

  const [org, owners] = await Promise.all([
    db.qRCode.findUnique({ where: { id: code.id }, select: { organization: { select: { name: true } } } }),
    db.membership.findMany({
      where: { organizationId: code.organizationId, role: 'OWNER' },
      select: { user: { select: { email: true } } },
    }),
  ]);
  const recipients = new Set(owners.map((o) => o.user.email).filter(Boolean));
  if (config.abuse.notifyEmail) recipients.add(config.abuse.notifyEmail);
  const flag = { token: code.token, organizationName: org?.organization.name ?? '', url, threatTypes };
  await Promise.all(
    [...recipients].map((to) =>
      sendLinkFlaggedEmail(to, flag).catch((err: unknown) =>
        log.warn({ err, token: code.token }, 'link-screening: flag email not sent'),
      ),
    ),
  );
  log.warn({ event: 'qr.link_flagged', token: code.token, threatTypes }, 'QR content link flagged by Web Risk');
  return true;
}

/** Hashes of a code's flagged links (verify page). */
export async function flaggedLinkHashes(
  db: Pick<PrismaClient, 'qRCodeLinkFlag'>,
  qrCodeId: string,
): Promise<Set<string>> {
  const rows = await db.qRCodeLinkFlag.findMany({ where: { qrCodeId }, select: { urlHash: true } });
  return new Set(rows.map((r) => r.urlHash));
}
