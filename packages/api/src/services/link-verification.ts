import type { PrismaClient } from '@prisma/client';
import { appLinkContentSchema, contentLinkUrls, isLinkedContentType } from '@qrauth/shared';
import type { LinkState } from '../renderers/index.js';
import type { DomainCheck, DomainService } from './domain.js';
import { flaggedLinkHashes, linkUrlHash } from './link-screening.js';
import { compareLookalikeWarnings } from './lookalike.js';
import { detectPlatform, PLATFORM_URL_FIELD, type Platform } from './platform.js';
import { resolveAppLinkScanMode, type ScanMode } from './scan-mode.js';
import type { TrustState } from './trust-state.js';

/**
 * Verify-page checks for the links of smart link and link list codes.
 *
 * - Web Risk flags (qr_code_link_flags): the entry is hidden on the page.
 * - The lookalike check runs on every link, as it does on a URL code's
 *   destination; one lookalike link makes the code UNTRUSTED, and the page
 *   marks that entry.
 */

export interface LinkAssessment {
  states: Record<string, LinkState>;
  /** Combined result in the shape of a single-URL check (first lookalike link first). */
  domainCheck: DomainCheck;
}

type LinkedCode = { id: string; organizationId: string; contentType: string | null; content: unknown };

export async function assessContentLinks(
  prisma: Pick<PrismaClient, 'qRCodeLinkFlag'>,
  domainService: Pick<DomainService, 'checkUrlsAgainstVerifiedDomains'>,
  code: LinkedCode,
): Promise<LinkAssessment | null> {
  if (!isLinkedContentType(code.contentType)) return null;
  const urls = contentLinkUrls(code.contentType, code.content);
  const [flagged, checks] = await Promise.all([
    flaggedLinkHashes(prisma, code.id),
    domainService.checkUrlsAgainstVerifiedDomains(urls, code.organizationId),
  ]);

  const states: Record<string, LinkState> = {};
  const warnings: DomainCheck['warnings'] = [];
  let isSuspicious = false;
  for (const url of urls) {
    const check = checks.get(url);
    const top = check?.isSuspicious ? check.warnings[0] : undefined;
    states[url] = {
      flagged: flagged.has(linkUrlHash(url)),
      ...(top ? { lookalike: { similarTo: top.domain, verifiedOrg: top.verifiedOrgName, reason: top.reason, scripts: top.scripts, source: top.source } } : {}),
    };
    if (check?.isSuspicious) {
      isSuspicious = true;
      warnings.push(...check.warnings);
    }
  }
  warnings.sort(compareLookalikeWarnings);
  return { states, domainCheck: { isSuspicious, warnings } };
}

export interface AppLinkTarget {
  platform: Platform;
  scanMode: ScanMode;
  /** Set when scanMode is FLASH: the platform's URL. */
  continueUrl?: string;
}

/**
 * Smart link: the scanner's platform, and whether this scan continues to its
 * URL. The stored content is checked against the schema first; content that
 * does not match it never continues (PAGE).
 */
export function appLinkTarget(input: {
  userAgent: string | undefined;
  content: unknown;
  states: Record<string, LinkState>;
  configured: string | null | undefined;
  trustState: TrustState;
  locationBound: boolean;
}): AppLinkTarget {
  const platform = detectPlatform(input.userAgent);
  const parsed = appLinkContentSchema.safeParse(input.content);
  if (!parsed.success) return { platform, scanMode: 'PAGE' };
  // Link states are keyed by the parsed URL (contentLinkUrls), as here.
  const url = parsed.data[PLATFORM_URL_FIELD[platform]];
  const platformUrl = input.states[url]?.flagged ? null : url;
  const scanMode = resolveAppLinkScanMode({
    configured: input.configured,
    trustState: input.trustState,
    locationBound: input.locationBound,
    platformUrl,
  });
  return scanMode === 'FLASH' && platformUrl ? { platform, scanMode, continueUrl: platformUrl } : { platform, scanMode };
}
