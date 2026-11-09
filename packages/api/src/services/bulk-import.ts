import type { PrismaClient } from '@prisma/client';
import { MAX_FOLDERS_PER_ORG, MAX_TAGS_PER_ORG } from '@qrauth/shared';

import { mapLimit } from '../lib/map-limit.js';
import { checkRowFields, hasError, type BulkRowDraft, type RowIssue, type ValidatedRow } from './bulk-rows.js';
import { destinationFlaggedBody, screenDestination } from './destination-screening.js';
import type { DomainService } from './domain.js';
import { allowlistRefusal, readPolicy } from './org-policy.js';
import type { UsageService } from './usage.js';

/**
 * Validating bulk import rows (ADR-0008 D9) with the rules of a single
 * create: the URL rules of createQRCodeSchema (http(s), public host,
 * normalised), the organization's allowlist, Web Risk (one lookup per
 * distinct URL), lookalike detection (a warning, as on create), the QR quota
 * for the whole file, and the folder and tag limits. The dry run and the
 * import job run the same checks, so a row that became invalid after the dry
 * run (policy, quota, a newly listed URL) is skipped at commit.
 */

/** Concurrent Web Risk lookups in one validation. */
const WEB_RISK_CONCURRENCY = 8;

export interface ValidationDeps {
  prisma: PrismaClient;
  domainService: Pick<DomainService, 'checkUrlsAgainstVerifiedDomains'>;
  usage: Pick<UsageService, 'checkQuota' | 'current' | 'getLimits'>;
  /** The clock, for expiry dates in the past (tests pass a fixed one). */
  now?: () => Date;
  /** IANA time zone of date-only expiry dates (default UTC). */
  timeZone?: string;
}

/** Names the rows need that the organization does not have, in order of first use (case-insensitive). */
async function missingNames(
  prisma: PrismaClient,
  orgId: string,
  rows: readonly ValidatedRow[],
): Promise<{ folders: string[]; tags: string[]; folderCount: number; tagCount: number }> {
  const [folders, tags] = await Promise.all([
    prisma.qRFolder.findMany({ where: { organizationId: orgId }, select: { name: true } }),
    prisma.tag.findMany({ where: { organizationId: orgId }, select: { name: true } }),
  ]);
  const haveFolders = new Set(folders.map((f) => f.name.toLowerCase()));
  const haveTags = new Set(tags.map((t) => t.name.toLowerCase()));
  const newFolders = new Map<string, string>();
  const newTags = new Map<string, string>();
  for (const { draft, issues } of rows) {
    if (hasError(issues)) continue;
    if (draft.folder && !haveFolders.has(draft.folder.toLowerCase())) newFolders.set(draft.folder.toLowerCase(), newFolders.get(draft.folder.toLowerCase()) ?? draft.folder);
    for (const tag of draft.tags) if (!haveTags.has(tag.toLowerCase())) newTags.set(tag.toLowerCase(), newTags.get(tag.toLowerCase()) ?? tag);
  }
  return { folders: [...newFolders.values()], tags: [...newTags.values()], folderCount: folders.length, tagCount: tags.length };
}

/**
 * Validate drafts against the organization: field rules, allowlist, Web Risk,
 * lookalikes, duplicates in the file, folder and tag limits, and the quota.
 * Throws QuotaUnavailableError when the code count cannot be read.
 */
export async function validateDrafts(
  deps: ValidationDeps,
  orgId: string,
  plan: string,
  input: ReadonlyArray<{ draft: BulkRowDraft; issues?: readonly RowIssue[] }>,
): Promise<{ rows: ValidatedRow[]; newFolders: string[]; newTags: string[] }> {
  const now = deps.now?.() ?? new Date();
  const rows: ValidatedRow[] = input.map(({ draft, issues = [] }) => {
    const checked = checkRowFields(draft, now, deps.timeZone);
    return { draft: checked.draft, issues: [...issues, ...checked.issues], webRiskUnavailable: false };
  });

  // The allowlist, before Web Risk (as on single create).
  const policy = await readPolicy(deps.prisma, orgId);
  for (const row of rows) {
    if (hasError(row.issues)) continue;
    const refusal = allowlistRefusal(policy, [row.draft.url]);
    if (refusal) row.issues.push({ severity: 'error', code: 'destination-not-allowed', message: refusal.body.message });
  }

  // Web Risk and lookalikes: one lookup per distinct URL.
  const urls = [...new Set(rows.filter((r) => !hasError(r.issues)).map((r) => r.draft.url))];
  const verdicts = new Map(
    await mapLimit(urls, WEB_RISK_CONCURRENCY, async (url) => [url, await screenDestination(url)] as const),
  );
  const similar = await deps.domainService.checkUrlsAgainstVerifiedDomains(urls, orgId);
  const firstRowOf = new Map<string, number>();
  for (const row of rows) {
    if (hasError(row.issues)) continue;
    const verdict = verdicts.get(row.draft.url);
    if (verdict?.verdict === 'flagged') {
      row.issues.push({ severity: 'error', code: 'destination-flagged', message: destinationFlaggedBody(verdict.threatTypes).message });
      continue;
    }
    if (verdict?.verdict === 'unavailable') {
      row.webRiskUnavailable = true;
      row.issues.push({ severity: 'warning', code: 'web-risk-unavailable', message: 'Web Risk did not answer; the code is checked again right after it is created.' });
    }
    const check = similar.get(row.draft.url);
    const top = check?.isSuspicious ? check.warnings[0] : undefined;
    if (top) {
      row.issues.push({
        severity: 'warning',
        code: 'lookalike',
        message: `The destination looks like ${top.domain}${top.verifiedOrgName ? ` (${top.verifiedOrgName})` : ''}; it is recorded as a fraud incident when created.`,
      });
    }
    const first = firstRowOf.get(row.draft.url);
    if (first === undefined) firstRowOf.set(row.draft.url, row.draft.row);
    else row.issues.push({ severity: 'warning', code: 'duplicate-url', message: `Same URL as row ${first}.` });
  }

  // Folder and tag limits: names beyond the organization's room are refused.
  const missing = await missingNames(deps.prisma, orgId, rows);
  const allowedFolders = new Set(missing.folders.slice(0, Math.max(0, MAX_FOLDERS_PER_ORG - missing.folderCount)).map((n) => n.toLowerCase()));
  const allowedTags = new Set(missing.tags.slice(0, Math.max(0, MAX_TAGS_PER_ORG - missing.tagCount)).map((n) => n.toLowerCase()));
  const newFolderSet = new Set(missing.folders.map((n) => n.toLowerCase()));
  const newTagSet = new Set(missing.tags.map((n) => n.toLowerCase()));
  for (const row of rows) {
    if (hasError(row.issues)) continue;
    const folder = row.draft.folder?.toLowerCase();
    if (folder && newFolderSet.has(folder) && !allowedFolders.has(folder)) {
      row.issues.push({ severity: 'error', code: 'folder-limit', message: `Creating folder "${row.draft.folder}" would exceed ${MAX_FOLDERS_PER_ORG} folders.` });
    }
    const tag = row.draft.tags.find((t) => newTagSet.has(t.toLowerCase()) && !allowedTags.has(t.toLowerCase()));
    if (tag) row.issues.push({ severity: 'error', code: 'tag-limit', message: `Creating tag "${tag}" would exceed ${MAX_TAGS_PER_ORG} tags.` });
  }

  // The quota, for the whole file: rows past the remaining room are refused.
  const limit = deps.usage.getLimits(plan).qrcodes;
  if (limit !== 'unlimited') {
    let room = Math.max(0, limit - (await deps.usage.current(orgId, 'qrcodes')));
    for (const row of rows) {
      if (hasError(row.issues)) continue;
      if (room > 0) {
        room--;
        continue;
      }
      row.issues.push({ severity: 'error', code: 'quota-exceeded', message: `Your plan allows ${limit} QR codes; this row is past the limit.` });
    }
  }

  const used = rows.filter((r) => !hasError(r.issues));
  const usedFolders = new Set(used.map((r) => r.draft.folder?.toLowerCase()).filter(Boolean));
  const usedTags = new Set(used.flatMap((r) => r.draft.tags.map((t) => t.toLowerCase())));
  return {
    rows,
    newFolders: missing.folders.filter((n) => usedFolders.has(n.toLowerCase())),
    newTags: missing.tags.filter((n) => usedTags.has(n.toLowerCase())),
  };
}

