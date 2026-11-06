import { Prisma, type PrismaClient } from '@prisma/client';
import { createHash, randomBytes } from 'node:crypto';
import { registrableDomain } from '../lib/public-suffix.js';
import {
  BRAND_KEYWORD_MIN_LENGTH,
  BRAND_TOKEN_MIN_LENGTH,
  brandWithKeyword,
  embeddedName,
  hasCredentialKeyword,
  hostTokens,
  protectedNameLabels,
  protectedNameTokens,
  tokenSkeleton,
} from './lookalike-words.js';
import {
  compareLookalikeWarnings,
  curatedBrands,
  hostSkeleton,
  coveredBy,
  isSameOrSubdomain,
  mixedScriptLabel,
  normalizeHost,
  normalizeUrlHost,
  parentDomains,
  registrableLabel,
  stripMarks,
  SUSPICIOUS_SIMILARITY,
  unicodeLabel,
} from './lookalike.js';

// ---------------------------------------------------------------------------
// Homoglyph map — characters that look similar
// ---------------------------------------------------------------------------
const HOMOGLYPHS: Record<string, string[]> = {
  '0': ['o', 'O'],
  'o': ['0', 'O'],
  'O': ['0', 'o'],
  '1': ['l', 'I', 'i'],
  'l': ['1', 'I', 'i'],
  'I': ['1', 'l', 'i'],
  'i': ['1', 'l', 'I'],
  'rn': ['m'],
  'm': ['rn'],
  'vv': ['w'],
  'w': ['vv'],
  'cl': ['d'],
  'd': ['cl'],
  'nn': ['m'],
};

/** Why a destination was flagged (`similar_to` / `reason` in API responses). */
export type LookalikeReason =
  | 'confusable' // UTS #39 skeleton equal to a protected domain
  | 'mixed_script' // a label below UTS #39 Highly Restrictive
  | 'brand_name' // a strict brand's exact name on a TLD it does not list
  | 'homoglyph_match'
  | 'one_char_difference'
  | 'typosquatting'
  | 'substring_match'
  | 'hyphen_variation'
  | 'high_similarity';

/** HOMOGLYPHS as compiled replacements, in the original iteration order. */
const HOMOGLYPH_REPLACEMENTS: Array<[RegExp, string]> = Object.entries(HOMOGLYPHS).flatMap(([char, replacements]) =>
  replacements.map((replacement): [RegExp, string] => [new RegExp(replacement.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g'), char]),
);

export interface DomainCheck {
  warnings: Array<{
    /** The protected domain it looks like; for mixed_script, the host itself. */
    domain: string;
    /** Verified organization or protected brand name; empty for mixed_script. */
    verifiedOrgName: string;
    similarity: number;
    reason: string;
    /** mixed_script only: the scripts of the offending label. */
    scripts?: string[];
    /** What `domain` is: a curated brand (named in messages) or a verified organization's domain (not named). */
    source?: 'curated' | 'verified';
  }>;
  isSuspicious: boolean;
}

interface ReferenceDomain {
  /** Lowercase ASCII host, without www. */
  domain: string;
  orgName: string;
  /** Owning verified organization (absent for the curated list). */
  orgId?: string;
  source: 'verified_org' | 'verified_destination' | 'curated';
  /** hostSkeleton of the domain, computed once per load. */
  skeleton: string;
  /** The skeleton without its TLD, and its normalizeDomain form (edit-distance rules). */
  base: string;
  norm: string;
  /** Curated: the registered name (registrableLabel), its skeleton and normalizeDomain form. */
  label?: string;
  labelSkeleton?: string;
  labelNorm?: string;
  /**
   * Curated and verified organizations' domains: skeletons of the
   * registrable domain's tokens (eurobank.gr → eurobank, gr) and the
   * registrable domain itself, for the brand-as-subdomain rule (D11).
   */
  nameTokens?: string[];
  /** The registrable domain's labels as skeletons (deutsche-bank, de), for the dotted form. */
  nameLabels?: string[];
  registrable?: string | null;
  /** Curated: a multi-tenant domain (only the apex is the brand's own). */
  multiTenant?: boolean;
  /** Curated: the brand's exact name on an unlisted TLD is a lookalike too. */
  strict?: boolean;
  /** Curated: a strict brand whose name is an ordinary word (needs a keyword as a hyphen token). */
  wordlike?: boolean;
  /** Curated: every official domain of the brand (all exempt; multi-tenant ones at the apex only). */
  brandDomains?: Array<{ domain: string; multiTenant: boolean }>;
}

interface ReferenceSet {
  references: ReferenceDomain[];
  /** Verified domain of each verified organization (issuer exemption). */
  verifiedDomainByOrg: Map<string, string>;
  /**
   * An organization's verified domain that a superadmin approved after a
   * lookalike hold (ADR-0007 D10): exempt for that organization's own codes
   * only.
   */
  approvedDomainByOrg: Map<string, string>;
  /** Every curated domain: these are never lookalikes of each other. */
  curatedDomains: Array<{ domain: string; multiTenant: boolean }>;
  /**
   * Verified domains that shield their subdomains from verified references
   * (host → organization ids). A superadmin-approved lookalike (D10) is not
   * one: it stays a lookalike for everyone but its own organization.
   */
  verifiedDomains: Map<string, Set<string>>;
}

/**
 * The scan path runs this check on every verification, so both the
 * reference set and per-URL results are cached in process (ADR-0007):
 * a new verified organization or protected entry applies within the TTL.
 */
export const LOOKALIKE_REFERENCE_TTL_MS = 5 * 60_000;
/** Results kept per generation (issuer × host). */
const RESULT_CACHE_MAX = 10_000;
/** Verified organizations' active destinations kept as references. */
const VERIFIED_DESTINATION_LIMIT = 2_000;
/** Curated names shorter than this match on skeleton equality only (wolt/bolt, viva/visa). */
const CURATED_EDIT_DISTANCE_MIN_LABEL = 6;


/** After a failed reload, wait this long before trying again (the previous set keeps serving). */
export const LOOKALIKE_RELOAD_RETRY_MS = 30_000;

/** Per Prisma client: the reference set, its generation and the results computed against it. */
interface CacheState {
  set: ReferenceSet | null;
  loadedAt: number;
  /** Bumped on every successful load; part of every result key. */
  generation: number;
  loading: Promise<ReferenceSet> | null;
  retryAt: number;
  /** Results of the current generation, keyed by issuer and host. */
  results: Map<string, DomainCheck>;
}

const cacheStates = new WeakMap<object, CacheState>();

/** Whether a verified domain is itself a lookalike of a curated brand (the curated list is fixed per process). */
const curatedLookalikeMemo = new Map<string, boolean>();
const CURATED_LOOKALIKE_MEMO_MAX = 50_000;

/**
 * Whether a destination (domain and owning organization) is a lookalike of
 * another organization's verified domain. Valid while the verified domains
 * are unchanged (`fingerprint`); a change starts a new memo.
 */
const verifiedLookalikeMemo = { fingerprint: '', results: new Map<string, boolean>() };
const VERIFIED_LOOKALIKE_MEMO_MAX = 50_000;

function cacheState(prisma: object): CacheState {
  let state = cacheStates.get(prisma);
  if (!state) {
    state = { set: null, loadedAt: 0, generation: 0, loading: null, retryAt: 0, results: new Map() };
    cacheStates.set(prisma, state);
  }
  return state;
}

export interface LookalikeLogger {
  error: (obj: object, msg: string) => void;
}

/** Bare lowercase host of a domain stored as a hostname or as a URL, without www. */
export function referenceHost(value: string): string | null {
  const trimmed = value.trim();
  try {
    const host = /^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed) ? new URL(trimmed).hostname : new URL(`https://${trimmed}`).hostname;
    return host.toLowerCase().replace(/^www\./, '').replace(/\.$/, '') || null;
  } catch {
    return null;
  }
}

/** Recorded on the organization when its domain is held for review. */
export interface DomainReview {
  domain: string;
  matches: DomainCheck['warnings'];
  /** What led to the hold: setting the domain, DNS verification, or a superadmin override. */
  source: 'domain_set' | 'dns' | 'admin_override';
  /** DNS (or a superadmin) established that the organization controls the domain. */
  ownershipProven: boolean;
  heldAt: string;
  decision?: 'approved' | 'rejected';
  decidedBy?: string;
  decidedAt?: string;
  note?: string;
}

export interface DomainVerificationOutcome {
  verified: boolean;
  /** Held: the domain resembles a protected domain; a superadmin decides. */
  pendingReview?: boolean;
  /** The held domain (normalised host), when held. */
  domain?: string;
  rejected?: boolean;
  matches?: DomainCheck['warnings'];
  error?: string;
}

/**
 * Records the outcome of a verification (held or verified) in the
 * transaction that stores it (ADR-0008: audit entries commit with the change).
 */
export type DomainOutcomeAudit = (tx: Prisma.TransactionClient, outcome: DomainVerificationOutcome) => Promise<void>;

export const DOMAIN_REVIEW_MESSAGE =
  'This domain resembles a protected domain, so a QRAuth administrator reviews it before it can be verified.';

export class DomainService {
  constructor(
    private prisma: PrismaClient,
    private log?: LookalikeLogger,
  ) {}

  /**
   * Extract the domain from a URL, stripping www. prefix
   */
  extractDomain(url: string): string {
    try {
      const parsed = new URL(url);
      return parsed.hostname.replace(/^www\./, '').toLowerCase();
    } catch {
      return url.toLowerCase();
    }
  }

  /**
   * Levenshtein distance between two strings
   */
  levenshtein(a: string, b: string): number {
    const matrix: number[][] = [];
    for (let i = 0; i <= b.length; i++) matrix[i] = [i];
    for (let j = 0; j <= a.length; j++) matrix[0][j] = j;

    for (let i = 1; i <= b.length; i++) {
      for (let j = 1; j <= a.length; j++) {
        if (b.charAt(i - 1) === a.charAt(j - 1)) {
          matrix[i][j] = matrix[i - 1][j - 1];
        } else {
          matrix[i][j] = Math.min(
            matrix[i - 1][j - 1] + 1,
            matrix[i][j - 1] + 1,
            matrix[i - 1][j] + 1,
          );
        }
      }
    }
    return matrix[b.length][a.length];
  }

  /**
   * Normalize a domain by replacing common homoglyphs.
   * "pr0gressnet" -> "progressnet", "progress-net" -> "progressnet"
   */
  normalizeDomain(domain: string): string {
    let normalized = domain.toLowerCase();
    // Remove hyphens (progress-net -> progressnet)
    normalized = normalized.replace(/-/g, '');
    // Replace common homoglyphs
    for (const [pattern, char] of HOMOGLYPH_REPLACEMENTS) {
      normalized = normalized.replace(pattern, char);
    }
    return normalized;
  }

  /**
   * Check if two domains are suspiciously similar.
   * Returns a similarity score (0-100) and the type of similarity.
   */
  checkSimilarity(domain1: string, domain2: string): {
    similar: boolean;
    score: number;
    reason?: string;
  } {
    if (domain1 === domain2) return { similar: false, score: 0 }; // Exact match = same domain, not suspicious

    const d1 = this.extractDomain(domain1);
    const d2 = this.extractDomain(domain2);

    if (d1 === d2) return { similar: false, score: 0 };

    // Strip TLD for comparison (.gr, .com, etc.)
    const d1Base = d1.replace(/\.[^.]+$/, '');
    const d2Base = d2.replace(/\.[^.]+$/, '');
    return this.similarityOfBases(d1Base, d2Base, this.normalizeDomain(d1Base), this.normalizeDomain(d2Base));
  }

  /**
   * checkSimilarity on domains with the TLD stripped (`base`) and their
   * normalizeDomain forms (`norm`), so the lookalike check can precompute
   * them once per reference.
   */
  similarityOfBases(d1Base: string, d2Base: string, n1: string, n2: string): { similar: boolean; score: number; reason?: string } {
    // 1. Homoglyph normalization match
    if (n1 === n2) {
      return { similar: true, score: 95, reason: 'homoglyph_match' };
    }

    const maxLen = Math.max(d1Base.length, d2Base.length);
    const lengthGap = Math.abs(d1Base.length - d2Base.length);
    // No rule below can match across a larger length gap: distance <= 2,
    // substring within 4 characters, or similarity >= 0.8. (Hyphen-only
    // differences are equal after normalizeDomain, rule 1.)
    if (lengthGap > Math.max(4, Math.floor(maxLen * 0.2))) {
      return { similar: false, score: Math.round((1 - lengthGap / Math.max(maxLen, 1)) * 100) };
    }

    // 2. Levenshtein distance
    const distance = this.levenshtein(d1Base, d2Base);
    const similarity = 1 - distance / maxLen;

    if (distance <= 1 && maxLen > 3) {
      return { similar: true, score: 90, reason: 'one_char_difference' };
    }
    if (distance <= 2 && maxLen > 5) {
      return { similar: true, score: 80, reason: 'typosquatting' };
    }

    // 3. Substring containment (progressnet vs progressnet-pay)
    if (d1Base.includes(d2Base) || d2Base.includes(d1Base)) {
      if (Math.abs(d1Base.length - d2Base.length) <= 4) {
        return { similar: true, score: 70, reason: 'substring_match' };
      }
    }

    // 4. Hyphen insertion (progressnet vs progress-net)
    if (d1Base.replace(/-/g, '') === d2Base.replace(/-/g, '')) {
      return { similar: true, score: 85, reason: 'hyphen_variation' };
    }

    // 5. General similarity threshold
    if (similarity >= 0.8 && maxLen > 4) {
      return { similar: true, score: Math.round(similarity * 100), reason: 'high_similarity' };
    }

    return { similar: false, score: Math.round(similarity * 100) };
  }

  /**
   * Check a destination URL against the protected domains: verified
   * organizations' domains and active destinations (other than the issuer's)
   * and the curated list (data/protected-domains.txt). Cached per URL and
   * issuer for LOOKALIKE_RESULT_TTL_MS.
   */
  async checkUrlAgainstVerifiedDomains(
    destinationUrl: string,
    excludeOrgId: string,
  ): Promise<DomainCheck> {
    const host = normalizeUrlHost(destinationUrl);
    if (!host) return { warnings: [], isSuspicious: false };
    const set = await this.referenceSet();
    const state = cacheState(this.prisma);
    // The check depends only on the host and the issuer; results belong to
    // the reference-set generation they were computed against.
    const key = `${state.generation}\u0000${excludeOrgId}\u0000${host.ascii}`;
    const hit = state.results.get(key);
    if (hit) return hit;

    const check = this.compareWithReferences(destinationUrl, set, excludeOrgId);
    if (state.results.size >= RESULT_CACHE_MAX) state.results.delete(state.results.keys().next().value as string);
    state.results.set(key, check);
    return check;
  }

  /** The same check for several URLs (smart link and link list content). Keyed by the URL as given. */
  async checkUrlsAgainstVerifiedDomains(
    urls: string[],
    excludeOrgId: string,
  ): Promise<Map<string, DomainCheck>> {
    const results = new Map<string, DomainCheck>();
    for (const url of urls) {
      if (!results.has(url)) results.set(url, await this.checkUrlAgainstVerifiedDomains(url, excludeOrgId));
    }
    return results;
  }

  /**
   * Loads the protected set into the cache shared by every DomainService on
   * this Prisma client (server start, ADR-0007 D11), so no request pays the
   * first load. Requests that arrive meanwhile wait for the same load.
   * Returns the number of protected domains.
   */
  async preload(): Promise<number> {
    return (await this.referenceSet()).references.length;
  }

  /** Drops the cached references and results (tests; an operator after editing the list). */
  static clearCaches(prisma: object): void {
    cacheStates.delete(prisma);
  }

  /**
   * The protected set, reloaded after LOOKALIKE_REFERENCE_TTL_MS. A reload
   * that fails never fails the caller: the previous set keeps serving (an
   * error is logged and the reload is retried after
   * LOOKALIKE_RELOAD_RETRY_MS); before any successful load, the curated
   * list alone is used.
   */
  private async referenceSet(): Promise<ReferenceSet> {
    const state = cacheState(this.prisma);
    const now = Date.now();
    if (state.set && now - state.loadedAt < LOOKALIKE_REFERENCE_TTL_MS) return state.set;
    if (state.loading) return state.loading;
    if (now < state.retryAt) return state.set ?? this.curatedOnlySet();
    state.loading = this.loadReferenceSet()
      .then((set) => {
        state.set = set;
        state.loadedAt = Date.now();
        state.generation += 1;
        state.results.clear();
        return set;
      })
      .catch((err: unknown) => {
        state.retryAt = Date.now() + LOOKALIKE_RELOAD_RETRY_MS;
        this.log?.error(
          { err, event: 'lookalike.reference_reload_failed', servingPrevious: state.set !== null },
          'Lookalike check: could not reload the protected set; serving the previous one',
        );
        return state.set ?? this.curatedOnlySet();
      })
      .finally(() => {
        state.loading = null;
      });
    return state.loading;
  }

  private curatedOnly: ReferenceSet | null = null;

  /** The curated list without database references (no successful load yet). */
  private curatedOnlySet(): ReferenceSet {
    this.curatedOnly ??= this.buildReferenceSet([], []);
    return this.curatedOnly;
  }

  /** Verified organizations' domains and active destinations, and the curated list, with skeletons. */
  private async loadReferenceSet(): Promise<ReferenceSet> {
    const verifiedOrgs = await this.prisma.organization.findMany({
      where: { domainVerified: true, domain: { not: null } },
      select: { id: true, name: true, domain: true, domainReviewStatus: true, domainReview: true },
    });
    const verifiedDestinations = await this.prisma.qRCode.findMany({
      where: { organization: { domainVerified: true }, status: 'ACTIVE' },
      select: { destinationUrl: true, organizationId: true, organization: { select: { name: true } } },
      distinct: ['destinationUrl'],
      take: VERIFIED_DESTINATION_LIMIT,
    });

    return this.buildReferenceSet(verifiedOrgs, verifiedDestinations);
  }

  private buildReferenceSet(
    verifiedOrgs: Array<{ id: string; name: string; domain: string | null; domainReviewStatus?: string | null; domainReview?: unknown }>,
    verifiedDestinations: Array<{ destinationUrl: string; organizationId: string; organization: { name: string } }>,
  ): ReferenceSet {
    const references: ReferenceDomain[] = [];
    const verifiedDomainByOrg = new Map<string, string>();
    const approvedDomainByOrg = new Map<string, string>();
    const comparable = (domain: string) => {
      const skeleton = hostSkeleton(normalizeHost(domain).unicode);
      const base = skeleton.replace(/\.[^.]+$/, '');
      return { skeleton, base, norm: this.normalizeDomain(base) };
    };
    const curatedDomains: ReferenceSet['curatedDomains'] = [];
    for (const brand of curatedBrands()) {
      const brandDomains = brand.domains.map((domain) => ({ domain, multiTenant: brand.multiTenant.includes(domain) }));
      for (const { domain, multiTenant } of brandDomains) {
        curatedDomains.push({ domain, multiTenant });
        const label = registrableLabel(domain);
        const labelSkeleton = hostSkeleton(label);
        references.push({
          domain,
          orgName: brand.name,
          source: 'curated',
          ...comparable(domain),
          multiTenant,
          strict: brand.strict,
          wordlike: brand.wordlike,
          brandDomains,
          label,
          nameTokens: protectedNameTokens(domain),
          nameLabels: protectedNameLabels(domain),
          registrable: registrableDomain(domain).domain,
          labelSkeleton,
          labelNorm: this.normalizeDomain(labelSkeleton),
        });
      }
    }
    const curatedOnly: ReferenceSet = { references: [...references], verifiedDomainByOrg: new Map(), approvedDomainByOrg: new Map(), curatedDomains, verifiedDomains: new Map() };

    // Verified organizations' domains and destinations. One that is itself a
    // lookalike of a curated brand (raypal.com verified by its owner) is not
    // a reference: it would make the real brand look like a lookalike of it.
    // The curated list is fixed for the process, so each domain's answer is
    // remembered across reloads: only new domains cost a comparison.
    const isCuratedLookalike = (domain: string) => {
      let known = curatedLookalikeMemo.get(domain);
      if (known === undefined) {
        known = this.compareWithReferences(`https://${domain}/`, curatedOnly, '').isSuspicious;
        if (curatedLookalikeMemo.size >= CURATED_LOOKALIKE_MEMO_MAX) curatedLookalikeMemo.clear();
        curatedLookalikeMemo.set(domain, known);
      }
      return known;
    };
    const verifiedDomains = new Map<string, Set<string>>();
    const seen = new Set<string>();
    for (const org of verifiedOrgs) {
      const domain = org.domain ? referenceHost(org.domain) : null;
      if (!domain) continue;
      verifiedDomainByOrg.set(org.id, domain);
      // A superadmin approval applies to the exact domain it was given for.
      if (org.domainReviewStatus === 'APPROVED' && (org.domainReview as { domain?: string } | null)?.domain === domain) {
        approvedDomainByOrg.set(org.id, domain);
      }
      if (!approvedDomainByOrg.has(org.id)) {
        verifiedDomains.set(domain, new Set([...(verifiedDomains.get(domain) ?? []), org.id]));
      }
      seen.add(`${org.id}|${domain}`);
      if (isCuratedLookalike(domain)) continue;
      references.push({
        domain,
        orgName: org.name,
        orgId: org.id,
        source: 'verified_org',
        ...comparable(domain),
        nameTokens: protectedNameTokens(domain),
        nameLabels: protectedNameLabels(domain),
        registrable: registrableDomain(domain).domain,
      });
    }
    // A destination that is a lookalike of another organization's verified
    // domain (an active code to bigc0rp.com) is not a reference either: it
    // would make the real bigcorp.com look like a lookalike of it.
    const orgReferences: ReferenceSet = {
      references: references.filter((r) => r.source === 'verified_org'),
      verifiedDomainByOrg: new Map(),
      approvedDomainByOrg: new Map(),
      curatedDomains,
      verifiedDomains,
    };
    // Each answer depends only on the verified domains (and the fixed
    // curated list), so it is remembered across reloads while they are
    // unchanged: only new destinations cost a comparison.
    const fingerprint = createHash('sha256')
      .update(
        verifiedOrgs
          .map((org) => `${org.id}|${verifiedDomainByOrg.get(org.id) ?? ''}|${approvedDomainByOrg.has(org.id) ? 'approved' : ''}`)
          .sort()
          .join('\n'),
      )
      .digest('hex');
    if (verifiedLookalikeMemo.fingerprint !== fingerprint) {
      verifiedLookalikeMemo.fingerprint = fingerprint;
      verifiedLookalikeMemo.results = new Map();
    }
    const isVerifiedLookalike = (domain: string, ownerOrgId: string) => {
      const key = `${ownerOrgId}|${domain}`;
      let known = verifiedLookalikeMemo.results.get(key);
      if (known === undefined) {
        known = this.compareWithReferences(`https://${domain}/`, orgReferences, ownerOrgId)
          .warnings.some((w) => w.source === 'verified' && w.similarity >= SUSPICIOUS_SIMILARITY);
        if (verifiedLookalikeMemo.results.size >= VERIFIED_LOOKALIKE_MEMO_MAX) verifiedLookalikeMemo.results.clear();
        verifiedLookalikeMemo.results.set(key, known);
      }
      return known;
    };
    for (const qr of verifiedDestinations) {
      const domain = referenceHost(qr.destinationUrl);
      if (!domain || seen.has(`${qr.organizationId}|${domain}`)) continue;
      seen.add(`${qr.organizationId}|${domain}`);
      if (isCuratedLookalike(domain) || isVerifiedLookalike(domain, qr.organizationId)) continue;
      references.push({
        domain,
        orgName: qr.organization.name,
        orgId: qr.organizationId,
        source: 'verified_destination',
        ...comparable(domain),
      });
    }
    return { references, verifiedDomainByOrg, approvedDomainByOrg, curatedDomains, verifiedDomains };
  }

  /** A strict, not wordlike curated name of BRAND_TOKEN_MIN_LENGTH+ characters: flagged as a hyphen token alone (D11). */
  private distinctiveName(ref: ReferenceDomain): boolean {
    return ref.source === 'curated' && ref.strict === true && !ref.wordlike && ref.label!.length >= BRAND_TOKEN_MIN_LENGTH;
  }

  private compareWithReferences(destinationUrl: string, set: ReferenceSet, excludeOrgId: string): DomainCheck {
    const none: DomainCheck = { warnings: [], isSuspicious: false };
    const host = normalizeUrlHost(destinationUrl);
    if (!host) return none;
    const ascii = host.ascii.replace(/^www\./, '');
    const unicode = host.unicode.replace(/^www\./, '');

    // A verified domain is not exempt for its organization just by being
    // verified (it was reviewed for lookalikes, reviewDomain). Only one a
    // superadmin approved after a hold is: for the same organization's codes
    // (the domain and its subdomains), never for anyone else's (D10).
    const approved = set.approvedDomainByOrg.get(excludeOrgId);
    if (approved && isSameOrSubdomain(ascii, approved)) return none;

    const warnings: DomainCheck['warnings'] = [];
    const mixed = mixedScriptLabel(unicode);
    if (mixed) {
      warnings.push({ domain: host.ascii, verifiedOrgName: '', similarity: 100, reason: 'mixed_script', scripts: mixed.scripts });
    }

    // Parent domains in both forms (labels align: punycode is per label).
    const asciiParents = parentDomains(ascii);
    const parentSkeletons = parentDomains(unicode).map(hostSkeleton);
    const fullSkeleton = hostSkeleton(unicode);
    const base = fullSkeleton.replace(/\.[^.]+$/, '');
    const norm = this.normalizeDomain(base);
    // The registered name: the tenant label under a multi-tenant curated
    // domain (paypa1.sharepoint.com → paypa1), otherwise from the PSL.
    const tenantOf = set.curatedDomains.find((d) => d.multiTenant && ascii.endsWith(`.${d.domain}`));
    const label = tenantOf
      ? unicodeLabel(ascii.slice(0, -(tenantOf.domain.length + 1)).split('.').pop()!)
      : registrableLabel(ascii);
    const labelSkeleton = hostSkeleton(label);
    // Diacritic-insensitive form for curated brands: äpple, åpple, päypal.
    const bareLabelSkeleton = hostSkeleton(stripMarks(label));
    const labelNorm = this.normalizeDomain(labelSkeleton);
    // Hyphen tokens of the registered name or tenant label
    // (paypal-secure.com, paypa1-login.sharepoint.com) for the brand-token
    // and brand-plus-keyword rules (D11), and every token left of the
    // public suffix for the brand-as-subdomain rule.
    const labelTokens = label.split('-').filter(Boolean).map((part) => ({ part, skeleton: tokenSkeleton(part) }));
    const labelParts = labelTokens.length > 1 ? labelTokens : [];
    const labelTokenSkeletons = labelTokens.map((t) => t.skeleton);
    const tokens = hostTokens(ascii);
    // A tenant host is never the brand's own, even under a broader listed
    // domain (x.my.salesforce.com under salesforce.com).
    const isCuratedHost = !tenantOf && set.curatedDomains.some((d) => coveredBy(ascii, d.domain, d.multiTenant));
    // Organizations whose verified domain is the host or a parent of it (a
    // lookalike cannot become verified without review, ADR-0007 D9; an
    // approved lookalike is not in this map).
    const shieldingOrgs = new Set(asciiParents.flatMap((d) => [...(set.verifiedDomains.get(d) ?? [])]));
    for (const ref of set.references) {
      if (ref.orgId !== undefined && ref.orgId === excludeOrgId) continue;
      if (ref.source === 'curated' && isCuratedHost) continue;
      // A verified organization's reference never makes a curated domain, or
      // a verified domain of any other organization (or its subdomains), a
      // lookalike.
      if (ref.source !== 'curated' && (isCuratedHost || [...shieldingOrgs].some((id) => id !== ref.orgId))) continue;
      if (!tenantOf && coveredBy(ascii, ref.domain, ref.multiTenant ?? false)) continue;
      if (!tenantOf && ref.brandDomains?.some((d) => coveredBy(ascii, d.domain, d.multiTenant))) continue;
      // A parent with the protected skeleton that is not literally the
      // protected domain (contoso.sharepoint.com is under the real one).
      const source = ref.source === 'curated' ? 'curated' : 'verified';
      if (parentSkeletons.some((sk, i) => sk === ref.skeleton && asciiParents[i] !== ref.domain)) {
        warnings.push({ domain: ref.domain, verifiedOrgName: ref.orgName, similarity: 100, reason: 'confusable', source });
        continue;
      }
      // The protected domain's name in front of another registrable domain,
      // left of the public suffix only, so a country domain (google.com.hk)
      // is not one. As labels (eurobank.gr.secure-login.com) it is flagged
      // for every protected domain. As hyphen tokens (paypal-com-login.net)
      // it is flagged alone only for a strict, not wordlike brand of
      // BRAND_TOKEN_MIN_LENGTH+ characters; otherwise, and always for
      // verified organizations, only next to a keyword (alpha-gr.com and
      // athens-taxi-gr.com pass).
      const embedded =
        ref.nameTokens && ref.nameLabels && !isSameOrSubdomain(ascii, ref.domain) && tokens.registrable !== ref.registrable
          ? embeddedName(tokens, ref.nameLabels, ref.nameTokens)
          : null;
      if (embedded && (embedded.form === 'dotted' || embedded.keyword || this.distinctiveName(ref))) {
        warnings.push({ domain: ref.domain, verifiedOrgName: ref.orgName, similarity: 95, reason: 'embedded_domain', source });
        continue;
      }
      if (ref.source === 'curated') {
        // The registered name: the brand's own name on another TLD is not a
        // lookalike (brands hold their names across country domains); a
        // confusable spelling of it on any TLD is.
        if (label === ref.label) {
          // Same name on a TLD the brand does not list (its listed domains
          // were exempted above): a lookalike only for strict brands.
          if (ref.strict) warnings.push({ domain: ref.domain, verifiedOrgName: ref.orgName, similarity: 90, reason: 'brand_name', source });
          continue;
        }
        if (labelSkeleton === ref.labelSkeleton || bareLabelSkeleton === ref.labelSkeleton) {
          warnings.push({ domain: ref.domain, verifiedOrgName: ref.orgName, similarity: 100, reason: 'confusable', source });
          continue;
        }
        // A hyphen token equal to a strict brand's name. Names shorter than
        // BRAND_TOKEN_MIN_LENGTH are common words (db, ing, gov): they count
        // only next to a credential keyword (nbg-login.gr, not db-tools.io or
        // nbg-support.gr), and so do wordlike brands (visa-login.com, not
        // visa-team.com or visa-support.gr).
        const needsKeyword = ref.label!.length < BRAND_TOKEN_MIN_LENGTH || ref.wordlike;
        const keywordNearby = labelParts.some((t) => t.skeleton !== ref.labelSkeleton && hasCredentialKeyword(t.skeleton));
        if (ref.strict && (!needsKeyword || keywordNearby) && labelParts.some((t) => t.part === ref.label)) {
          warnings.push({ domain: ref.domain, verifiedOrgName: ref.orgName, similarity: 90, reason: 'brand_token', source });
          continue;
        }
        // A token confusable with the name (strict brands; in tenant labels,
        // any brand). The keyword requirement covers the plain name only: an
        // ordinary word is spelled plainly, so a confusable or accented
        // spelling counts alone (vısa-pay.com, nbɡ-hr.sharepoint.com).
        if ((ref.strict || tenantOf !== undefined) && labelParts.some((t) => t.part !== ref.label && t.skeleton === ref.labelSkeleton)) {
          warnings.push({ domain: ref.domain, verifiedOrgName: ref.orgName, similarity: 100, reason: 'confusable', source });
          continue;
        }
        // A strict brand's name run together with a phishing keyword in one
        // token (paypalsecure.com, mypaypallogin.com); without a keyword, or
        // inside a longer word, it is not one (pinstripesupport.com).
        if (ref.strict && ref.label!.length >= BRAND_KEYWORD_MIN_LENGTH && brandWithKeyword(labelTokenSkeletons, ref.labelSkeleton!, ref.wordlike)) {
          warnings.push({ domain: ref.domain, verifiedOrgName: ref.orgName, similarity: 90, reason: 'brand_keyword', source });
          continue;
        }
        if (ref.label!.length < CURATED_EDIT_DISTANCE_MIN_LABEL) {
          // Short names skip edit distance but still get the ASCII homoglyph
          // map (vv → w, rn → m, l/1/i, 0/o, cl → d) and hyphen removal.
          if (labelNorm === ref.labelNorm) {
            warnings.push({ domain: ref.domain, verifiedOrgName: ref.orgName, similarity: 95, reason: 'homoglyph_match', source });
          }
          continue;
        }
        const result = this.similarityOfBases(labelSkeleton, ref.labelSkeleton!, labelNorm, ref.labelNorm!);
        if (result.similar) {
          warnings.push({ domain: ref.domain, verifiedOrgName: ref.orgName, similarity: result.score, reason: result.reason!, source });
        }
        continue;
      }
      if (fullSkeleton === ref.skeleton) continue;
      const result = this.similarityOfBases(base, ref.base, norm, ref.norm);
      if (result.similar) {
        warnings.push({ domain: ref.domain, verifiedOrgName: ref.orgName, similarity: result.score, reason: result.reason!, source });
      }
    }

    // Suspicious brand matches, then mixed scripts, then weaker matches;
    // one warning per protected brand or organization.
    warnings.sort(compareLookalikeWarnings);
    const seen = new Set<string>();
    const unique = warnings.filter((w) => {
      const key = w.reason === 'mixed_script' ? '\u0000mixed' : w.verifiedOrgName || w.domain;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });

    return {
      warnings: unique,
      isSuspicious: unique.some((w) => w.similarity >= SUSPICIOUS_SIMILARITY),
    };
  }

  /**
   * The lookalike check for an organization's own domain (ADR-0007 D9):
   * against curated brands and other organizations' verified domains only
   * (not their destinations). Run when the domain is set and when it would
   * become verified.
   */
  async reviewDomain(domain: string, orgId: string): Promise<DomainCheck> {
    const host = referenceHost(domain);
    if (!host) return { warnings: [], isSuspicious: false };
    const set = await this.referenceSet();
    // The review never applies the approved exemption (D10): whether an
    // approval covers this exact domain is applyDomainVerification's decision.
    const reviewSet: ReferenceSet = {
      ...set,
      approvedDomainByOrg: new Map(),
      references: set.references.filter((r) => r.source === 'curated' || (r.source === 'verified_org' && r.orgId !== orgId)),
      verifiedDomains: new Map([...set.verifiedDomains].map(([d, ids]) => [d, new Set([...ids].filter((id) => id !== orgId))] as const)),
    };
    return this.compareWithReferences(`https://${host}/`, reviewSet, orgId);
  }

  /**
   * Marks the organization's domain verified, unless it is a lookalike: then
   * it is held for superadmin review (PENDING_REVIEW, not verified). A domain
   * a superadmin approved or rejected keeps that decision while it stays the
   * same. `source` is how ownership was established.
   */
  async applyDomainVerification(
    orgId: string,
    source: 'dns' | 'admin_override',
    audit?: DomainOutcomeAudit,
  ): Promise<DomainVerificationOutcome> {
    const org = await this.prisma.organization.findUnique({
      where: { id: orgId },
      select: { domain: true, domainReviewStatus: true, domainReview: true },
    });
    const host = org?.domain ? referenceHost(org.domain) : null;
    if (!org || !host) return { verified: false, error: 'No domain set on organization' };
    const decided = (org.domainReview as { domain?: string } | null)?.domain === host ? org.domainReviewStatus : null;
    if (decided === 'REJECTED') {
      return { verified: false, rejected: true, error: 'This domain was rejected in review. Contact QRAuth support.' };
    }
    if (decided !== 'APPROVED') {
      const check = await this.reviewDomain(host, orgId);
      if (check.isSuspicious) {
        const review: DomainReview = {
          domain: host,
          matches: check.warnings.slice(0, 5),
          source,
          ownershipProven: true,
          heldAt: new Date().toISOString(),
        };
        const held: DomainVerificationOutcome = { verified: false, pendingReview: true, domain: host, matches: review.matches, error: DOMAIN_REVIEW_MESSAGE };
        return this.storeOutcome(orgId, { domainVerified: false, domainReviewStatus: 'PENDING_REVIEW', domainReview: review as never }, held, audit);
      }
    }
    const data: Prisma.OrganizationUpdateInput = decided === 'APPROVED'
      ? { domainVerified: true }
      : { domainVerified: true, domainReviewStatus: null, domainReview: Prisma.DbNull };
    return this.storeOutcome(orgId, data, { verified: true, domain: host }, audit);
  }

  private async storeOutcome(
    orgId: string,
    data: Prisma.OrganizationUpdateInput,
    outcome: DomainVerificationOutcome,
    audit?: DomainOutcomeAudit,
  ): Promise<DomainVerificationOutcome> {
    await this.prisma.$transaction(async (tx) => {
      await tx.organization.update({ where: { id: orgId }, data });
      await audit?.(tx, outcome);
    });
    return outcome;
  }

  /**
   * Generate a domain verification token.
   * The org adds a DNS TXT record: qrauth-verify=<token>
   */
  async generateVerifyToken(orgId: string): Promise<string> {
    const token = randomBytes(16).toString('hex');

    await this.prisma.organization.update({
      where: { id: orgId },
      data: { domainVerifyToken: token },
    });

    return token;
  }

  /**
   * Verify domain ownership by checking DNS TXT records.
   */
  async verifyDomain(orgId: string, audit?: DomainOutcomeAudit): Promise<DomainVerificationOutcome> {
    const org = await this.prisma.organization.findUnique({
      where: { id: orgId },
      select: { domain: true, domainVerifyToken: true },
    });

    if (!org?.domain) return { verified: false, error: 'No domain set on organization' };
    if (!org.domainVerifyToken) return { verified: false, error: 'No verification token generated. Call generate-verify-token first.' };

    // Strip protocol and path if the domain was stored as a URL
    let hostname = org.domain;
    try { hostname = new URL(hostname.includes('://') ? hostname : `https://${hostname}`).hostname; } catch { /* use as-is */ }

    try {
      // Use DNS lookup via fetch to a DNS-over-HTTPS provider
      const res = await fetch(
        `https://dns.google/resolve?name=${encodeURIComponent(hostname)}&type=TXT`,
        { signal: AbortSignal.timeout(5000) },
      );

      if (!res.ok) return { verified: false, error: 'DNS lookup failed' };

      const data = await res.json() as {
        Answer?: Array<{ type: number; data: string }>;
      };

      const txtRecords = (data.Answer || [])
        .filter((r) => r.type === 16) // TXT record type
        .map((r) => r.data.replace(/"/g, ''));

      const expectedValue = `qrauth-verify=${org.domainVerifyToken}`;
      const found = txtRecords.some((txt) => txt.includes(expectedValue));

      if (found) return this.applyDomainVerification(orgId, 'dns', audit);

      return {
        verified: false,
        error: `TXT record "qrauth-verify=${org.domainVerifyToken}" not found for ${hostname}. Found records: ${txtRecords.join(', ') || 'none'}`,
      };
    } catch (err: any) {
      return { verified: false, error: `DNS lookup error: ${err.message}` };
    }
  }
}
