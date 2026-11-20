import type { PrismaClient } from '@prisma/client';
import type { FastifyBaseLogger } from 'fastify';
import { createHash } from 'node:crypto';
import {
  canonicalizeCore,
  canonicalGeoHash,
  computeDestHash,
  contentLinkUrls,
  generateToken,
  getContentType,
  isLinkedContentType,
} from '@qrauth/shared';

import { config } from '../lib/config.js';
import { stableStringify } from '../lib/crypto.js';
import { policyDestinations } from '../lib/allowlist-domains.js';
import { buildVerificationUrl } from '../lib/qrcode-access.js';
import type { QrStyle } from '../routes/qrcodes.js';
import type { DomainCheck, DomainService } from './domain.js';
import type { GeoService } from './geo.js';
import type { HybridSigningService } from './hybrid-signing.js';
import { assertLogoScans, LogoUnreadableError } from './logo-decode.js';
import { LogoLibrary, type LogoTx } from './logo-library.js';
import { recordLookalikeIncident, type LookalikeIncidentSource } from './lookalike-incidents.js';
import { compareLookalikeWarnings } from './lookalike.js';
import type { MacService } from './mac.js';
import type { MerkleNode } from './merkle-signing.js';
import { enforcePolicyInTransaction, isOutsidePolicy } from './org-policy.js';
import { recordCreated, type RevisionContext } from './qr-revisions.js';
import { qrImageDataUrl, RenderUnavailableError } from './qr-render.js';
import type { ScanMode } from './scan-mode.js';
import type { SigningService } from './signing.js';
import { TransparencyLogService } from './transparency.js';

/**
 * Issuing a QR code: the core shared by single create, the bulk endpoint and
 * the bulk import job (ADR-0008 D9), so every path signs, stores and checks
 * a code the same way. Callers run the plan, quota, allowlist and Web Risk
 * checks first (routes/qrcodes.ts, services/bulk-import.ts).
 */

/** What issuing needs from the server: the database and a logger (a Fastify instance qualifies). */
export interface QrCreateHost {
  readonly prisma: PrismaClient;
  readonly log: FastifyBaseLogger;
}

/**
 * The save-time decode round trip for a style with a customer logo: throws
 * LogoUnreadableError when a raster does not read back, and
 * RenderUnavailableError when rendering itself fails (queue busy).
 */
export async function checkLogoScans(token: string, style: QrStyle, assetLogo: Uint8Array): Promise<void> {
  try {
    await assertLogoScans(buildVerificationUrl(token), style, assetLogo);
  } catch (err) {
    if (err instanceof LogoUnreadableError) throw err;
    throw new RenderUnavailableError(err);
  }
}

/**
 * Recompute the symmetric MAC fast path (ALGORITHM.md §7, AUDIT-FINDING-011)
 * over the SAME canonical core string the ECDSA/Merkle legs sign, then sign
 * it. Shared by QR create and update so both paths stay byte-for-byte in
 * agreement.
 *
 * Best-effort: if the MAC signer is unavailable the caller persists the row
 * without a fast-path MAC (this returns nulls) rather than failing the whole
 * operation. Stored server-side only — never embedded in the QR.
 */
export async function recomputeAndSignMac(
  macService: MacService,
  log: FastifyBaseLogger,
  params: {
    algVersion: string;
    token: string;
    organizationId: string;
    contentType: string;
    destinationUrl: string;
    contentHashHex: string;
    lat: number | null;
    lng: number | null;
    radiusM: number | null;
    expiresAt: string;
  },
): Promise<{ mac: string | null; keyVersion: number | null }> {
  const destHash = await computeDestHash(
    params.contentType,
    params.destinationUrl,
    params.contentHashHex,
  );
  const geoHash = await canonicalGeoHash(params.lat, params.lng, params.radiusM);
  const canonical = canonicalizeCore({
    algVersion: params.algVersion,
    token: params.token,
    tenantId: params.organizationId,
    destHash,
    geoHash,
    expiresAt: params.expiresAt,
  });
  try {
    const result = await macService.signCanonical(params.organizationId, canonical);
    return { mac: result.mac, keyVersion: result.keyVersion };
  } catch (err) {
    log.warn(
      { err, organizationId: params.organizationId },
      'MAC signing unavailable, QR row will lack the fast-path MAC',
    );
    return { mac: null, keyVersion: null };
  }
}

/**
 * Compares a destination with the domains of verified organizations and, when
 * it is suspiciously similar, records a HIGH fraud incident on the QR code.
 * Non-blocking: the caller keeps going whatever the result. Runs on create and
 * whenever an update changes the destination.
 */
export async function checkDestinationSimilarity(
  fastify: QrCreateHost,
  domainService: DomainService,
  qrCodeId: string,
  destinationUrl: string,
  organizationId: string,
  source: LookalikeIncidentSource,
): ReturnType<DomainService['checkUrlAgainstVerifiedDomains']> {
  const checked = await domainService.checkUrlAgainstVerifiedDomains(
    destinationUrl,
    organizationId,
  );
  // Brand matches before mixed scripts (ADR-0007 D11), as for links.
  const domainCheck = { ...checked, warnings: [...checked.warnings].sort(compareLookalikeWarnings) };

  const top = domainCheck.isSuspicious ? domainCheck.warnings[0] : undefined;
  if (top) {
    try {
      await recordLookalikeIncident(fastify.prisma, qrCodeId, destinationUrl, top, source);
    } catch (err) {
      fastify.log.warn({ err, qrCodeId }, 'Failed to create suspicious domain fraud incident');
    }
  }

  return domainCheck;
}

export type LinkDomainWarning = DomainCheck['warnings'][number] & { url?: string };

/**
 * The same check for the links of a smart link or link list code (its
 * destination is the verify page): one lookup of the reference domains, a
 * HIGH fraud incident per lookalike link, and the warnings with their link.
 */
export async function checkLinksSimilarity(
  fastify: QrCreateHost,
  domainService: DomainService,
  qrCodeId: string,
  urls: string[],
  organizationId: string,
  source: LookalikeIncidentSource,
): Promise<{ warnings: LinkDomainWarning[]; isSuspicious: boolean }> {
  const checks = await domainService.checkUrlsAgainstVerifiedDomains(urls, organizationId);
  const warnings: LinkDomainWarning[] = [];
  let isSuspicious = false;
  const incidents: Array<Promise<unknown>> = [];
  for (const [url, check] of checks) {
    warnings.push(...check.warnings.map((w) => ({ ...w, url })));
    if (!check.isSuspicious) continue;
    isSuspicious = true;
    const top = check.warnings[0];
    incidents.push(
      recordLookalikeIncident(fastify.prisma, qrCodeId, url, top, source).catch((err: unknown) => {
        fastify.log.warn({ err, qrCodeId }, 'Failed to create suspicious domain fraud incident');
      }),
    );
  }
  await Promise.all(incidents);
  warnings.sort(compareLookalikeWarnings);
  return { warnings, isSuspicious };
}

/** domain_warnings in a create or update response. */
export function domainWarningsBody(warnings: LinkDomainWarning[]) {
  return warnings.map((w) => ({
    ...(w.url ? { url: w.url } : {}),
    similar_to: w.domain,
    verified_org: w.verifiedOrgName,
    similarity: w.similarity,
    reason: w.reason,
  }));
}

/** Destination similarity for any content type: the links of linked types, else the destination. */
export function checkCodeSimilarity(
  fastify: QrCreateHost,
  domainService: DomainService,
  code: { id: string; organizationId: string; contentType: string; destinationUrl: string; content: unknown },
  source: LookalikeIncidentSource,
): Promise<{ warnings: LinkDomainWarning[]; isSuspicious: boolean }> {
  return isLinkedContentType(code.contentType)
    ? checkLinksSimilarity(fastify, domainService, code.id, contentLinkUrls(code.contentType, code.content), code.organizationId, source)
    : checkDestinationSimilarity(fastify, domainService, code.id, code.destinationUrl, code.organizationId, source);
}

/**
 * Core QR code generation logic extracted so it can be reused by both the
 * single-create and bulk-create endpoints without duplication.
 */
export async function generateQRCode(
  fastify: QrCreateHost,
  signingService: SigningService,
  hybridSigningService: HybridSigningService,
  macService: MacService,
  geoService: GeoService,
  transparencyService: TransparencyLogService,
  domainService: DomainService,
  organizationId: string,
  input: {
    destinationUrl: string;
    label?: string;
    location?: { lat: number; lng: number; radiusM: number; requireProximity?: boolean };
    expiresAt?: string;
    contentType?: string;
    content?: unknown;
    maxScans?: number;
    maxScansPerDevice?: number;
    scanMode?: ScanMode;
    qrStyle?: QrStyle;
    /** The customer logo's bytes when qrStyle draws one (loaded and scoped by the route). */
    assetLogo?: Uint8Array | null;
    /** The organization is a verified issuer: the badge mark's wording in qr_image_url (D9). */
    issuerVerified: boolean;
    /** Who is creating it: revision 1 of the code's edit history. */
    revision: RevisionContext;
    /**
     * Render qr_image_url (default true). A bulk import does not return the
     * image and renders nothing, so it never takes an issuance-lane slot.
     */
    renderImage?: boolean;
    /** Folder and tags of the new code, written in the create transaction (ids of this organization). */
    organize?: { folderId: string | null; tagIds: readonly string[] };
  },
) {
  // 1. Resolve and validate content type.
  const resolvedContentType = input.contentType || 'url';
  const typeRegistry = getContentType(resolvedContentType);
  if (!typeRegistry) {
    throw new Error(`Unknown content type: ${resolvedContentType}`);
  }

  let contentHashHex = '';
  if (input.content && resolvedContentType !== 'url') {
    const parseResult = typeRegistry.schema.safeParse(input.content);
    if (!parseResult.success) {
      throw new Error(`Invalid content for type ${resolvedContentType}: ${parseResult.error.message}`);
    }
    // Deterministic JSON for hashing (PostgreSQL JSONB reorders keys alphabetically).
    // SHA-256 here matches the verify-side hashString(stableStringify(...)) call
    // so the destHash computation agrees across sign and verify.
    contentHashHex = createHash('sha256').update(stableStringify(input.content)).digest('hex');
  }

  // Derive destinationUrl for non-URL types (the verify page is the destination).
  const baseUrl = config.server.isDev
    ? `http://localhost:${config.server.port}`
    : config.webauthn.origin;

  // 2. Get active signing key.
  const signingKey = await signingService.getActiveKey(organizationId);

  // 3. Generate a short, unbiased token.
  const token = generateToken();

  // 3a. A customer logo must read back at the checked export sizes before the
  // style is stored (ADR-0005 PR 4); a failure (LogoUnreadableError) stores
  // nothing.
  const assetLogo = input.qrStyle?.logo?.kind === 'asset' ? (input.assetLogo ?? null) : null;
  if (input.qrStyle && assetLogo) await checkLogoScans(token, input.qrStyle, assetLogo);

  // 3b. Render qr_image_url now, before anything is signed or stored: if
  // rendering fails (RenderUnavailableError) nothing is persisted and no
  // quota is used. The image depends only on the token and the style.
  const qrImageUrl = input.renderImage === false
    ? null
    : await qrImageDataUrl({ token, issuerVerified: input.issuerVerified }, input.qrStyle ?? null, assetLogo);

  // 4. For non-URL types, the QR code points to the QRAuth verify page itself.
  const destinationUrl = resolvedContentType === 'url'
    ? input.destinationUrl
    : `${baseUrl}/v/${token}`;

  // 5. Encode geohash when location is provided.
  const geoHash = input.location
    ? geoService.encodeGeoHash(input.location.lat, input.location.lng)
    : '';

  const expiresAtStr = input.expiresAt ?? '';
  const expiresAtDate = input.expiresAt ? new Date(input.expiresAt) : null;

  // 6. Sign the canonical payload through the hybrid (ECDSA + SLH-DSA/Merkle)
  //    pipeline and await both legs before persisting. Latency is dominated
  //    by the SLH-DSA batch-root sign, amortized across concurrent enqueues.
  //    Every row is written with all Merkle fields set; there is no
  //    intermediate state (ALGORITHM.md §6.3).
  const hybrid = await hybridSigningService.signSingleQR({
    organizationId,
    signingKeyDbId: signingKey.id,
    signingKeyId: signingKey.keyId,
    token,
    contentType: resolvedContentType,
    destinationUrl,
    contentHashHex,
    expiresAt: expiresAtStr,
    lat: input.location?.lat ?? null,
    lng: input.location?.lng ?? null,
    radiusM: input.location?.radiusM ?? null,
  });
  const signature = hybrid.ecdsaSignature;
  const pqcFields = {
    algVersion: hybrid.algVersion,
    merkleBatchId: hybrid.batchId,
    merkleLeafIndex: hybrid.leafIndex,
    merkleLeafHash: hybrid.leafHash,
    merkleLeafNonce: hybrid.leafNonce,
    merklePath: hybrid.merklePath as unknown as object,
    merkleRoot: hybrid.merkleRoot,
  };

  // 6b. Compute the symmetric MAC fast path (ALGORITHM.md §7,
  //     AUDIT-FINDING-011). The MAC binds the SAME canonical core string
  //     the ECDSA leg signs, so the verifier recomputes it deterministically
  //     from any QR row. Stored server-side only — never embedded in the QR.
  const { mac: macTokenMac, keyVersion: macKeyVersion } = await recomputeAndSignMac(
    macService,
    fastify.log,
    {
      algVersion: pqcFields.algVersion,
      token,
      organizationId,
      contentType: resolvedContentType,
      destinationUrl,
      contentHashHex,
      lat: input.location?.lat ?? null,
      lng: input.location?.lng ?? null,
      radiusM: input.location?.radiusM ?? null,
      expiresAt: expiresAtStr,
    },
  );

  // 7. Persist to database. A style that draws a customer logo is written
  //    under the logo row's lock, after re-checking that the logo still
  //    exists, so a parallel delete cannot leave the code without it
  //    (LogoNotFoundError when it lost the race; nothing is stored).
  const persist = async (db: LogoTx) => {
    // The allowlist as locked in this transaction (the route checked it
    // before signing; this closes the window to a concurrent policy change).
    const destinations = policyDestinations({ contentType: resolvedContentType, destinationUrl, content: input.content });
    const lockedPolicy = await enforcePolicyInTransaction(db, organizationId, { urls: destinations });
    const row = await db.qRCode.create({
    data: {
      outsidePolicy: isOutsidePolicy(lockedPolicy, destinations),
      token,
      organizationId,
      signingKeyId: signingKey.id,
      keyId: signingKey.keyId,
      destinationUrl,
      label: input.label,
      contentType: resolvedContentType,
      content: input.content ? (input.content as object) : undefined,
      // Dashboard style preferences. Undefined when omitted → stored NULL;
      // callers fall back to DEFAULT_STYLE on read. Already validated by
      // qrStyleSchema at the route boundary.
      style: input.qrStyle ?? undefined,
      signature,
      geoHash: geoHash || null,
      latitude: input.location?.lat ?? null,
      longitude: input.location?.lng ?? null,
      radiusM: input.location?.radiusM ?? 50,
      // Default true — geo-bound rows fail closed at verify unless explicitly
      // toggled off. Ignored at verify time when lat/lng are null.
      requireProximity: input.location?.requireProximity ?? true,
      status: 'ACTIVE',
      expiresAt: expiresAtDate,
      maxScans: input.maxScans ?? null,
      maxScansPerDevice: input.maxScansPerDevice ?? null,
      // Browser scan behaviour; display only, not part of the signed payload.
      scanMode: input.scanMode ?? 'FLASH',
      algVersion: pqcFields.algVersion,
      merkleBatchId: pqcFields.merkleBatchId,
      merkleLeafIndex: pqcFields.merkleLeafIndex,
      merkleLeafHash: pqcFields.merkleLeafHash,
      merkleLeafNonce: pqcFields.merkleLeafNonce,
      merklePath: pqcFields.merklePath as never,
      macTokenMac,
      macKeyVersion,
      folderId: input.organize?.folderId ?? null,
    },
    });
    if (input.organize && input.organize.tagIds.length > 0) {
      await db.qRCodeTag.createMany({ data: input.organize.tagIds.map((tagId) => ({ qrCodeId: row.id, tagId })) });
    }
    // Revision 1 of the edit history, in the same transaction.
    await recordCreated(db, row, input.revision);
    return row;
  };
  const logoAssetId = input.qrStyle?.logo?.kind === 'asset' ? input.qrStyle.logo.assetId : null;
  const qrCode = logoAssetId
    ? await new LogoLibrary(fastify.prisma).writeWithLogo(organizationId, logoAssetId, persist)
    : await fastify.prisma.$transaction((tx) => persist(tx));

  // 6. Append to transparency log. For hybrid-signed QRs we attach the
  //    commitment-only fields (leaf hash, batch root ref, inclusion proof)
  //    so the public log carries opaque commitments instead of plaintext
  //    hashes — see ALGORITHM.md §8.
  let transparencyLogIndex: number | null = null;
  try {
    const pqcBlock =
      pqcFields.algVersion === 'hybrid-ecdsa-slhdsa-v1' &&
      pqcFields.merkleLeafHash &&
      pqcFields.merkleBatchId &&
      pqcFields.merkleRoot
        ? {
            algVersion: pqcFields.algVersion,
            leafHash: pqcFields.merkleLeafHash,
            batchRootRef: TransparencyLogService.computeBatchRootRef(pqcFields.merkleRoot),
            merkleInclusionProof: pqcFields.merklePath as unknown as MerkleNode[],
          }
        : null;

    const logEntry = await transparencyService.appendEntry({
      id: qrCode.id,
      token: qrCode.token,
      organizationId: qrCode.organizationId,
      destinationUrl: qrCode.destinationUrl,
      geoHash: qrCode.geoHash,
      pqc: pqcBlock,
    });
    transparencyLogIndex = logEntry.logIndex;
  } catch (err) {
    fastify.log.warn({ err, qrCodeId: qrCode.id }, 'Failed to append transparency log entry');
  }

  // 7. Check destination domain (or each link) against verified org domains (non-blocking).
  const domainCheck = await checkCodeSimilarity(fastify, domainService, {
    id: qrCode.id,
    organizationId,
    contentType: resolvedContentType,
    destinationUrl,
    content: input.content,
  }, 'create');

  const verificationUrl = buildVerificationUrl(qrCode.token);

  return {
    token: qrCode.token,
    verification_url: verificationUrl,
    qr_image_url: qrImageUrl,
    signature: qrCode.signature,
    organization_id: qrCode.organizationId,
    label: qrCode.label,
    created_at: qrCode.createdAt,
    expires_at: qrCode.expiresAt,
    transparency_log_index: transparencyLogIndex,
    // PQC fields — present on every new token since the hybrid
    // cutover. `alg_version` is authoritative; `merkle_batch_id` is
    // null for legacy or async-pending rows.
    alg_version: qrCode.algVersion,
    merkle_batch_id: qrCode.merkleBatchId,
    scan_mode: qrCode.scanMode,
    ...(domainCheck.warnings.length > 0 ? { domain_warnings: domainWarningsBody(domainCheck.warnings) } : {}),
  };
}
