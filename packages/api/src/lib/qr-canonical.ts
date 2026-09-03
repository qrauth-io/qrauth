import {
  canonicalizeCore,
  canonicalGeoHash,
  computeDestHash,
  ALG_VERSION_POLICY,
} from '@qrauth/shared';
import { hashString, stableStringify } from './crypto.js';

/**
 * Minimal shape of a QRCode row needed to rebuild its canonical core — the
 * byte string every signing/MAC leg binds to (ALGORITHM.md §5).
 */
export interface QrCanonicalRow {
  token: string;
  organizationId: string;
  contentType: string | null;
  destinationUrl: string;
  content: unknown;
  latitude: number | null;
  longitude: number | null;
  radiusM: number;
  expiresAt: Date | null;
  algVersion: string | null;
}

/**
 * Rebuild the unified canonical core string for a QR row, exactly as the
 * verify route does at scan time (Findings 011/019/020/021). Single source
 * of truth shared by the verify route, MAC re-keying (MacService.remacOrgRows),
 * and operational scripts — any drift between issuer and verifier canonicals
 * turns into a permanent verification failure, so there must be one builder.
 *
 * Content-type-aware destHash: URL QRs commit to the URL; content QRs
 * (vCard, coupon, event, pdf, feedback) commit to the hash of the
 * stable-stringified content body. Domain-separated via `computeDestHash`.
 */
export async function buildQrCanonicalCore(qr: QrCanonicalRow): Promise<string> {
  let contentHashHex = '';
  if (qr.content && qr.contentType !== 'url') {
    contentHashHex = hashString(stableStringify(qr.content));
  }
  const destHash = await computeDestHash(
    qr.contentType ?? 'url',
    qr.destinationUrl,
    contentHashHex,
  );
  const geoHash = await canonicalGeoHash(qr.latitude, qr.longitude, qr.radiusM);
  return canonicalizeCore({
    algVersion: qr.algVersion ?? ALG_VERSION_POLICY.hybrid,
    token: qr.token,
    tenantId: qr.organizationId,
    destHash,
    geoHash,
    expiresAt: qr.expiresAt?.toISOString() ?? '',
  });
}
