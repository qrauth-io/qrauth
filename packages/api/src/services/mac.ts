import { createHmac, timingSafeEqual } from 'node:crypto';
import type { OrgMacKey, PrismaClient } from '@prisma/client';
import { generateSecureEntropy } from '../lib/entropy.js';
import { buildQrCanonicalCore } from '../lib/qr-canonical.js';

/**
 * Symmetric MAC fast path (ALGORITHM.md §7).
 *
 * For every issued QR we compute an HMAC-SHA3-256 over the canonical payload
 * using the issuing organization's secret. The MAC is stored on the QRCode
 * row server-side and NEVER embedded in the QR image or the verify URL —
 * an adversary who scrapes the URL learns nothing about the MAC.
 *
 * At verify time the route recomputes the MAC and compares it constant-time.
 * AUDIT-FINDING-001 made the MAC a fail-CLOSED pre-filter: on mismatch the
 * verifier rejects the row outright and the asymmetric legs never run (see
 * routes/verify-signatures.ts). A row with no MAC at all (legacy) skips the
 * pre-filter and the asymmetric legs remain authoritative.
 *
 * Fail-closed has a hard consequence for the key ring: every row must carry
 * a MAC under a key version that still exists, forever. Long-lived printed
 * QRs outlive any fixed grace window (incident 2026-09-03, token qV2zsVQM),
 * so rotation re-MACs rows instead of relying on grace.
 *
 * Key ring:
 *   - One ACTIVE OrgMacKey per organization at any time.
 *   - On rotation the previous ACTIVE row flips to ROTATED, and the cleanup
 *     worker immediately re-MACs the org's live rows under the new key
 *     (`remacOrgRows`). The 30-day ROTATED grace window only covers rows
 *     minted mid-rotation.
 *   - After grace it is marked RETIRED and pruned by the cleanup worker —
 *     but only once no ACTIVE row references its version.
 *   - Verification tries the version stored on the QRCode row first; if that
 *     row is missing it tries ACTIVE → ROTATED in order.
 */

export const MAC_ALGORITHM = 'hmac-sha3-256' as const;
export const MAC_KEY_BYTES = 32; // 256-bit secret per NIST SP 800-107

export interface MacComputation {
  mac: string;          // hex
  keyVersion: number;
}

/** Outcome of the pre-rewrite check against the row's original key. */
export type RemacOldMacCheck = 'verified' | 'key_unavailable' | 'mismatch';

export interface RemacRowResult {
  token: string;
  fromVersion: number | null;
  toVersion: number;
  oldMacCheck: RemacOldMacCheck;
}

export interface RemacSummary {
  /** Rows rewritten under the ACTIVE key (or that would be, in dry-run). */
  updated: RemacRowResult[];
  /** Rows whose stored MAC failed to reproduce under a surviving key — left untouched. */
  flagged: RemacRowResult[];
}

/**
 * Pure function: compute the MAC over a canonical payload string.
 *
 * Domain separation tag `qrauth:mac:v1` is part of the input to prevent the
 * same secret from producing colliding MACs if it's ever reused in a
 * different protocol.
 */
export function computeMac(canonicalPayload: string, secret: Buffer): string {
  return createHmac('sha3-256', secret)
    .update(`qrauth:mac:v1:${canonicalPayload}`)
    .digest('hex');
}

/**
 * Constant-time MAC comparison. Always converts to fixed-length buffers
 * before comparing — never use string `===` on cryptographic values.
 */
export function macsEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  const ba = Buffer.from(a, 'hex');
  const bb = Buffer.from(b, 'hex');
  if (ba.length !== bb.length) return false;
  return timingSafeEqual(ba, bb);
}

export class MacService {
  // AUDIT-FINDING-016: MAC secret currently loaded from DB into process memory; move to KMS per-request.
  constructor(private prisma: PrismaClient) {}

  /**
   * Return the active MAC key for an organization, minting one if none
   * exists yet. Idempotent: subsequent calls return the same row until
   * the next rotation.
   */
  async getOrCreateActiveKey(organizationId: string): Promise<OrgMacKey> {
    const existing = await this.prisma.orgMacKey.findFirst({
      where: { organizationId, status: 'ACTIVE' },
      orderBy: { version: 'desc' },
    });
    if (existing) return existing;

    const secret = await generateSecureEntropy(MAC_KEY_BYTES);
    return this.prisma.orgMacKey.create({
      data: {
        organizationId,
        version: 1,
        secret: secret.toString('base64'),
        algorithm: MAC_ALGORITHM,
        status: 'ACTIVE',
      },
    });
  }

  /**
   * Rotate an organization's MAC key. The current ACTIVE row becomes
   * ROTATED (keeping it valid for the grace window). A new row is created
   * with `version = max + 1` and `status = ACTIVE`. Atomic.
   */
  async rotateKey(organizationId: string): Promise<OrgMacKey> {
    const current = await this.prisma.orgMacKey.findFirst({
      where: { organizationId, status: 'ACTIVE' },
      orderBy: { version: 'desc' },
    });

    const nextSecret = await generateSecureEntropy(MAC_KEY_BYTES);
    const nextVersion = (current?.version ?? 0) + 1;

    return this.prisma.$transaction(async (tx) => {
      if (current) {
        await tx.orgMacKey.update({
          where: { id: current.id },
          data: { status: 'ROTATED', rotatedAt: new Date() },
        });
      }
      return tx.orgMacKey.create({
        data: {
          organizationId,
          version: nextVersion,
          secret: nextSecret.toString('base64'),
          algorithm: MAC_ALGORITHM,
          status: 'ACTIVE',
        },
      });
    });
  }

  /**
   * Compute a MAC for a QR being issued. Caller persists `mac` and
   * `keyVersion` onto the QRCode row.
   */
  async signCanonical(
    organizationId: string,
    canonicalPayload: string,
  ): Promise<MacComputation> {
    const key = await this.getOrCreateActiveKey(organizationId);
    const secret = Buffer.from(key.secret, 'base64');
    return { mac: computeMac(canonicalPayload, secret), keyVersion: key.version };
  }

  /**
   * Verify a stored MAC for a QR being scanned.
   *
   * Looks up the key by `(organizationId, keyVersion)` if a version is
   * supplied; otherwise tries every ACTIVE/ROTATED key in newest-first
   * order. Returns `true` only when constant-time MAC comparison succeeds.
   *
   * A `false` result does NOT prove the QR is forged — it only means the
   * fast path could not confirm authenticity, and the caller MUST fall
   * through to the asymmetric legs (ALGORITHM.md §7.1).
   */
  async verifyCanonical(args: {
    organizationId: string;
    canonicalPayload: string;
    storedMac: string;
    keyVersion: number | null;
  }): Promise<boolean> {
    const candidates: OrgMacKey[] = [];
    if (args.keyVersion != null) {
      const exact = await this.prisma.orgMacKey.findUnique({
        where: {
          organizationId_version: { organizationId: args.organizationId, version: args.keyVersion },
        },
      });
      if (exact && exact.status !== 'RETIRED') candidates.push(exact);
    } else {
      const all = await this.prisma.orgMacKey.findMany({
        where: { organizationId: args.organizationId, status: { in: ['ACTIVE', 'ROTATED'] } },
        orderBy: { version: 'desc' },
      });
      candidates.push(...all);
    }

    for (const key of candidates) {
      const secret = Buffer.from(key.secret, 'base64');
      const expected = computeMac(args.canonicalPayload, secret);
      if (macsEqual(expected, args.storedMac)) return true;
    }
    return false;
  }

  /**
   * Re-MAC every ACTIVE QR row of an organization under its current ACTIVE
   * key (incident 2026-09-03, token qV2zsVQM).
   *
   * The verify route fails CLOSED on a MAC miss (AUDIT-FINDING-001), so a QR
   * whose key version has been retired/purged permanently stops verifying —
   * fatal for long-lived printed QRs. The cleanup worker therefore calls this
   * immediately after `rotateKey` and again before retiring a ROTATED key, so
   * no live row ever references a dead key version. The MAC exists only on
   * the DB row (never in the printed QR), so rewriting it is invisible to
   * anything in circulation.
   *
   * Safety: when the row's original key still exists, the stored MAC must
   * reproduce under it first — proof the rebuilt canonical binds this row.
   * A mismatch flags the row and leaves it untouched (it already fails the
   * fail-closed check today; rewriting could mask a real integrity problem).
   * When the original key is gone (`key_unavailable`), no such check is
   * possible: re-MACing trusts the DB row as ground truth. That is
   * acceptable because the ECDSA + Merkle/SLH-DSA legs still bind to the
   * row's original signatures and remain authoritative — a tampered row
   * fails those legs regardless of its MAC.
   */
  async remacOrgRows(
    organizationId: string,
    opts: { dryRun?: boolean } = {},
  ): Promise<RemacSummary> {
    const keys = await this.prisma.orgMacKey.findMany({ where: { organizationId } });
    const activeKey = keys.find((k) => k.status === 'ACTIVE');
    if (!activeKey) return { updated: [], flagged: [] };
    const activeSecret = Buffer.from(activeKey.secret, 'base64');

    // Filter to stale rows in the query itself — the retirement guard calls
    // this hourly per org, so fetching already-current rows would be a
    // recurring full-org scan. Null macKeyVersion (legacy rows) needs its own
    // branch: Prisma's `not` comparison excludes NULLs.
    const rows = await this.prisma.qRCode.findMany({
      where: {
        organizationId,
        status: 'ACTIVE',
        macTokenMac: { not: null },
        OR: [
          { macKeyVersion: null },
          { macKeyVersion: { not: activeKey.version } },
        ],
      },
    });

    const updated: RemacRowResult[] = [];
    const flagged: RemacRowResult[] = [];
    for (const row of rows) {
      if (row.macKeyVersion === activeKey.version) continue;

      const canonical = await buildQrCanonicalCore(row);
      const originalKey = keys.find((k) => k.version === row.macKeyVersion);
      let oldMacCheck: RemacOldMacCheck = 'key_unavailable';
      if (originalKey) {
        const expected = computeMac(canonical, Buffer.from(originalKey.secret, 'base64'));
        oldMacCheck = macsEqual(expected, row.macTokenMac!) ? 'verified' : 'mismatch';
      }

      const result: RemacRowResult = {
        token: row.token,
        fromVersion: row.macKeyVersion,
        toVersion: activeKey.version,
        oldMacCheck,
      };
      if (oldMacCheck === 'mismatch') {
        flagged.push(result);
        continue;
      }

      if (!opts.dryRun) {
        await this.prisma.qRCode.update({
          where: { id: row.id },
          data: {
            macTokenMac: computeMac(canonical, activeSecret),
            macKeyVersion: activeKey.version,
          },
        });
      }
      updated.push(result);
    }
    return { updated, flagged };
  }
}
