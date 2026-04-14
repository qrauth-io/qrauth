import { createHmac, timingSafeEqual } from 'node:crypto';
import type { OrgMacKey, PrismaClient } from '@prisma/client';
import { generateSecureEntropy } from '../lib/entropy.js';

/**
 * Symmetric MAC fast path (ALGORITHM.md §7).
 *
 * For every issued QR we compute an HMAC-SHA3-256 over the canonical payload
 * using the issuing organization's secret. The MAC is stored on the QRCode
 * row server-side and NEVER embedded in the QR image or the verify URL —
 * an adversary who scrapes the URL learns nothing about the MAC.
 *
 * At verify time the route recomputes the MAC and compares it constant-time.
 * On match the QR is server-authentic and the verifier can short-circuit
 * before touching the ECDSA + SLH-DSA legs. On mismatch (or missing MAC,
 * which happens for legacy rows or during key rotation) the verifier falls
 * through to the asymmetric legs which remain authoritative — the MAC is
 * additive, not a replacement.
 *
 * Key ring:
 *   - One ACTIVE OrgMacKey per organization at any time.
 *   - On rotation the previous ACTIVE row flips to ROTATED and stays around
 *     for a 30-day grace window (long enough for in-flight QRs to verify).
 *   - After grace it is marked RETIRED and pruned by a cleanup worker.
 *   - Verification tries the version stored on the QRCode row first; if that
 *     row is missing it tries ACTIVE → ROTATED in order.
 */

export const MAC_ALGORITHM = 'hmac-sha3-256' as const;
export const MAC_KEY_BYTES = 32; // 256-bit secret per NIST SP 800-107

export interface MacComputation {
  mac: string;          // hex
  keyVersion: number;
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
}
