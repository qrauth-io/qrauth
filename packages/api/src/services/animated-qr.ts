import { createHmac, hkdfSync, randomBytes } from 'node:crypto';
import { cacheSet, cacheGet } from '../lib/cache.js';
import { constantTimeEqualString } from '../lib/constant-time.js';

/**
 * Service for animated QR frame secret management and validation.
 */
export class AnimatedQRService {
  /**
   * Server-side HMAC secret for deriving per-session frame secrets.
   *
   * AUDIT-FINDING-004: in production this MUST come from
   * `ANIMATED_QR_SECRET`. The silent per-process random fallback only
   * survives in `test` and `development` — on a multi-pod deployment the
   * random fallback produces session HMACs that validate on the issuing
   * pod but not on neighbours, surfacing as intermittent "Invalid HMAC"
   * responses that look indistinguishable from replay attempts.
   *
   * AUDIT-FINDING-013: migrate to HMAC-SHA3-256 at next animated-qr protocol version bump.
   */
  private readonly serverSecret: string;

  constructor() {
    const fromEnv = process.env.ANIMATED_QR_SECRET;

    if (!fromEnv) {
      throw new Error(
        'ANIMATED_QR_SECRET is required. Generate with `openssl rand -hex 32` ' +
        'and add to your .env file. See Audit-4 A4-L3.',
      );
    }

    if (fromEnv.length < 32) {
      throw new Error(
        'ANIMATED_QR_SECRET must be at least 32 characters (16 bytes hex). ' +
        `Got ${fromEnv.length} characters. Generate with \`openssl rand -hex 32\`. ` +
        'See Audit-3 H-4.',
      );
    }

    this.serverSecret = fromEnv;
  }

  /**
   * Derive a per-session frame secret from the server secret + session identifier.
   * The client receives this to generate frame HMACs locally.
   *
   * Uses HKDF-SHA256 (RFC 5869) with:
   *   - IKM: the server secret (ANIMATED_QR_SECRET, >= 256 bits)
   *   - salt: domain separator "qrauth:animated-qr:v1" (prevents cross-protocol reuse)
   *   - info: "frame_secret:" + sessionIdentifier (binds output to this session)
   *   - L: 32 bytes (256 bits)
   *
   * Audit-4 A4-M1: replaces plain HMAC-SHA256 KDF which lacked salt and formal
   * domain separation.
   */
  deriveFrameSecret(sessionIdentifier: string): string {
    const okm = hkdfSync(
      'sha256',
      this.serverSecret,
      'qrauth:animated-qr:v1',                // salt (domain separator)
      `frame_secret:${sessionIdentifier}`,     // info (session binding)
      32,                                      // 256-bit output
    );
    return Buffer.from(okm).toString('hex');
  }

  /**
   * Validate a scanned animated QR frame.
   *
   * @param baseUrl - The base verification URL (e.g., "https://qrauth.io/v/TOKEN")
   * @param frameIndex - Frame index from the scanned URL
   * @param timestamp - Timestamp from the scanned URL (ms)
   * @param hmac - HMAC from the scanned URL (first 16 hex chars)
   * @param sessionIdentifier - Session ID to re-derive the frame secret
   * @returns Validation result with details
   */
  validateFrame(
    baseUrl: string,
    frameIndex: number,
    timestamp: number,
    hmac: string,
    sessionIdentifier: string,
  ): { valid: boolean; reason?: string } {
    // 1. Check timestamp freshness (allow 5 second window for scanning delay)
    const now = Date.now();
    const age = now - timestamp;
    if (age < -2000) {
      return { valid: false, reason: 'Frame timestamp is in the future' };
    }
    if (age > 5000) {
      return { valid: false, reason: 'Frame expired (older than 5 seconds)' };
    }

    // 2. Recompute HMAC
    const frameSecret = this.deriveFrameSecret(sessionIdentifier);
    const message = `${baseUrl}:${timestamp}:${frameIndex}`;
    const expectedHmac = createHmac('sha256', Buffer.from(frameSecret, 'hex'))
      .update(message)
      .digest('hex')
      .slice(0, 16); // First 16 hex chars

    // 3. Constant-time comparison (AUDIT-FINDING-012: replaces the
    //    hand-rolled per-char XOR with `crypto.timingSafeEqual` via the
    //    repository-wide constant-time helper).
    if (!constantTimeEqualString(hmac, expectedHmac)) {
      return { valid: false, reason: 'Invalid HMAC' };
    }

    return { valid: true };
  }

  /**
   * Track frame indices to prevent replay attacks.
   * Stores the highest seen frame index per session.
   *
   * AUDIT-FINDING-014: fail closed on cache backend errors. If Redis is
   * unavailable we cannot tell whether a frame was previously seen, so
   * we reject the frame. "No prior entry" is a separate state returned
   * by `cacheGet` as `null`, not as a thrown error — the distinction
   * matters because the first scan of a session must still succeed.
   */
  async checkReplay(sessionIdentifier: string, frameIndex: number): Promise<boolean> {
    const key = `animated_qr:last_frame:${sessionIdentifier}`;

    let lastFrame: number | null;
    try {
      lastFrame = await cacheGet<number>(key);
    } catch {
      // Cache backend error — reject the frame. Replay protection
      // cannot be established without a working store, and returning
      // `true` would silently disable it for the duration of the
      // outage.
      return false;
    }

    if (lastFrame !== null && lastFrame !== undefined && frameIndex <= lastFrame) {
      return false; // Replay detected
    }

    // Store the new highest frame index (TTL: 10 minutes). A failure
    // here also fails closed — we cannot persist the high-water mark,
    // so we cannot guarantee replay protection for the next frame.
    try {
      await cacheSet(key, frameIndex, 600);
    } catch {
      return false;
    }
    return true;
  }
}
