import { createHmac, randomBytes } from 'node:crypto';
import { cacheSet, cacheGet } from '../lib/cache.js';

/**
 * Service for animated QR frame secret management and validation.
 */
export class AnimatedQRService {
  /**
   * Server-side HMAC secret for deriving per-session frame secrets.
   * Falls back to a random key if ANIMATED_QR_SECRET env var is not set.
   */
  private readonly serverSecret: string;

  constructor() {
    this.serverSecret = process.env.ANIMATED_QR_SECRET || randomBytes(32).toString('hex');
  }

  /**
   * Derive a per-session frame secret from the server secret + session identifier.
   * The client receives this to generate frame HMACs locally.
   */
  deriveFrameSecret(sessionIdentifier: string): string {
    return createHmac('sha256', this.serverSecret)
      .update(`frame_secret:${sessionIdentifier}`)
      .digest('hex');
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

    // 3. Constant-time comparison
    if (hmac.length !== expectedHmac.length) {
      return { valid: false, reason: 'Invalid HMAC' };
    }

    let mismatch = 0;
    for (let i = 0; i < hmac.length; i++) {
      mismatch |= hmac.charCodeAt(i) ^ expectedHmac.charCodeAt(i);
    }

    if (mismatch !== 0) {
      return { valid: false, reason: 'Invalid HMAC' };
    }

    return { valid: true };
  }

  /**
   * Track frame indices to prevent replay attacks.
   * Stores the highest seen frame index per session.
   */
  async checkReplay(sessionIdentifier: string, frameIndex: number): Promise<boolean> {
    const key = `animated_qr:last_frame:${sessionIdentifier}`;
    const lastFrame = await cacheGet<number>(key);

    if (lastFrame !== null && lastFrame !== undefined && frameIndex <= lastFrame) {
      return false; // Replay detected
    }

    // Store the new highest frame index (TTL: 10 minutes)
    await cacheSet(key, frameIndex, 600);
    return true;
  }
}
