import { describe, it, expect, beforeAll } from 'vitest';
import { createHmac } from 'node:crypto';

/**
 * Audit-4 A4-M1: Verify HKDF-based frame secret derivation properties.
 */
describe('AnimatedQRService.deriveFrameSecret (HKDF)', () => {
  let service: any;

  beforeAll(async () => {
    // Set required env vars so config.ts doesn't throw
    process.env.DATABASE_URL = 'postgresql://test:test@localhost:5432/test';
    process.env.REDIS_URL = 'redis://localhost:6379';
    process.env.JWT_SECRET = 'a'.repeat(32);
    process.env.ANIMATED_QR_SECRET = 'a'.repeat(64); // 256-bit hex
    // Dynamic import so the constructor reads our env
    const mod = await import('../animated-qr.js');
    service = new mod.AnimatedQRService();
  });

  it('produces a 64-character hex string (256 bits)', () => {
    const secret = service.deriveFrameSecret('test-session-id');
    expect(secret).toMatch(/^[0-9a-f]{64}$/);
  });

  it('is deterministic for the same session identifier', () => {
    const a = service.deriveFrameSecret('session-123');
    const b = service.deriveFrameSecret('session-123');
    expect(a).toBe(b);
  });

  it('produces different secrets for different session identifiers', () => {
    const a = service.deriveFrameSecret('session-aaa');
    const b = service.deriveFrameSecret('session-bbb');
    expect(a).not.toBe(b);
  });

  it('produces different output than the old HMAC-based derivation', () => {
    // The old method: HMAC-SHA256(serverSecret, "frame_secret:" + sessionId)
    const oldSecret = createHmac('sha256', process.env.ANIMATED_QR_SECRET!)
      .update('frame_secret:migration-check')
      .digest('hex');
    const newSecret = service.deriveFrameSecret('migration-check');

    // Must differ — confirms HKDF produces different output than raw HMAC
    expect(newSecret).not.toBe(oldSecret);
  });
});
