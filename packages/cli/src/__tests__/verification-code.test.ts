import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import { deriveCliVerificationCode, CLI_VERIFICATION_CODE_DOMAIN } from '@qrauth/shared';

/**
 * The CLI and the API both call the SAME shared function to show the user the
 * verification code. These tests pin that the shared (Web Crypto, async) output
 * is byte-identical to a Node `createHash` digest — i.e. the code the CLI
 * prints will always equal the code the API renders on the approval page.
 */
describe('deriveCliVerificationCode (single source for CLI + API)', () => {
  it('reproduces the SHA-256 derivation the API uses', async () => {
    const sessionId = 'clxsession_abc123';
    const hex = createHash('sha256')
      .update(CLI_VERIFICATION_CODE_DOMAIN + sessionId, 'utf8')
      .digest('hex');
    const slice = hex.slice(0, 8).toUpperCase();
    const expected = `${slice.slice(0, 4)}-${slice.slice(4, 8)}`;
    expect(await deriveCliVerificationCode(sessionId)).toBe(expected);
  });

  it('formats as XXXX-XXXX and is deterministic', async () => {
    expect(await deriveCliVerificationCode('s1')).toMatch(/^[0-9A-F]{4}-[0-9A-F]{4}$/);
    expect(await deriveCliVerificationCode('s1')).toBe(await deriveCliVerificationCode('s1'));
    expect(await deriveCliVerificationCode('s1')).not.toBe(await deriveCliVerificationCode('s2'));
  });
});
