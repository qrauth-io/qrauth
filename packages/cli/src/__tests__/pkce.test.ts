import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import { generatePkce } from '../pkce.js';

describe('generatePkce', () => {
  it('produces a base64url verifier and a matching S256 challenge', () => {
    const { codeVerifier, codeChallenge } = generatePkce();
    expect(codeVerifier).toMatch(/^[A-Za-z0-9_-]+$/);
    // Must match what the server computes in verifyCodeChallenge.
    const expected = createHash('sha256').update(codeVerifier, 'ascii').digest('base64url');
    expect(codeChallenge).toBe(expected);
  });

  it('is unique per call', () => {
    expect(generatePkce().codeVerifier).not.toBe(generatePkce().codeVerifier);
  });
});
