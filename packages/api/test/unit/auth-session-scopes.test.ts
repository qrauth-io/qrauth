import { describe, it, expect } from 'vitest';
import { createAuthSessionSchema } from '@qrauth/shared';

/**
 * ADR-0002: the qrauth-cli app's allowedScopes is ['cli'], so the create-session
 * schema must accept 'cli' — otherwise `qrauth login` 400s before approve.
 */
describe('createAuthSessionSchema scopes', () => {
  it('accepts the first-party cli scope', () => {
    const parsed = createAuthSessionSchema.parse({ scopes: ['cli'], codeChallengeMethod: 'S256' });
    expect(parsed.scopes).toEqual(['cli']);
  });

  it('still accepts the federation scopes', () => {
    expect(createAuthSessionSchema.parse({ scopes: ['identity', 'email'] }).scopes).toEqual(['identity', 'email']);
  });

  it('rejects an unknown scope', () => {
    expect(() => createAuthSessionSchema.parse({ scopes: ['admin'] })).toThrow();
  });

  it('defaults to identity when scopes are omitted', () => {
    expect(createAuthSessionSchema.parse({}).scopes).toEqual(['identity']);
  });
});
