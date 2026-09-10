import { describe, it, expect } from 'vitest';
import { createOidcClientSchema, updateOidcClientSchema } from '../oidc-clients.js';

// Validation matrix for the self-serve OIDC client routes (ADR-0004 D4).
// The redirect-URI policy mirrors the schema comment on
// OidcClient.redirectUris: exact absolute URIs, https: required except
// localhost/127.0.0.1 loopback, no fragments, no wildcards. Scopes are capped
// to the hardcoded SELF_SERVE_ALLOWED_SCOPES, never the discovery document.

const validBody = {
  name: 'Acme Sign-In',
  redirectUris: ['https://app.acme.example/callback'],
  clientType: 'confidential',
};

describe('createOidcClientSchema — redirect URIs', () => {
  it('accepts an https redirect URI', () => {
    expect(createOidcClientSchema.safeParse(validBody).success).toBe(true);
  });

  it('accepts http loopback on localhost with a port and path', () => {
    const result = createOidcClientSchema.safeParse({
      ...validBody,
      redirectUris: ['http://localhost:8080/cb'],
    });
    expect(result.success).toBe(true);
  });

  it('accepts http loopback on 127.0.0.1', () => {
    const result = createOidcClientSchema.safeParse({
      ...validBody,
      redirectUris: ['http://127.0.0.1/cb'],
    });
    expect(result.success).toBe(true);
  });

  it('rejects plain http on a non-loopback host', () => {
    const result = createOidcClientSchema.safeParse({
      ...validBody,
      redirectUris: ['http://app.acme.example/callback'],
    });
    expect(result.success).toBe(false);
  });

  it('rejects a URI with a fragment', () => {
    const result = createOidcClientSchema.safeParse({
      ...validBody,
      redirectUris: ['https://app.acme.example/callback#frag'],
    });
    expect(result.success).toBe(false);
  });

  it('rejects wildcards', () => {
    const result = createOidcClientSchema.safeParse({
      ...validBody,
      redirectUris: ['https://*.acme.example/callback'],
    });
    expect(result.success).toBe(false);
  });

  it('rejects a relative URI', () => {
    const result = createOidcClientSchema.safeParse({
      ...validBody,
      redirectUris: ['/callback'],
    });
    expect(result.success).toBe(false);
  });

  it('rejects an empty redirectUris array', () => {
    const result = createOidcClientSchema.safeParse({ ...validBody, redirectUris: [] });
    expect(result.success).toBe(false);
  });

  it('rejects more than 10 redirect URIs', () => {
    const redirectUris = Array.from(
      { length: 11 },
      (_, i) => `https://app.acme.example/cb/${i}`,
    );
    const result = createOidcClientSchema.safeParse({ ...validBody, redirectUris });
    expect(result.success).toBe(false);
  });
});

describe('createOidcClientSchema — scopes', () => {
  it('defaults allowedScopes to ["openid"]', () => {
    const result = createOidcClientSchema.safeParse(validBody);
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.allowedScopes).toEqual(['openid']);
    }
  });

  it('accepts the full self-serve allowlist', () => {
    const result = createOidcClientSchema.safeParse({
      ...validBody,
      allowedScopes: ['openid', 'profile', 'email', 'offline_access', 'qrauth:auth_method'],
    });
    expect(result.success).toBe(true);
  });

  it('rejects scopes missing openid', () => {
    const result = createOidcClientSchema.safeParse({
      ...validBody,
      allowedScopes: ['profile', 'email'],
    });
    expect(result.success).toBe(false);
  });

  it('rejects advertised-but-not-emitted qrauth scopes (device_trust etc.)', () => {
    for (const scope of ['qrauth:device_trust', 'qrauth:proximity', 'qrauth:fraud_signals']) {
      const result = createOidcClientSchema.safeParse({
        ...validBody,
        allowedScopes: ['openid', scope],
      });
      expect(result.success).toBe(false);
    }
  });
});

describe('createOidcClientSchema — other fields', () => {
  it('defaults idTokenSignedResponseAlg to RS256', () => {
    const result = createOidcClientSchema.safeParse(validBody);
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.idTokenSignedResponseAlg).toBe('RS256');
    }
  });

  it('accepts ES256 as an explicit opt-in', () => {
    const result = createOidcClientSchema.safeParse({
      ...validBody,
      idTokenSignedResponseAlg: 'ES256',
    });
    expect(result.success).toBe(true);
  });

  it('requires clientType', () => {
    const { clientType: _omitted, ...withoutType } = validBody;
    expect(createOidcClientSchema.safeParse(withoutType).success).toBe(false);
  });

  it('rejects an http sectorIdentifierUri', () => {
    const result = createOidcClientSchema.safeParse({
      ...validBody,
      sectorIdentifierUri: 'http://acme.example/sector.json',
    });
    expect(result.success).toBe(false);
  });

  it('accepts an https sectorIdentifierUri', () => {
    const result = createOidcClientSchema.safeParse({
      ...validBody,
      sectorIdentifierUri: 'https://acme.example/sector.json',
    });
    expect(result.success).toBe(true);
  });

  it('rejects attempts to set tier (strict object)', () => {
    const result = createOidcClientSchema.safeParse({ ...validBody, tier: 'FIRST_PARTY' });
    expect(result.success).toBe(false);
  });
});

describe('FINDING-004 — input normalization', () => {
  it('rejects duplicate allowedScopes (no silent dedupe)', () => {
    const result = createOidcClientSchema.safeParse({
      ...validBody,
      allowedScopes: ['openid', 'profile', 'openid'],
    });
    expect(result.success).toBe(false);
  });

  it('accepts distinct allowedScopes', () => {
    const result = createOidcClientSchema.safeParse({
      ...validBody,
      allowedScopes: ['openid', 'profile'],
    });
    expect(result.success).toBe(true);
  });

  it('rejects duplicate redirectUris (exact string comparison)', () => {
    const result = createOidcClientSchema.safeParse({
      ...validBody,
      redirectUris: ['https://app.acme.example/callback', 'https://app.acme.example/callback'],
    });
    expect(result.success).toBe(false);
  });

  it('treats differently-cased redirect URIs as distinct (no normalization)', () => {
    const result = createOidcClientSchema.safeParse({
      ...validBody,
      redirectUris: ['https://app.acme.example/callback', 'https://app.acme.example/Callback'],
    });
    expect(result.success).toBe(true);
  });

  it('rejects redirect URIs carrying credentials', () => {
    for (const uri of [
      'https://user:pass@app.acme.example/callback',
      'https://user@app.acme.example/callback',
    ]) {
      const result = createOidcClientSchema.safeParse({ ...validBody, redirectUris: [uri] });
      expect(result.success).toBe(false);
    }
  });

  it('applies all three rules to PATCH via the shared schemas', () => {
    expect(
      updateOidcClientSchema.safeParse({ allowedScopes: ['openid', 'openid'] }).success,
    ).toBe(false);
    expect(
      updateOidcClientSchema.safeParse({
        redirectUris: ['https://a.example/cb', 'https://a.example/cb'],
      }).success,
    ).toBe(false);
    expect(
      updateOidcClientSchema.safeParse({
        redirectUris: ['https://user:pass@a.example/cb'],
      }).success,
    ).toBe(false);
    expect(
      updateOidcClientSchema.safeParse({
        redirectUris: ['https://a.example/cb', 'https://b.example/cb'],
      }).success,
    ).toBe(true);
  });
});

describe('updateOidcClientSchema', () => {
  it('accepts a partial update of mutable fields', () => {
    const result = updateOidcClientSchema.safeParse({
      name: 'Renamed',
      redirectUris: ['https://app.acme.example/cb2'],
    });
    expect(result.success).toBe(true);
  });

  it('allows clearing sectorIdentifierUri with null', () => {
    expect(updateOidcClientSchema.safeParse({ sectorIdentifierUri: null }).success).toBe(true);
  });

  it('rejects an empty body', () => {
    expect(updateOidcClientSchema.safeParse({}).success).toBe(false);
  });

  it('rejects immutable fields: clientId, tier, clientType', () => {
    expect(updateOidcClientSchema.safeParse({ clientId: 'x' }).success).toBe(false);
    expect(updateOidcClientSchema.safeParse({ tier: 'PUBLIC' }).success).toBe(false);
    expect(updateOidcClientSchema.safeParse({ clientType: 'public' }).success).toBe(false);
  });

  it('applies the same redirect URI policy as create', () => {
    const result = updateOidcClientSchema.safeParse({
      redirectUris: ['http://app.acme.example/cb'],
    });
    expect(result.success).toBe(false);
  });

  it('applies the same scope allowlist as create', () => {
    const result = updateOidcClientSchema.safeParse({
      allowedScopes: ['openid', 'qrauth:fraud_signals'],
    });
    expect(result.success).toBe(false);
  });
});
