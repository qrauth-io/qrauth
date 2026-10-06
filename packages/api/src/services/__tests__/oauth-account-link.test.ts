import { describe, it, expect } from 'vitest';
import type { AuthProvider } from '@prisma/client';
import { resolveOAuthAccount, escapeLikePattern } from '../oauth-account-link.js';
import type { OAuthUser } from '../../lib/oauth.js';

/**
 * Linking policy (nOAuth fix) against an in-memory user table that mimics the
 * two Prisma queries resolveOAuthAccount issues — including that Prisma turns
 * `equals` + `mode: 'insensitive'` into a Postgres ILIKE (wildcards `_` `%`,
 * backslash escape), verified against Postgres 16.
 */

function ilike(value: string, pattern: string): boolean {
  const lit = (c: string) => c.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  let re = '';
  for (let i = 0; i < pattern.length; i++) {
    const c = pattern[i];
    if (c === '\\') re += lit(pattern[++i] ?? '');
    else if (c === '%') re += '.*';
    else if (c === '_') re += '.';
    else re += lit(c);
  }
  return new RegExp(`^${re}$`, 'is').test(value);
}

interface Row { id: string; email: string; provider: AuthProvider; providerId: string | null; createdAt: number }

function fakeDb(rows: Row[]) {
  return {
    user: {
      findFirst: async ({ where }: { where: { provider: AuthProvider; providerId: string } }) =>
        rows.find((r) => r.provider === where.provider && r.providerId === where.providerId) ?? null,
      findMany: async ({ where, take }: { where: { email: { equals: string } }; take: number }) =>
        rows
          .filter((r) => ilike(r.email, where.email.equals))
          .sort((a, b) => a.createdAt - b.createdAt)
          .slice(0, take)
          .map((r) => ({ id: r.id, email: r.email, providerId: r.providerId })),
    },
  } as never;
}

const victim: Row = { id: 'u_victim', email: 'victim@corp.example', provider: 'EMAIL', providerId: null, createdAt: 1 };
const googleUser: Row = { id: 'u_google', email: 'g@example.com', provider: 'GOOGLE', providerId: 'g-1', createdAt: 2 };
const msUser: Row = { id: 'u_ms', email: 'ms@contoso.example', provider: 'MICROSOFT', providerId: 'oid-ms', createdAt: 3 };

function identity(overrides: Partial<OAuthUser>): OAuthUser {
  return { providerId: 'p-new', email: 'new@example.com', emailVerified: true, name: 'N', ...overrides };
}

describe('resolveOAuthAccount', () => {
  it('TAKEOVER: refuses an unverified email matching an existing account and never links it', async () => {
    const db = fakeDb([victim]);
    const result = await resolveOAuthAccount(db, 'MICROSOFT', identity({
      providerId: 'attacker-oid', email: 'victim@corp.example', emailVerified: false,
    }));
    expect(result).toEqual({ kind: 'refuse', reason: 'unverified_email_existing_account', userId: 'u_victim' });
  });

  it('TAKEOVER: case variants of an unverified email are refused too', async () => {
    const result = await resolveOAuthAccount(fakeDb([victim]), 'MICROSOFT', identity({
      providerId: 'attacker-oid', email: 'VICTIM@Corp.Example', emailVerified: false,
    }));
    expect(result).toMatchObject({ kind: 'refuse', reason: 'unverified_email_existing_account' });
  });

  it('(provider, providerId) wins over email', async () => {
    // The returning Microsoft user signs in by oid even though the token email
    // is unverified and happens to equal another account's email.
    const result = await resolveOAuthAccount(fakeDb([victim, msUser]), 'MICROSOFT', identity({
      providerId: 'oid-ms', email: 'victim@corp.example', emailVerified: false,
    }));
    expect(result).toEqual({ kind: 'signin', userId: 'u_ms', via: 'providerId' });
  });

  it('providerId match is scoped to the provider', async () => {
    const result = await resolveOAuthAccount(fakeDb([googleUser]), 'GITHUB', identity({
      providerId: 'g-1', email: 'unrelated@example.com', emailVerified: false,
    }));
    expect(result).toEqual({ kind: 'refuse', reason: 'unverified_email_new_account' });
  });

  it('links a verified email (case-insensitive) and links the provider only if none is set', async () => {
    await expect(resolveOAuthAccount(fakeDb([victim]), 'GOOGLE', identity({
      providerId: 'g-new', email: 'Victim@Corp.example', emailVerified: true,
    }))).resolves.toEqual({ kind: 'signin', userId: 'u_victim', via: 'verifiedEmail', linkProvider: true });

    await expect(resolveOAuthAccount(fakeDb([googleUser]), 'GITHUB', identity({
      providerId: 'gh-7', email: 'g@example.com', emailVerified: true,
    }))).resolves.toEqual({ kind: 'signin', userId: 'u_google', via: 'verifiedEmail', linkProvider: false });
  });

  it('refuses a verified email that matches two case-variant accounts', async () => {
    const twin: Row = { ...victim, id: 'u_twin', email: 'Victim@corp.example', createdAt: 5 };
    const result = await resolveOAuthAccount(fakeDb([victim, twin]), 'GOOGLE', identity({
      email: 'victim@corp.example', emailVerified: true,
    }));
    expect(result).toEqual({ kind: 'refuse', reason: 'ambiguous_email' });
  });

  it('creates a new account only for a verified email', async () => {
    await expect(resolveOAuthAccount(fakeDb([]), 'GOOGLE', identity({ emailVerified: true })))
      .resolves.toEqual({ kind: 'create', email: 'new@example.com', emailVerified: true, via: 'verifiedEmail' });
    await expect(resolveOAuthAccount(fakeDb([]), 'MICROSOFT', identity({ emailVerified: false })))
      .resolves.toEqual({ kind: 'refuse', reason: 'unverified_email_new_account' });
  });

  it('LIKE wildcards in a verified email never match another account', async () => {
    const john: Row = { id: 'u_john', email: 'john@outlook.example', provider: 'EMAIL', providerId: null, createdAt: 1 };
    for (const email of ['j_hn@outlook.example', '%@outlook.example', 'JOH_@outlook.example']) {
      await expect(resolveOAuthAccount(fakeDb([john]), 'GITHUB', identity({ email, emailVerified: true })))
        .resolves.toEqual({ kind: 'create', email, emailVerified: true, via: 'verifiedEmail' });
    }
  });

  it('an email that really contains _ or % still matches itself', async () => {
    const jane: Row = { id: 'u_jane', email: 'jane_doe%1@example.com', provider: 'EMAIL', providerId: null, createdAt: 1 };
    await expect(resolveOAuthAccount(fakeDb([jane]), 'GOOGLE', identity({ email: 'Jane_Doe%1@example.com', emailVerified: true })))
      .resolves.toMatchObject({ kind: 'signin', userId: 'u_jane', via: 'verifiedEmail' });
  });

  it('escapeLikePattern escapes backslash, percent and underscore', () => {
    expect(escapeLikePattern('a_b%c\\d')).toBe('a\\_b\\%c\\\\d');
  });

  it('refuses when the provider returned no email', async () => {
    await expect(resolveOAuthAccount(fakeDb([victim]), 'GITHUB', identity({ email: '', emailVerified: false })))
      .resolves.toEqual({ kind: 'refuse', reason: 'missing_email' });
  });
});

describe('resolveOAuthAccount — Microsoft identity without an email claim (sign-in name)', () => {
  const noEmail = (overrides: Partial<OAuthUser>) =>
    identity({ providerId: 'oid-new', email: '', emailVerified: false, ...overrides });

  it('creates a new, UNVERIFIED account from a clean sign-in name', async () => {
    const result = await resolveOAuthAccount(fakeDb([victim]), 'MICROSOFT', noEmail({
      signInName: 'reviewer@contoso.onmicrosoft.com',
    }));
    expect(result).toEqual({
      kind: 'create', email: 'reviewer@contoso.onmicrosoft.com', emailVerified: false, via: 'signInName',
    });
  });

  it('TAKEOVER: a sign-in name matching an existing account is refused and never linked', async () => {
    for (const signInName of ['victim@corp.example', 'VICTIM@Corp.Example']) {
      const result = await resolveOAuthAccount(fakeDb([victim]), 'MICROSOFT', noEmail({
        providerId: 'attacker-oid', signInName,
      }));
      expect(result).toEqual({ kind: 'refuse', reason: 'sign_in_name_existing_account', userId: 'u_victim' });
    }
  });

  it('TAKEOVER: LIKE wildcards in a sign-in name are refused only for a real match, never treated as one', async () => {
    const john: Row = { id: 'u_john', email: 'john@contoso.example', provider: 'EMAIL', providerId: null, createdAt: 1 };
    const result = await resolveOAuthAccount(fakeDb([john]), 'MICROSOFT', noEmail({ signInName: 'j_hn@contoso.example' }));
    expect(result).toEqual({ kind: 'create', email: 'j_hn@contoso.example', emailVerified: false, via: 'signInName' });
  });

  it('refuses when there is neither an email nor a usable sign-in name', async () => {
    await expect(resolveOAuthAccount(fakeDb([]), 'MICROSOFT', noEmail({})))
      .resolves.toEqual({ kind: 'refuse', reason: 'missing_email' });
  });

  it('never applies the sign-in name for a personal Microsoft account', async () => {
    await expect(resolveOAuthAccount(fakeDb([]), 'MICROSOFT', noEmail({
      signInName: 'someone@outlook.com', personalMicrosoftAccount: true,
    }))).resolves.toEqual({ kind: 'refuse', reason: 'missing_email' });
  });

  it('never creates an account from a sign-in name that is a platform admin address', async () => {
    const before = process.env.ADMIN_EMAILS;
    process.env.ADMIN_EMAILS = 'root@qrauth.example, Ops@qrauth.example';
    try {
      for (const signInName of ['root@qrauth.example', 'ops@QRAUTH.example']) {
        await expect(resolveOAuthAccount(fakeDb([]), 'MICROSOFT', noEmail({ signInName })))
          .resolves.toEqual({ kind: 'refuse', reason: 'missing_email' });
      }
    } finally {
      if (before === undefined) delete process.env.ADMIN_EMAILS;
      else process.env.ADMIN_EMAILS = before;
    }
  });

  it('never applies the sign-in name for another provider', async () => {
    await expect(resolveOAuthAccount(fakeDb([]), 'GITHUB', noEmail({ signInName: 'someone@example.com' })))
      .resolves.toEqual({ kind: 'refuse', reason: 'missing_email' });
  });

  it('an email claim, even unverified, is never replaced by the sign-in name', async () => {
    await expect(resolveOAuthAccount(fakeDb([]), 'MICROSOFT', identity({
      email: 'someone@unverified.example', emailVerified: false, signInName: 'someone@contoso.onmicrosoft.com',
    }))).resolves.toEqual({ kind: 'refuse', reason: 'unverified_email_new_account' });
  });

  it('a returning user is found by oid whatever the claims say', async () => {
    const created: Row = { id: 'u_upn', email: 'reviewer@contoso.onmicrosoft.com', provider: 'MICROSOFT', providerId: 'oid-upn', createdAt: 9 };
    const db = fakeDb([victim, created]);
    const variants: Partial<OAuthUser>[] = [
      { signInName: 'reviewer@contoso.onmicrosoft.com' },
      { signInName: 'renamed@contoso.onmicrosoft.com' },
      { signInName: 'victim@corp.example' },
      {},
      { email: 'victim@corp.example', emailVerified: false },
    ];
    for (const claims of variants) {
      await expect(resolveOAuthAccount(db, 'MICROSOFT', noEmail({ providerId: 'oid-upn', ...claims })))
        .resolves.toEqual({ kind: 'signin', userId: 'u_upn', via: 'providerId' });
    }
  });
});
