import { describe, it, expect } from 'vitest';
import type { PrismaClient } from '@prisma/client';
import { deriveAuthMethod } from '../oidc-auth-method.js';

/**
 * deriveAuthMethod (ADR-0003 Slice 4) — read-only mapping from the user's
 * underlying dashboard auth to acr / amr / qrauth:auth_method.
 */

interface LoginRow {
  userId: string;
  success: boolean;
  provider: string;
  createdAt: Date;
}

const REF = new Date('2026-06-01T12:00:00Z');

/**
 * Minimal in-memory fake of the two prisma delegates deriveAuthMethod reads.
 * loginEvent.findFirst applies the same userId/success/createdAt-window filter
 * + newest-first ordering as production.
 */
function makeFakePrisma(opts: { logins?: LoginRow[]; userProvider?: string }) {
  const logins = opts.logins ?? [];
  return {
    loginEvent: {
      async findFirst({
        where,
      }: {
        where: { userId: string; success: boolean; createdAt: { gte: Date; lte: Date } };
      }) {
        const matches = logins
          .filter(
            (l) =>
              l.userId === where.userId &&
              l.success === where.success &&
              l.createdAt >= where.createdAt.gte &&
              l.createdAt <= where.createdAt.lte,
          )
          .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
        return matches[0] ?? null;
      },
    },
    user: {
      async findUnique() {
        return opts.userProvider ? { provider: opts.userProvider } : null;
      },
    },
  } as unknown as PrismaClient;
}

describe('deriveAuthMethod', () => {
  it('maps a recent passkey login to hwk', async () => {
    const prisma = makeFakePrisma({
      logins: [{ userId: 'u1', success: true, provider: 'PASSKEY', createdAt: new Date('2026-06-01T09:00:00Z') }],
      userProvider: 'EMAIL',
    });
    const ctx = await deriveAuthMethod(prisma, 'u1', REF);
    expect(ctx.qrauthAuthMethod).toBe('passkey');
    expect(ctx.acr).toBe('qrauth:living-code+passkey');
    expect(ctx.amr).toEqual(['qrauth-living-code', 'hwk']);
  });

  it('prefers a recent passkey login over a federated User.provider', async () => {
    const prisma = makeFakePrisma({
      logins: [{ userId: 'u1', success: true, provider: 'PASSKEY', createdAt: new Date('2026-06-01T09:00:00Z') }],
      userProvider: 'GOOGLE',
    });
    expect((await deriveAuthMethod(prisma, 'u1', REF)).qrauthAuthMethod).toBe('passkey');
  });

  it('maps a federated User.provider (no passkey login) to fed', async () => {
    const prisma = makeFakePrisma({ logins: [], userProvider: 'GOOGLE' });
    const ctx = await deriveAuthMethod(prisma, 'u1', REF);
    expect(ctx.qrauthAuthMethod).toBe('oauth_upstream');
    expect(ctx.acr).toBe('qrauth:living-code+oauth_upstream');
    expect(ctx.amr).toEqual(['qrauth-living-code', 'fed']);
  });

  it('falls back to the base qr_living_code for EMAIL/password logins', async () => {
    const prisma = makeFakePrisma({
      logins: [{ userId: 'u1', success: true, provider: 'EMAIL', createdAt: new Date('2026-06-01T11:00:00Z') }],
      userProvider: 'EMAIL',
    });
    const ctx = await deriveAuthMethod(prisma, 'u1', REF);
    expect(ctx.qrauthAuthMethod).toBe('qr_living_code');
    expect(ctx.acr).toBe('qrauth:living-code');
    expect(ctx.amr).toEqual(['qrauth-living-code']);
  });

  it('falls back to the base when there is no recent login and no federated provider', async () => {
    const prisma = makeFakePrisma({ logins: [], userProvider: 'EMAIL' });
    expect((await deriveAuthMethod(prisma, 'u1', REF)).qrauthAuthMethod).toBe('qr_living_code');
  });

  it('ignores a passkey login that falls outside the 24h window', async () => {
    const prisma = makeFakePrisma({
      logins: [{ userId: 'u1', success: true, provider: 'PASSKEY', createdAt: new Date('2026-05-30T09:00:00Z') }],
      userProvider: 'EMAIL',
    });
    expect((await deriveAuthMethod(prisma, 'u1', REF)).qrauthAuthMethod).toBe('qr_living_code');
  });

  it('ignores failed login attempts', async () => {
    const prisma = makeFakePrisma({
      logins: [{ userId: 'u1', success: false, provider: 'PASSKEY', createdAt: new Date('2026-06-01T11:30:00Z') }],
      userProvider: 'EMAIL',
    });
    expect((await deriveAuthMethod(prisma, 'u1', REF)).qrauthAuthMethod).toBe('qr_living_code');
  });
});
