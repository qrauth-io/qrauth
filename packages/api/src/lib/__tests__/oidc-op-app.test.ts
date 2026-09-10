import { describe, it, expect, beforeEach, beforeAll } from 'vitest';
import type { PrismaClient } from '@prisma/client';

beforeAll(() => {
  process.env.DATABASE_URL ??= 'postgresql://test:test@localhost:5432/test';
  process.env.REDIS_URL ??= 'redis://localhost:6379';
  process.env.JWT_SECRET ??= 'a'.repeat(32);
  process.env.ANIMATED_QR_SECRET ??= 'a'.repeat(64);
});

describe('getOpAppId (ADR-0003 Slice 3b.2)', () => {
  let getOpAppId: typeof import('../oidc-op-app.js').getOpAppId;
  let OpAppNotProvisionedError: typeof import('../oidc-op-app.js').OpAppNotProvisionedError;
  let resetCache: typeof import('../oidc-op-app.js').__resetOpAppIdCache;

  beforeAll(async () => {
    const mod = await import('../oidc-op-app.js');
    getOpAppId = mod.getOpAppId;
    OpAppNotProvisionedError = mod.OpAppNotProvisionedError;
    resetCache = mod.__resetOpAppIdCache;
  });

  beforeEach(() => resetCache());

  it('returns the App.id for clientId=qrauth-op and memoises it', async () => {
    let calls = 0;
    const fake = {
      app: {
        async findUnique({ where }: { where: { clientId: string } }) {
          calls++;
          expect(where.clientId).toBe('qrauth-op');
          return { id: 'app_qrauth_op' };
        },
      },
    } as unknown as PrismaClient;

    expect(await getOpAppId(fake)).toBe('app_qrauth_op');
    expect(await getOpAppId(fake)).toBe('app_qrauth_op');
    expect(calls).toBe(1); // second call served from the memo, no DB hit
  });

  it('throws OpAppNotProvisionedError when the App row is missing', async () => {
    const fake = {
      app: { async findUnique() { return null; } },
    } as unknown as PrismaClient;

    await expect(getOpAppId(fake)).rejects.toBeInstanceOf(OpAppNotProvisionedError);
  });
});
