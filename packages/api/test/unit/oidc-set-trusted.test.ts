import { describe, it, expect, vi } from 'vitest';
import type { PrismaClient } from '@prisma/client';
import { parseCliArgs, setClientTrusted, SetTrustedError } from '../../scripts/oidc-set-trusted.js';

/**
 * Audit 2026-10 FINDING-002: an operator marks a vetted self-serve client as
 * trusted, which lets it skip the consent page. Stubbed Prisma; no database.
 */

interface Row { id: string; clientId: string; tier: string; consentRequired: boolean; organizationId: string }

function makePrisma(row: Row | null, owner: { userId: string } | null = { userId: 'owner_1' }) {
  const audits: Array<Record<string, any>> = [];
  const update = vi.fn(async ({ data }: { data: { consentRequired: boolean } }) => {
    if (row) row.consentRequired = data.consentRequired;
    return row;
  });
  const prisma = {
    oidcClient: { findUnique: vi.fn(async () => (row ? { ...row } : null)), update },
    membership: { findFirst: vi.fn(async () => owner) },
    auditLog: { create: vi.fn(async ({ data }: { data: Record<string, any> }) => { audits.push(data); return data; }) },
    $transaction: vi.fn(async (ops: Array<Promise<unknown>>) => Promise.all(ops)),
  } as unknown as PrismaClient;
  return { prisma, update, audits };
}

const customer = (): Row => ({
  id: 'row1', clientId: 'qrauth_oidc_abc', tier: 'CUSTOMER', consentRequired: true, organizationId: 'org_client',
});

describe('parseCliArgs', () => {
  it('reads --client-id, --trusted and --dry-run', () => {
    expect(parseCliArgs(['--client-id', 'qrauth_oidc_abc', '--trusted', 'true'])).toEqual({
      clientId: 'qrauth_oidc_abc', trusted: true, dryRun: false,
    });
    expect(parseCliArgs(['--client-id', 'x', '--trusted', 'false', '--dry-run'])).toEqual({
      clientId: 'x', trusted: false, dryRun: true,
    });
  });

  it('rejects a missing client id, a missing or non-boolean --trusted, and unknown flags', () => {
    expect(() => parseCliArgs(['--trusted', 'true'])).toThrow(SetTrustedError);
    expect(() => parseCliArgs(['--client-id', 'x'])).toThrow(SetTrustedError);
    expect(() => parseCliArgs(['--client-id', 'x', '--trusted', 'yes'])).toThrow(SetTrustedError);
    expect(() => parseCliArgs(['--client-id', 'x', '--trusted', 'true', '--force'])).toThrow(SetTrustedError);
  });
});

describe('setClientTrusted', () => {
  it('marks a CUSTOMER client trusted and writes an audit row in the client org', async () => {
    const row = customer();
    const { prisma, update, audits } = makePrisma(row);

    const result = await setClientTrusted(prisma, { clientId: row.clientId, trusted: true, dryRun: false });

    expect(result).toMatchObject({ changed: true, dryRun: false, previousConsentRequired: true, consentRequired: false });
    expect(update).toHaveBeenCalledWith({ where: { id: 'row1' }, data: { consentRequired: false } });
    expect(audits).toHaveLength(1);
    expect(audits[0]).toMatchObject({
      organizationId: 'org_client',
      userId: 'owner_1',
      action: 'oidcClient.trust_set_by_operator',
      resource: 'OidcClient',
      resourceId: 'row1',
    });
    expect(audits[0].metadata).toMatchObject({
      actor: 'operator',
      via: 'scripts/oidc-set-trusted.ts',
      clientId: row.clientId,
      previousConsentRequired: true,
      consentRequired: false,
    });
    expect(typeof audits[0].metadata.operator).toBe('string');
    expect(typeof audits[0].metadata.host).toBe('string');
  });

  it('can take the trust away again', async () => {
    const row = { ...customer(), consentRequired: false };
    const { prisma } = makePrisma(row);

    const result = await setClientTrusted(prisma, { clientId: row.clientId, trusted: false, dryRun: false });

    expect(result).toMatchObject({ changed: true, consentRequired: true });
    expect(row.consentRequired).toBe(true);
  });

  it('is idempotent: no write and no audit row when the value is already set', async () => {
    const row = { ...customer(), consentRequired: false };
    const { prisma, update, audits } = makePrisma(row);

    const result = await setClientTrusted(prisma, { clientId: row.clientId, trusted: true, dryRun: false });

    expect(result).toMatchObject({ changed: false, consentRequired: false });
    expect(update).not.toHaveBeenCalled();
    expect(audits).toHaveLength(0);
  });

  it('dry run reports the change and writes nothing', async () => {
    const row = customer();
    const { prisma, update, audits } = makePrisma(row);

    const result = await setClientTrusted(prisma, { clientId: row.clientId, trusted: true, dryRun: true });

    expect(result).toMatchObject({ changed: true, dryRun: true, consentRequired: false });
    expect(update).not.toHaveBeenCalled();
    expect(audits).toHaveLength(0);
    expect(row.consentRequired).toBe(true);
  });

  it('refuses a FIRST_PARTY client', async () => {
    const row = { ...customer(), tier: 'FIRST_PARTY' };
    const { prisma, update } = makePrisma(row);

    await expect(setClientTrusted(prisma, { clientId: row.clientId, trusted: true, dryRun: false })).rejects.toThrow(
      /FIRST_PARTY/,
    );
    expect(update).not.toHaveBeenCalled();
  });

  it('refuses an unknown client id', async () => {
    const { prisma } = makePrisma(null);

    await expect(setClientTrusted(prisma, { clientId: 'nope', trusted: true, dryRun: false })).rejects.toThrow(
      SetTrustedError,
    );
  });

  it('refuses to change a client whose organization has no owner to attribute the audit row to', async () => {
    const row = customer();
    const { prisma, update } = makePrisma(row, null);

    await expect(setClientTrusted(prisma, { clientId: row.clientId, trusted: true, dryRun: false })).rejects.toThrow(
      /OWNER/,
    );
    expect(update).not.toHaveBeenCalled();
  });
});
