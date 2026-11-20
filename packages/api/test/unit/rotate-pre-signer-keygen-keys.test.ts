import { describe, it, expect, vi } from 'vitest';
import type { PrismaClient } from '@prisma/client';
import {
  DEFAULT_CUTOFF,
  CliArgsError,
  parseCliArgs,
  findCandidates,
  rotateCandidates,
  verificationQueries,
} from '../../scripts/rotate-pre-signer-keygen-keys.js';

/**
 * ADR-0009 D13: rotate ACTIVE ES256 keys created before prod was verified on
 * signer-side keygen. Stubbed Prisma and rotation; no database, no signer.
 */

describe('parseCliArgs', () => {
  it('defaults to a dry run over every org with the D13 cutoff', () => {
    expect(parseCliArgs([])).toEqual({ apply: false, orgId: null, before: DEFAULT_CUTOFF });
  });

  it('uses 2026-11-20T00:00:00Z as the default cutoff', () => {
    expect(DEFAULT_CUTOFF.toISOString()).toBe('2026-11-20T00:00:00.000Z');
  });

  it('reads --apply, --org and --before', () => {
    expect(parseCliArgs(['--apply', '--org', 'org_1', '--before', '2026-10-21T17:20:07Z'])).toEqual({
      apply: true,
      orgId: 'org_1',
      before: new Date('2026-10-21T17:20:07Z'),
    });
  });

  it('accepts fractional seconds in --before', () => {
    expect(parseCliArgs(['--before', '2026-11-20T00:00:00.000Z']).before.toISOString()).toBe(
      '2026-11-20T00:00:00.000Z',
    );
  });

  it('rejects a --before that is not an ISO-8601 UTC instant', () => {
    for (const bad of ['2026-11-20', '2026-11-20T00:00:00', '2026-11-20T00:00:00+02:00', 'yesterday', '2026-13-40T00:00:00Z']) {
      expect(() => parseCliArgs(['--before', bad]), bad).toThrow(CliArgsError);
    }
  });

  it('rejects options without a value', () => {
    expect(() => parseCliArgs(['--org'])).toThrow(CliArgsError);
    expect(() => parseCliArgs(['--org', '--apply'])).toThrow(CliArgsError);
    expect(() => parseCliArgs(['--before'])).toThrow(CliArgsError);
  });

  it('rejects unknown arguments', () => {
    expect(() => parseCliArgs(['--force'])).toThrow(CliArgsError);
  });
});

describe('findCandidates', () => {
  function makePrisma() {
    const findMany = vi.fn(async () => [
      { keyId: 'k1', organizationId: 'org_1', createdAt: new Date('2026-09-01T00:00:00Z') },
    ]);
    return { prisma: { signingKey: { findMany } } as unknown as PrismaClient, findMany };
  }

  it('selects ACTIVE ES256 keys created before the cutoff', async () => {
    const { prisma, findMany } = makePrisma();
    const before = new Date('2026-11-20T00:00:00Z');
    const rows = await findCandidates(prisma, null, before);

    expect(rows).toHaveLength(1);
    expect(findMany).toHaveBeenCalledWith(
      expect.objectContaining({
        where: { status: 'ACTIVE', algorithm: 'ES256', createdAt: { lt: before } },
      }),
    );
  });

  it('scopes to one org when --org is given', async () => {
    const { prisma, findMany } = makePrisma();
    await findCandidates(prisma, 'org_9', DEFAULT_CUTOFF);

    expect(findMany).toHaveBeenCalledWith(
      expect.objectContaining({
        where: expect.objectContaining({ organizationId: 'org_9' }),
      }),
    );
  });
});

describe('rotateCandidates', () => {
  const candidates = [
    { keyId: 'k1', organizationId: 'org_1', createdAt: new Date() },
    { keyId: 'k2', organizationId: 'org_2', createdAt: new Date() },
    { keyId: 'k3', organizationId: 'org_3', createdAt: new Date() },
  ];

  it('rotates every candidate in order and reports the new key ids', async () => {
    const rotate = vi.fn(async (keyId: string) => ({ keyId: `new-${keyId}` }));
    const result = await rotateCandidates(candidates, rotate);

    expect(rotate.mock.calls.map((c) => c[0])).toEqual(['k1', 'k2', 'k3']);
    expect(result.rotated).toEqual([
      { keyId: 'k1', newKeyId: 'new-k1' },
      { keyId: 'k2', newKeyId: 'new-k2' },
      { keyId: 'k3', newKeyId: 'new-k3' },
    ]);
    expect(result.failed).toEqual([]);
  });

  it('keeps going after a failure and records it', async () => {
    const rotate = vi.fn(async (keyId: string) => {
      if (keyId === 'k2') throw new Error('probe failed');
      return { keyId: `new-${keyId}` };
    });
    const result = await rotateCandidates(candidates, rotate);

    expect(result.rotated.map((r) => r.keyId)).toEqual(['k1', 'k3']);
    expect(result.failed).toEqual([{ keyId: 'k2', error: 'probe failed' }]);
  });
});

describe('verificationQueries', () => {
  const before = new Date('2026-11-20T00:00:00Z');

  it('sets the session to UTC before anything else', () => {
    const lines = verificationQueries(null, before);
    expect(lines[0]).toBe("SET TIME ZONE 'UTC';");
    expect(lines[1]).toBe('BEGIN READ ONLY;');
    expect(lines.at(-1)).toBe('ROLLBACK;');
  });

  it('compares against a plain UTC timestamp literal for the cutoff', () => {
    const sql = verificationQueries(null, before).join('\n');
    expect(sql).toContain("timestamp '2026-11-20 00:00:00'");
    expect(sql).not.toMatch(/timestamptz|[+-]\d\d:\d\d'/);
  });

  it('checks the cutoff, one ACTIVE key per org, the rotated rows and the audit entries', () => {
    const sql = verificationQueries(null, before).join('\n');
    expect(sql).toContain('HAVING count(*) <> 1');
    expect(sql).toContain("status = 'ROTATED'");
    expect(sql).toContain("action = 'signingKey.rotate'");
  });

  it('adds the org filter when scoped, with the id quoted as a literal', () => {
    const sql = verificationQueries('org_1', before).join('\n');
    expect(sql).toContain(`"organizationId" = 'org_1'`);
  });

  it('refuses an org id that is not a plain identifier', () => {
    expect(() => verificationQueries("x'; DROP TABLE signing_keys; --", before)).toThrow(CliArgsError);
  });
});
