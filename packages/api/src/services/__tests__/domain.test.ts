import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { DomainService } from '../domain.js';

function makeService(prisma: any = {}) {
  return new DomainService(prisma);
}

describe('DomainService.extractDomain', () => {
  const svc = makeService();

  it('strips protocol, path and www., and lowercases', () => {
    expect(svc.extractDomain('https://www.Example.com/some/path?q=1')).toBe('example.com');
  });

  it('handles a bare hostname (no scheme) via the fallback', () => {
    expect(svc.extractDomain('Progressnet.GR')).toBe('progressnet.gr');
  });
});

describe('DomainService.levenshtein', () => {
  const svc = makeService();

  it('is 0 for identical strings', () => {
    expect(svc.levenshtein('progressnet', 'progressnet')).toBe(0);
  });

  it('matches known edit distances', () => {
    expect(svc.levenshtein('kitten', 'sitting')).toBe(3);
    expect(svc.levenshtein('paypal', 'paypol')).toBe(1);
  });
});

describe('DomainService.checkSimilarity (typosquat / homoglyph detection)', () => {
  const svc = makeService();

  it('treats an exact match as NOT suspicious', () => {
    expect(svc.checkSimilarity('example.com', 'example.com')).toEqual({ similar: false, score: 0 });
  });

  it('treats two unrelated domains as NOT similar', () => {
    const result = svc.checkSimilarity('apple.com', 'microsoft.com');
    expect(result.similar).toBe(false);
  });

  it('flags a homoglyph substitution (o -> 0) with score 95', () => {
    const result = svc.checkSimilarity('progressnet.com', 'pr0gressnet.com');
    expect(result.similar).toBe(true);
    expect(result.reason).toBe('homoglyph_match');
    expect(result.score).toBe(95);
  });

  it('flags a single-character typo as highly similar', () => {
    const result = svc.checkSimilarity('paypal.com', 'paypol.com');
    expect(result.similar).toBe(true);
    expect(result.score).toBeGreaterThanOrEqual(80);
  });

  it('flags a substring/brand-extension domain', () => {
    const result = svc.checkSimilarity('progressnet.com', 'progressnetpay.com');
    expect(result.similar).toBe(true);
    expect(result.reason).toBe('substring_match');
    expect(result.score).toBe(70);
  });
});

describe('DomainService.checkUrlAgainstVerifiedDomains', () => {
  it('warns and marks suspicious when the new URL mimics a verified domain', async () => {
    const prisma = {
      organization: {
        findMany: vi.fn(async () => [{ id: 'org_a', name: 'ProgressNet', domain: 'progressnet.com' }]),
      },
      qRCode: { findMany: vi.fn(async () => []) },
    };
    const svc = makeService(prisma);

    const result = await svc.checkUrlAgainstVerifiedDomains('https://pr0gressnet.com/pay', 'org_b');

    expect(result.warnings).toHaveLength(1);
    expect(result.warnings[0]).toMatchObject({ domain: 'progressnet.com', verifiedOrgName: 'ProgressNet' });
    expect(result.isSuspicious).toBe(true);
  });

  it('returns no warnings for an unrelated URL', async () => {
    const prisma = {
      organization: {
        findMany: vi.fn(async () => [{ id: 'org_a', name: 'ProgressNet', domain: 'progressnet.com' }]),
      },
      qRCode: { findMany: vi.fn(async () => []) },
    };
    const svc = makeService(prisma);

    const result = await svc.checkUrlAgainstVerifiedDomains('https://totally-different-site.io', 'org_b');

    expect(result.warnings).toHaveLength(0);
    expect(result.isSuspicious).toBe(false);
  });
});

describe('DomainService.generateVerifyToken', () => {
  it('persists and returns a 32-char hex token', async () => {
    const update = vi.fn(async () => ({}));
    const svc = makeService({ organization: { update } });

    const token = await svc.generateVerifyToken('org_1');

    expect(token).toMatch(/^[0-9a-f]{32}$/);
    expect(update).toHaveBeenCalledWith({
      where: { id: 'org_1' },
      data: { domainVerifyToken: token },
    });
  });
});

describe('DomainService.verifyDomain (DNS-over-HTTPS)', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('errors when the org has no domain', async () => {
    const svc = makeService({
      organization: { findUnique: vi.fn(async () => ({ domain: null, domainVerifyToken: 't' })) },
    });
    expect(await svc.verifyDomain('org_1')).toEqual({ verified: false, error: 'No domain set on organization' });
  });

  it('errors when no verification token was generated', async () => {
    const svc = makeService({
      organization: { findUnique: vi.fn(async () => ({ domain: 'example.com', domainVerifyToken: null })) },
    });
    const result = await svc.verifyDomain('org_1');
    expect(result.verified).toBe(false);
    expect(result.error).toContain('No verification token');
  });

  it('verifies when the expected TXT record is present', async () => {
    const update = vi.fn(async () => ({}));
    const svc = makeService({
      organization: {
        findUnique: vi.fn(async () => ({ domain: 'example.com', domainVerifyToken: 'TOK123' })),
        update,
      },
    });
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => ({
        ok: true,
        json: async () => ({ Answer: [{ type: 16, data: '"qrauth-verify=TOK123"' }] }),
      })),
    );

    const result = await svc.verifyDomain('org_1');

    expect(result).toEqual({ verified: true });
    expect(update).toHaveBeenCalledWith({ where: { id: 'org_1' }, data: { domainVerified: true } });
  });

  it('fails when the TXT record is absent', async () => {
    const svc = makeService({
      organization: {
        findUnique: vi.fn(async () => ({ domain: 'example.com', domainVerifyToken: 'TOK123' })),
        update: vi.fn(),
      },
    });
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => ({ ok: true, json: async () => ({ Answer: [] }) })),
    );

    const result = await svc.verifyDomain('org_1');
    expect(result.verified).toBe(false);
    expect(result.error).toContain('not found');
  });
});
