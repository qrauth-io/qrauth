import { describe, expect, it, vi } from 'vitest';

import { CONFUSABLES_SHA256 } from '../../lib/confusables.js';
import { PSL_SHA256 } from '../../lib/public-suffix.js';
import { DomainService } from '../domain.js';
import { lookalikeDataLine, lookalikeDataSummary, preloadLookalikeData } from '../lookalike-data.js';
import { compareLookalikeWarnings } from '../lookalike.js';

describe('lookalike data summary (startup log)', () => {
  it('reports the bundled versions, checksums and list sizes', () => {
    const summary = lookalikeDataSummary();
    expect(summary.confusables).toEqual({ version: '17.0.0', sha256: CONFUSABLES_SHA256, matchesPinned: true });
    expect(summary.psl).toMatchObject({ version: expect.stringMatching(/^2026-10-31/), sha256: PSL_SHA256, matchesPinned: true });
    expect(summary.curated.brands).toBeGreaterThan(100);
    expect(summary.curated.domains).toBeGreaterThan(summary.curated.brands);
    expect(summary.keywords).toBeGreaterThan(30);

    const line = lookalikeDataLine(summary);
    expect(line).toContain(`confusables 17.0.0 (sha256 ${CONFUSABLES_SHA256.slice(0, 12)})`);
    expect(line).toContain(`(sha256 ${PSL_SHA256.slice(0, 12)})`);
    expect(line).toMatch(/curated list \d+ brands \/ \d+ domains, \d+ phishing keywords$/);
  });
});

describe('warning order', () => {
  it('brand and domain matches before mixed scripts, then strongest first', () => {
    const warnings = [
      { domain: 'x', verifiedOrgName: '', similarity: 100, reason: 'mixed_script' },
      { domain: 'b.com', verifiedOrgName: 'B', similarity: 80, reason: 'typosquatting' },
      { domain: 'a.com', verifiedOrgName: 'A', similarity: 95, reason: 'embedded_domain' },
    ];
    expect([...warnings].sort(compareLookalikeWarnings).map((w) => w.domain)).toEqual(['a.com', 'b.com', 'x']);
  });

  it('suspicious brand matches, then mixed scripts, then matches below the threshold', () => {
    const warnings = [
      { domain: 'weak.com', verifiedOrgName: 'W', similarity: 70, reason: 'substring_match' },
      { domain: 'x', verifiedOrgName: '', similarity: 100, reason: 'mixed_script' },
      { domain: 'b.com', verifiedOrgName: 'B', similarity: 80, reason: 'typosquatting' },
    ];
    expect([...warnings].sort(compareLookalikeWarnings).map((w) => w.domain)).toEqual(['b.com', 'x', 'weak.com']);
  });
});

describe('startup preload', () => {
  function prisma() {
    return {
      organization: { findMany: vi.fn(async () => [{ id: 'org_a', name: 'A', domain: 'acme-bank.gr' }]) },
      qRCode: { findMany: vi.fn(async () => []) },
    };
  }

  it('loads the protected set once; requests during and after the preload share it', async () => {
    const db = prisma();
    const preload = new DomainService(db as never).preload();
    // A request arriving while the preload runs waits for the same load.
    const during = new DomainService(db as never).checkUrlAgainstVerifiedDomains('https://acrne-bank.gr/', 'org_x');
    const [count, check] = await Promise.all([preload, during]);
    expect(count).toBeGreaterThan(200);
    expect(check.isSuspicious).toBe(true);
    await new DomainService(db as never).checkUrlAgainstVerifiedDomains('https://example.com/', 'org_x');
    expect(db.organization.findMany).toHaveBeenCalledTimes(1);
    expect(db.qRCode.findMany).toHaveBeenCalledTimes(1);
  });

  it('logs one line with versions, checksums and load times', async () => {
    const info = vi.fn();
    const error = vi.fn();
    let t = 0;
    const now = () => (t += 40);
    await preloadLookalikeData(async () => 251, { info, error }, now);
    expect(error).not.toHaveBeenCalled();
    expect(info).toHaveBeenCalledTimes(1);
    const [fields, line] = info.mock.calls[0];
    expect(fields).toMatchObject({ event: 'lookalike.data_loaded', dataMs: 40, referencesMs: 40, references: 251 });
    expect(line).toMatch(/^Lookalike data: confusables 17\.0\.0 \(sha256 091c7f82fc39\), PSL 2026-10-31\S* \(sha256 617d1b276660\), curated list \d+ brands \/ \d+ domains, \d+ phishing keywords; loaded in 80 ms \(data 40 ms, protected set of 251 domains 40 ms\)$/);
  });

  it('logs a failure and never throws', async () => {
    const info = vi.fn();
    const error = vi.fn();
    await expect(preloadLookalikeData(async () => { throw new Error('db down'); }, { info, error })).resolves.toBeUndefined();
    expect(info).not.toHaveBeenCalled();
    expect(error).toHaveBeenCalledWith(expect.objectContaining({ event: 'lookalike.data_load_failed' }), expect.any(String));
  });
});
