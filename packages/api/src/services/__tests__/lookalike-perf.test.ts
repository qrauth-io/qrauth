import { performance } from 'node:perf_hooks';
import { describe, expect, it, vi } from 'vitest';

import { DomainService } from '../domain.js';

/**
 * ADR-0007 budget: the lookalike check adds under 5 ms (p95) to a create
 * once the protected set is loaded (it is cached for 5 minutes), and a scan
 * answers from the per-URL cache without database work.
 *
 * Protected set used here, larger than production today: the curated list
 * (199 domains), 300 verified organizations and 2,000 verified destinations.
 */

const orgs = Array.from({ length: 300 }, (_, i) => ({ id: `org_${i}`, name: `Org ${i}`, domain: `verified-org-${i}.example` }));
const destinations = Array.from({ length: 2000 }, (_, i) => ({
  destinationUrl: `https://shop-${i}.verified-org-${i % 300}.example/path`,
  organizationId: `org_${i % 300}`,
  organization: { name: `Org ${i % 300}` },
}));

function p95(samples: number[]): number {
  const sorted = [...samples].sort((a, b) => a - b);
  return sorted[Math.floor(sorted.length * 0.95)];
}

const HOSTS = ['раураl', 'my-cafe', 'gοοgle-login', 'ουτοπία', 'shop', 'eurobank-secure', 'αθήνα-μενού', 'paypa1-help', 'example-store', 'menu'];
const tlds = ['com', 'gr', 'eu', 'io'];

describe('lookalike check latency', () => {
  // Wall-clock budget: retried when other test files compete for the CPU.
  it('create path: p95 under 5 ms with the protected set loaded; scan path served from cache', { retry: 2 }, async () => {
    const prisma = {
      organization: { findMany: vi.fn(async () => orgs) },
      qRCode: { findMany: vi.fn(async () => destinations) },
    };
    const svc = new DomainService(prisma as never);

    const loadStart = performance.now();
    await svc.checkUrlAgainstVerifiedDomains('https://warmup.example/', 'org_issuer');
    const loadMs = performance.now() - loadStart;
    // A later reload (every 5 minutes) of the same references.
    DomainService.clearCaches(prisma);
    const reloadStart = performance.now();
    await svc.checkUrlAgainstVerifiedDomains('https://warmup.example/', 'org_issuer');
    const reloadMs = performance.now() - reloadStart;

    // Create path: every URL is new (result cache miss).
    const create: number[] = [];
    for (let i = 0; i < 1000; i++) {
      const url = `https://${HOSTS[i % HOSTS.length]}-${i}.${tlds[i % tlds.length]}/x`;
      const t = performance.now();
      await svc.checkUrlAgainstVerifiedDomains(url, 'org_issuer');
      create.push(performance.now() - t);
    }

    // Scan path: the same URLs again (result cache hit).
    const scan: number[] = [];
    for (let i = 0; i < 1000; i++) {
      const url = `https://${HOSTS[i % HOSTS.length]}-${i}.${tlds[i % tlds.length]}/x`;
      const t = performance.now();
      await svc.checkUrlAgainstVerifiedDomains(url, 'org_issuer');
      scan.push(performance.now() - t);
    }

    console.log(
      `[lookalike-perf] protected set first load ${loadMs.toFixed(1)} ms, reload ${reloadMs.toFixed(1)} ms (every 5 min); ` +
        `create p95 ${p95(create).toFixed(3)} ms, p50 ${p95(create.slice().sort((a, b) => a - b).slice(0, 526)).toFixed(3)} ms; ` +
        `scan (cached) p95 ${p95(scan).toFixed(4)} ms`,
    );
    expect(p95(create)).toBeLessThan(5);
    expect(p95(scan)).toBeLessThan(0.1);
    expect(reloadMs).toBeLessThan(150);
    expect(prisma.organization.findMany).toHaveBeenCalledTimes(2);
    expect(prisma.qRCode.findMany).toHaveBeenCalledTimes(2);
  });
});
