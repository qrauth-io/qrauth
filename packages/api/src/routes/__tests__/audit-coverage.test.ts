import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it, vi } from 'vitest';
import Fastify from 'fastify';
import { AUDIT_ACTION_LABELS, QR_REVISION_ACTIONS } from '@qrauth/shared';

/**
 * Audit coverage (ADR-0008 D3): registers every route plugin of the API
 * (routes/index.ts, as server.ts does) on a bare instance and requires each
 * mutating route to be mapped in lib/audit-coverage.ts, to audit events or
 * to an exemption with a reason. A new POST/PUT/PATCH/DELETE route fails
 * this test until it is mapped.
 */

process.env.DATABASE_URL ??= 'postgresql://test:test@localhost:5432/test';
process.env.REDIS_URL ??= 'redis://localhost:6379';
process.env.JWT_SECRET ??= 'a'.repeat(32);
process.env.ANIMATED_QR_SECRET ??= 'a'.repeat(64);

// Route modules open queue and cache connections at import; none is used here.
vi.mock('ioredis', () => {
  class Redis {
    status = 'ready';
    on() { return this; }
    async quit() {}
    duplicate() { return new Redis(); }
  }
  return { Redis, default: Redis };
});
vi.mock('bullmq', () => {
  class Queue { on() { return this; } async add() {} async close() {} }
  class Worker { on() { return this; } async close() {} }
  return { Queue, Worker, QueueEvents: Queue };
});

const SRC = fileURLToPath(new URL('../../', import.meta.url));

/** API sources that can write audit entries: not tests, not the coverage map itself. */
function writerSources(): string {
  const files = readdirSync(SRC, { recursive: true, encoding: 'utf8' })
    .filter((f) => f.endsWith('.ts') && !f.includes('__tests__') && !f.endsWith('.test.ts') && !f.endsWith('audit-coverage.ts'));
  return files.map((f) => readFileSync(join(SRC, f), 'utf8')).join('\n');
}

const READ_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

async function mutatingRoutes(): Promise<string[]> {
  const { ROUTE_PLUGINS } = await import('../index.js');
  const app = Fastify();
  const stub: object = new Proxy({}, { get: () => stub });
  for (const name of ['prisma', 'redis', 'ecdsaSigner', 'batchSigner', 'macSigner']) app.decorate(name, stub);
  app.decorate('authenticate', async () => {});
  app.decorateRequest('user', null);
  const routes = new Set<string>();
  app.addHook('onRoute', (route) => {
    for (const method of [route.method].flat()) {
      if (!READ_METHODS.has(method)) routes.add(`${method} ${route.url}`);
    }
  });
  for (const [plugin, prefix] of ROUTE_PLUGINS) await app.register(plugin, prefix ? { prefix } : {});
  await app.ready();
  await app.close();
  return [...routes].sort();
}

describe('audit coverage of mutating routes', async () => {
  const { ROUTE_AUDIT } = await import('../../lib/audit-coverage.js');
  const routes = await mutatingRoutes();

  it('finds the registered mutating routes', () => {
    expect(routes.length).toBeGreaterThan(100);
  });

  it('maps every mutating route to audit events or an exemption with a reason', () => {
    const unmapped = routes.filter((r) => !(r in ROUTE_AUDIT));
    expect(unmapped, 'add these routes to lib/audit-coverage.ts').toEqual([]);
  });

  it('has no entries for routes that are not registered', () => {
    const stale = Object.keys(ROUTE_AUDIT).filter((r) => !routes.includes(r));
    expect(stale, 'remove these entries from lib/audit-coverage.ts').toEqual([]);
  });

  it('names only catalogued events, and gives every exemption a reason', () => {
    for (const [route, audit] of Object.entries(ROUTE_AUDIT)) {
      if ('events' in audit) {
        expect(audit.events.length, route).toBeGreaterThan(0);
        for (const e of audit.events) expect(AUDIT_ACTION_LABELS, `${route}: ${e}`).toHaveProperty([e]);
      } else {
        expect(audit.exempt.trim().length, route).toBeGreaterThan(20);
      }
    }
  });

  it('every mapped audit-table event is written somewhere in the API sources', () => {
    const sources = writerSources();
    const events = new Set(
      Object.values(ROUTE_AUDIT).flatMap((a) => ('events' in a ? a.events : [])).filter((e) => !(e in QR_REVISION_ACTIONS)),
    );
    const missing = [...events].filter((e) => !sources.includes(`'${e}'`));
    expect(missing, 'mapped but never written').toEqual([]);
  });
});
