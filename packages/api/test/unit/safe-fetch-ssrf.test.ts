import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import http from 'node:http';
import type { AddressInfo } from 'node:net';

/**
 * Pentest INJ-005: closing webhook DNS rebinding. `safeFetch` must resolve the
 * host ONCE, reject if any resolved address is private/reserved, and pin the
 * connection to a validated address (so a record that resolves public-at-check
 * and private-at-connect cannot reach an internal target).
 *
 * `node:dns`'s `lookup` is mocked so we control exactly what the host resolves
 * to. The actual connection uses safeFetch's own pinned lookup (which never
 * re-resolves), so a loopback target + a real local server exercises the full
 * resolve → validate → pin → request path end-to-end.
 */
const { mockLookup } = vi.hoisted(() => ({ mockLookup: vi.fn() }));
vi.mock('node:dns', () => ({ lookup: mockLookup, default: { lookup: mockLookup } }));

import { safeFetch, SsrfBlockedError } from '../../src/lib/safe-fetch.js';

/** Make the mocked dns.lookup return a fixed address list. */
function resolveTo(addresses: { address: string; family: number }[]): void {
  // dns.lookup's callback is the last argument (arity varies with options).
  // Guard for the function: the mock can also be probed with no args by the
  // test runner's mock bookkeeping, which we simply ignore.
  mockLookup.mockImplementation((...args: unknown[]) => {
    const cb = args[args.length - 1];
    if (typeof cb === 'function') (cb as (e: Error | null, a: unknown) => void)(null, addresses);
  });
}

describe('safeFetch — INJ-005 DNS rebinding defense', () => {
  beforeEach(() => mockLookup.mockReset());

  it('blocks when the host resolves to a private IP (RFC-1918)', async () => {
    resolveTo([{ address: '10.0.0.5', family: 4 }]);
    await expect(safeFetch('http://internal.attacker.test/')).rejects.toBeInstanceOf(SsrfBlockedError);
  });

  it('blocks when the host resolves to the cloud-metadata address', async () => {
    resolveTo([{ address: '169.254.169.254', family: 4 }]);
    await expect(safeFetch('http://metadata.attacker.test/')).rejects.toBeInstanceOf(SsrfBlockedError);
  });

  it('blocks loopback by default (allowLoopback off)', async () => {
    resolveTo([{ address: '127.0.0.1', family: 4 }]);
    await expect(safeFetch('http://rebind.attacker.test/')).rejects.toBeInstanceOf(SsrfBlockedError);
  });

  it('blocks an IPv6 unique-local resolution', async () => {
    resolveTo([{ address: 'fd00::1', family: 6 }]);
    await expect(safeFetch('http://v6.attacker.test/')).rejects.toBeInstanceOf(SsrfBlockedError);
  });

  it('blocks a multi-A record where ANY address is private (public + private)', async () => {
    // The classic rebinding/round-robin trick: one routable + one internal.
    resolveTo([
      { address: '93.184.216.34', family: 4 }, // public
      { address: '192.168.1.10', family: 4 }, // private — must poison the whole set
    ]);
    await expect(safeFetch('http://mixed.attacker.test/')).rejects.toBeInstanceOf(SsrfBlockedError);
  });

  it('blocks an IPv4-mapped IPv6 private resolution', async () => {
    resolveTo([{ address: '::ffff:10.0.0.1', family: 6 }]);
    await expect(safeFetch('http://mapped.attacker.test/')).rejects.toBeInstanceOf(SsrfBlockedError);
  });

  it('surfaces the blocked address in the rejection (validated before connect)', async () => {
    resolveTo([{ address: '10.0.0.5', family: 4 }]);
    // The rejection names the resolved address — proving safeFetch validated
    // what the host *resolved to*, not just the hostname, before any connect.
    await expect(safeFetch('http://internal.attacker.test/')).rejects.toThrow(/10\.0\.0\.5/);
    expect(mockLookup).toHaveBeenCalled();
  });
});

describe('safeFetch — allowed path pins to the validated address', () => {
  let server: http.Server;
  let port: number;
  let hits: { host?: string; path?: string }[] = [];

  beforeEach(async () => {
    mockLookup.mockReset();
    hits = [];
    server = http.createServer((req, res) => {
      hits.push({ host: req.headers.host, path: req.url });
      res.statusCode = 200;
      res.end('ok');
    });
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    port = (server.address() as AddressInfo).port;
  });

  afterEach(async () => {
    await new Promise<void>((r) => server.close(() => r()));
  });

  it('resolves once, pins to the validated address, and reaches it (Host preserved)', async () => {
    // Public-looking hostname that "resolves" to our local server. allowLoopback
    // mirrors the non-prod E2E affordance. The point: the connection goes to the
    // single resolved+validated address, and the host is NOT re-resolved.
    resolveTo([{ address: '127.0.0.1', family: 4 }]);

    const result = await safeFetch(`http://webhook.example.com:${port}/deliver`, {
      method: 'POST',
      body: '{"event":"test"}',
      allowLoopback: true,
      timeoutMs: 5000,
    });

    expect(result.ok).toBe(true);
    expect(result.status).toBe(200);
    expect(result.bodyText).toBe('ok');
    // The request reached the PINNED address (our local server) — had safeFetch
    // re-resolved the hostname at connect time, it would not have hit this
    // server. That, plus the preserved Host header, is the rebinding closure.
    expect(mockLookup).toHaveBeenCalledWith('webhook.example.com', expect.anything(), expect.any(Function));
    expect(hits).toHaveLength(1);
    expect(hits[0].host).toBe(`webhook.example.com:${port}`);
    expect(hits[0].path).toBe('/deliver');
  });

  it('rejects an unsupported scheme before any resolution', async () => {
    await expect(safeFetch('file:///etc/passwd')).rejects.toBeInstanceOf(SsrfBlockedError);
    expect(mockLookup).not.toHaveBeenCalled();
  });
});
