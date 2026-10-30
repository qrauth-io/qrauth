import { request as httpRequest, type IncomingMessage } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { isIP, type LookupFunction } from 'node:net';
import { lookup as dnsLookup } from 'node:dns';
import { URL } from 'node:url';
import { isSafeWebhookUrl, reservedAddressReason } from './url-validation.js';

const DEFAULT_TIMEOUT_MS = 10_000;
const DEFAULT_MAX_RESPONSE_BYTES = 100_000;

/**
 * Thrown when a URL — or any address it resolves to — is unsafe for an
 * outbound server-side request. Callers treat this as a permanent failure
 * (do NOT retry): the destination is invalid, retrying won't change that.
 */
export class SsrfBlockedError extends Error {
  readonly reason: string;
  constructor(reason: string) {
    super(`Blocked: ${reason}`);
    this.name = 'SsrfBlockedError';
    this.reason = reason;
  }
}

export interface SafeFetchInit {
  method?: string;
  headers?: Record<string, string>;
  body?: string;
  timeoutMs?: number;
  maxResponseBytes?: number;
  /**
   * Permit resolved loopback addresses (127.0.0.0/8, ::1). Used ONLY by the
   * non-production E2E affordance that delivers webhooks to a local capture
   * server. Every other reserved range stays blocked even when set.
   */
  allowLoopback?: boolean;
}

export interface SafeFetchResult {
  ok: boolean;
  status: number;
  bodyText: string;
  truncated: boolean;
}

/**
 * SSRF-safe outbound fetch for webhook delivery. Closes the DNS-rebinding
 * residual (pentest INJ-005) that `isSafeWebhookUrl` alone cannot:
 *
 *  1. Validate the URL (scheme + hostname) via `isSafeWebhookUrl`.
 *  2. Resolve the host ONCE with `dns.lookup(host, { all: true })`.
 *  3. Reject if ANY resolved address is private/reserved — a record mixing a
 *     public and an internal address is refused outright.
 *  4. PIN the connection to a validated address via a custom `lookup` that
 *     ignores the hostname and returns only that address, so the socket
 *     connects to exactly the address we validated (no TOCTOU re-resolution).
 *     The `Host` header and TLS SNI / certificate validation still use the
 *     original hostname.
 *  5. Never follow redirects — `http(s).request` does not auto-follow, so a 30x
 *     surfaces as a non-2xx response rather than a hop to an internal target.
 *
 * Throws {@link SsrfBlockedError} for an unsafe URL/address (permanent — no
 * retry); throws a generic Error for network/timeout failures (retryable).
 */
export async function safeFetch(urlString: string, init: SafeFetchInit = {}): Promise<SafeFetchResult> {
  const check = isSafeWebhookUrl(urlString, { allowLoopback: init.allowLoopback });
  if (!check.safe) {
    throw new SsrfBlockedError(check.reason ?? 'Unsafe URL');
  }

  const url = new URL(urlString);
  const host = url.hostname.replace(/^\[|\]$/g, '');

  // Resolve once. For an IP literal, lookup returns the literal itself.
  let resolved: { address: string; family: number }[];
  try {
    resolved = await new Promise((resolve, reject) => {
      dnsLookup(host, { all: true }, (err, addresses) => {
        if (err) reject(err);
        else resolve(addresses);
      });
    });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new SsrfBlockedError(`DNS resolution failed for ${host}: ${msg}`);
  }

  if (resolved.length === 0) {
    throw new SsrfBlockedError(`${host} did not resolve to any address`);
  }

  // Validate EVERY address. Reject the whole request if any is reserved — a
  // mixed public+private record must not be allowed to pick the public one.
  for (const { address } of resolved) {
    const { reason, isLoopback } = reservedAddressReason(address);
    if (reason && !(init.allowLoopback && isLoopback)) {
      throw new SsrfBlockedError(`${host} resolves to a blocked address (${address}): ${reason}`);
    }
  }

  // Pin to the first (now-validated) address. The custom lookup ignores the
  // hostname entirely and always returns this address, so there is no second
  // resolution between validation and connect.
  const pinnedAddress = resolved[0].address;
  const pinnedFamily = isIP(pinnedAddress);
  const pinnedLookup: LookupFunction = (_hostname, options, callback) => {
    if (options && (options as { all?: boolean }).all) {
      (callback as unknown as (e: Error | null, a: { address: string; family: number }[]) => void)(
        null,
        [{ address: pinnedAddress, family: pinnedFamily }],
      );
    } else {
      callback(null, pinnedAddress, pinnedFamily);
    }
  };

  const requestFn = url.protocol === 'https:' ? httpsRequest : httpRequest;
  const timeoutMs = init.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const maxBytes = init.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES;

  return await new Promise<SafeFetchResult>((resolve, reject) => {
    const req = requestFn(
      urlString,
      {
        method: init.method ?? 'GET',
        headers: init.headers,
        lookup: pinnedLookup,
        signal: AbortSignal.timeout(timeoutMs),
      },
      (res: IncomingMessage) => {
        const status = res.statusCode ?? 0;
        const chunks: Buffer[] = [];
        let total = 0;
        let truncated = false;

        res.on('data', (chunk: Buffer) => {
          if (truncated) return;
          total += chunk.length;
          if (total > maxBytes) {
            truncated = true;
            res.destroy();
            return;
          }
          chunks.push(chunk);
        });
        res.on('end', () => {
          resolve({
            ok: status >= 200 && status < 300,
            status,
            bodyText: truncated ? '(response truncated — exceeded limit)' : Buffer.concat(chunks).toString('utf-8'),
            truncated,
          });
        });
        res.on('error', (err) => {
          // A deliberate destroy() after hitting the cap still resolves above
          // via 'end' on some streams, but guard the error path too.
          if (truncated) {
            resolve({ ok: status >= 200 && status < 300, status, bodyText: '(response truncated — exceeded limit)', truncated: true });
          } else {
            reject(err);
          }
        });
      },
    );

    req.on('error', reject);
    if (init.body !== undefined) req.write(init.body);
    req.end();
  });
}
