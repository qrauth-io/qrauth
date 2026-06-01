/**
 * Security webhook delivery (Audit-2 M-13 / ALGORITHM.md §16).
 *
 * Every SigningKey.create call emits a `signing-key.created` event to
 * the organization's registered security webhook endpoint so integrators
 * can detect an unauthorized key being inserted into the DB (threat T-9).
 * Delivery is asynchronous — the caller enqueues and returns; the
 * `qrauth-webhooks` worker handles retries and logging.
 *
 * Wire format (headers):
 *   X-QRAuth-Event: signing-key.created
 *   X-QRAuth-Signature: sha3-256=<hex>
 *   Content-Type: application/json
 *   User-Agent: QRAuth-Security-Webhook/1
 *
 * The signature is HMAC-SHA3-256 computed over the raw request body
 * using the organization's base64-encoded 32-byte secret. Verifiers
 * reconstruct the HMAC exactly the same way — the signer and the
 * verifier must hash the byte-for-byte body, not a re-serialized JSON
 * object, since `JSON.stringify` output is key-order sensitive.
 */
import { createHmac, randomBytes, randomUUID } from 'node:crypto';
import type { PrismaClient, SigningKey } from '@prisma/client';
import { webhookQueue } from '../lib/queue.js';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Job name on the shared `qrauth-webhooks` queue. */
export const SECURITY_WEBHOOK_JOB_NAME = 'deliver-security' as const;

/** Custom backoff strategy name — returns 1s / 5s / 30s step delays. */
export const SECURITY_WEBHOOK_BACKOFF = 'security-webhook-steps' as const;

/**
 * Total attempts for a security-webhook delivery. The plan spec says
 * "3 attempts with exponential backoff (1s, 5s, 30s)". We read that as
 * one initial attempt plus three retries, giving 4 total attempts and
 * three backoff steps.
 */
export const SECURITY_WEBHOOK_MAX_ATTEMPTS = 4 as const;

/**
 * Delay table (ms) consumed by the worker's custom backoff strategy.
 * Index is `attemptsMade - 1` — i.e. the first retry after the initial
 * failure waits `BACKOFF_MS[0]`, the second `BACKOFF_MS[1]`, etc.
 */
export const SECURITY_WEBHOOK_BACKOFF_MS = [1_000, 5_000, 30_000] as const;

/** User-Agent header (pinned in ALGORITHM.md §16). */
export const SECURITY_WEBHOOK_USER_AGENT = 'QRAuth-Security-Webhook/1' as const;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface SigningKeyCreatedEvent {
  eventId: string;
  eventType: 'signing-key.created';
  occurredAt: string;
  organizationId: string;
  signingKey: {
    kid: string;
    algorithm: string;
    slhdsaAlgorithm: string | null;
    status: string;
    createdAt: string;
  };
  /**
   * Identity of the operator responsible for this action, when known.
   * Always `null` for now — ADR-0001 follow-up introduces operator
   * context on the service layer.
   */
  operatorIdentity: null;
}

export interface SecurityWebhookJobData {
  organizationId: string;
  url: string;
  /** Raw request body — the exact bytes that were HMAC'd. */
  rawBody: string;
  /** `sha3-256=<hex>` — the X-QRAuth-Signature header value. */
  signatureHeader: string;
  eventType: string;
  eventId: string;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Generate a fresh webhook secret. 32 random bytes, base64-encoded.
 * The registration endpoint mints one of these per (re)configuration;
 * integrators store the secret on their side and use it to validate the
 * HMAC on every delivery.
 */
export function generateSecurityWebhookSecret(): string {
  return randomBytes(32).toString('base64');
}

/**
 * HMAC-SHA3-256 a raw request body under the organization's secret. The
 * `secret` argument is the base64 string stored on the Organization row;
 * we decode it to its raw bytes before feeding to createHmac so
 * integrators on other runtimes (Python, Go) can reproduce the result
 * from the same base64 value.
 */
export function signSecurityWebhookBody(secret: string, rawBody: string): string {
  const key = Buffer.from(secret, 'base64');
  const mac = createHmac('sha3-256', key).update(rawBody, 'utf8').digest('hex');
  return `sha3-256=${mac}`;
}

/**
 * Build the `signing-key.created` event body in the exact shape pinned
 * by ALGORITHM.md §16. Takes a `SigningKey` row as its input and emits
 * a canonical JSON object with stable key ordering.
 */
export function buildSigningKeyCreatedEvent(key: SigningKey): SigningKeyCreatedEvent {
  return {
    eventId: randomUUID(),
    eventType: 'signing-key.created',
    occurredAt: new Date().toISOString(),
    organizationId: key.organizationId,
    signingKey: {
      kid: key.keyId,
      algorithm: key.algorithm,
      slhdsaAlgorithm: key.slhdsaAlgorithm ?? null,
      status: key.status,
      createdAt: key.createdAt.toISOString(),
    },
    operatorIdentity: null,
  };
}

// ---------------------------------------------------------------------------
// Enqueue
// ---------------------------------------------------------------------------

/**
 * Enqueue a `signing-key.created` webhook for the organization that
 * owns `key`. Fire-and-forget from the caller's perspective: on
 * success, the job is persisted to Redis and the worker takes over;
 * on any error (missing org row, no configured endpoint, Redis
 * unreachable) we swallow and log so key creation is never blocked.
 *
 * Returns the event object when a delivery was enqueued, or `null`
 * when the org has no configured endpoint (so callers / tests can
 * distinguish "nothing to deliver" from "delivery enqueued").
 */
export async function enqueueSigningKeyCreatedWebhook(
  prisma: PrismaClient,
  key: SigningKey,
): Promise<SigningKeyCreatedEvent | null> {
  try {
    const org = await prisma.organization.findUnique({
      where: { id: key.organizationId },
      select: { securityWebhookUrl: true, securityWebhookSecret: true },
    });

    if (!org?.securityWebhookUrl || !org.securityWebhookSecret) {
      console.warn(
        `[security-webhook] org ${key.organizationId} has no configured ` +
          `security webhook endpoint; skipping signing-key.created delivery ` +
          `for kid=${key.keyId} (T-9 detection signal suppressed).`,
      );
      return null;
    }

    const event = buildSigningKeyCreatedEvent(key);
    const rawBody = JSON.stringify(event);
    const signatureHeader = signSecurityWebhookBody(org.securityWebhookSecret, rawBody);

    const jobData: SecurityWebhookJobData = {
      organizationId: key.organizationId,
      url: org.securityWebhookUrl,
      rawBody,
      signatureHeader,
      eventType: event.eventType,
      eventId: event.eventId,
    };

    await webhookQueue.add(SECURITY_WEBHOOK_JOB_NAME, jobData, {
      attempts: SECURITY_WEBHOOK_MAX_ATTEMPTS,
      backoff: { type: SECURITY_WEBHOOK_BACKOFF },
    });

    return event;
  } catch (err) {
    // Never block key creation on security webhook emission. If Redis
    // is down or the org row has been deleted mid-flight, log and
    // swallow. The plan treats missing deliveries as a detection gap,
    // not a failure of key creation itself.
    console.error(
      `[security-webhook] failed to enqueue signing-key.created for ` +
        `kid=${key.keyId} org=${key.organizationId}:`,
      err instanceof Error ? err.message : err,
    );
    return null;
  }
}
