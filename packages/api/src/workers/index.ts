import { Worker } from 'bullmq';
import type { Job } from 'bullmq';
import type { Prisma } from '@prisma/client';
import {
  createQueueConnection,
  alertQueue,
  fraudQueue,
  webhookQueue,
  cleanupQueue,
  reconcileQueue,
} from '../lib/queue.js';
import { db } from '../lib/db.js';
import { GeoService } from '../services/geo.js';
import { AlertService } from '../services/alerts.js';
import { FraudDetectionService } from '../services/fraud.js';
import type { FraudAlertJobData } from '../services/alerts.js';
import { FeatureExtractionService } from '../services/feature-extraction.js';
import { DynamicRuleEngine } from '../services/dynamic-rules.js';
import { WebhookService } from '../services/webhook.js';
import type { WebhookJobData } from '../services/webhook.js';
import {
  SECURITY_WEBHOOK_JOB_NAME,
  SECURITY_WEBHOOK_BACKOFF,
  SECURITY_WEBHOOK_BACKOFF_MS,
  SECURITY_WEBHOOK_USER_AGENT,
  type SecurityWebhookJobData,
} from '../services/security-webhook.js';
import { checkAlgVersion, ALG_VERSION_POLICY } from '@qrauth/shared';
import { SigningService } from '../services/signing.js';
import {
  LocalEcdsaSigner,
  HttpEcdsaSigner,
  type EcdsaSigner,
} from '../services/ecdsa-signer/index.js';
import { config } from '../lib/config.js';
import { MacService } from '../services/mac.js';
import { hashString, stableStringify } from '../lib/crypto.js';
import type { BatchSigner } from '../services/batch-signer.js';
import { TransparencyLogService } from '../services/transparency.js';
import { ALGORITHM_VERSION_PENDING } from '../services/hybrid-signing.js';
import { revokeOrphanedPending } from '../services/pending-reconciler.js';

// ---------------------------------------------------------------------------
// Scan job payload
// ---------------------------------------------------------------------------

export interface ScanJobData {
  qrCodeId: string;
  clientIpHash: string;
  clientLat?: number;
  clientLng?: number;
  userAgent?: string;
  metadata?: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Service instantiation helpers
// ---------------------------------------------------------------------------

/**
 * Build the FraudDetectionService with all its dependencies wired up.
 * Each call returns a fresh set of service instances so workers that share
 * no state cannot interfere with each other.
 */
function buildFraudService(): FraudDetectionService {
  const geoService = new GeoService(db);
  // The alertService used inside fraud analysis enqueues jobs; we give it the
  // shared alertQueue rather than a dummy so real alerts are dispatched.
  const alertService = new AlertService(db, alertQueue);
  return new FraudDetectionService(db, geoService, alertService);
}

// ---------------------------------------------------------------------------
// Worker: qrauth-scans
// ---------------------------------------------------------------------------

/**
 * Records every QR-code scan to the database and triggers fraud analysis.
 *
 * 1. Insert a Scan row with the raw job data (trustScore defaults to 100).
 * 2. Run FraudDetectionService.analyzeScan() to detect anomalies.
 * 3. Patch the Scan row with the computed trustScore and proxyDetected flag.
 */
function createScanWorker(): Worker<ScanJobData> {
  return new Worker<ScanJobData>(
    'qrauth-scans',
    async (job: Job<ScanJobData>) => {
      const { qrCodeId, clientIpHash, clientLat, clientLng, userAgent, metadata } =
        job.data;

      // Step 1 – persist the scan record immediately so any downstream lookup
      // (e.g. geo-impossibility check) can see it.
      const scan = await db.scan.create({
        data: {
          qrCodeId,
          clientIpHash,
          clientLat: clientLat ?? null,
          clientLng: clientLng ?? null,
          userAgent: userAgent ?? null,
          metadata: (metadata ?? undefined) as Prisma.InputJsonValue | undefined,
          // trustScore and proxyDetected carry their schema defaults (100 / false)
          // until the fraud analysis patches them below.
        },
      });

      // Step 2 – run fraud analysis; this may create FraudIncident rows and
      // enqueue alert jobs when severity is HIGH or CRITICAL.
      const fraudService = buildFraudService();

      let trustScore = 100;
      let proxyDetected = false;
      let fraudResult = { trustScore: 100, incidents: [] as any[] };

      try {
        fraudResult = await fraudService.analyzeScan({
          qrCodeId,
          scanId: scan.id,
          clientIpHash,
          clientLat,
          clientLng,
          userAgent: userAgent ?? undefined,
          metadata,
        });

        trustScore = fraudResult.trustScore;
        proxyDetected =
          fraudResult.incidents.some((i: any) => i.type === 'PROXY_DETECTED');
      } catch (err) {
        // Fraud analysis failure must not block the scan record from being
        // committed – log and proceed with default values.
        console.error(
          `[scan-worker] fraud analysis failed for scan ${scan.id}:`,
          err,
        );
      }

      // Step 3 – update the scan with the final trust score and proxy flag.
      await db.scan.update({
        where: { id: scan.id },
        data: { trustScore, proxyDetected },
      });

      // Step 4 – enqueue feature extraction + dynamic rule evaluation (fire-and-forget).
      const qrCode = await db.qRCode.findUnique({
        where: { id: qrCodeId },
        select: {
          organizationId: true,
          token: true,
          algVersion: true,
          merkleBatchId: true,
        },
      });

      // Emit qr.scanned webhook (fire-and-forget).
      //
      // Webhook payloads now carry a `securityContext` block alongside
      // the existing fraud signals. The block tells consumers which
      // algorithm version the token was signed under and whether the
      // PQC leg is protecting it — operators can filter their incident
      // pipelines on `pqcProtected: false` to find tokens that still
      // need re-issuance. The alg_version surfaces cleanly even for
      // legacy ECDSA-only rows so the consumer never has to special-
      // case a missing field.
      if (qrCode?.organizationId) {
        const algVersion = qrCode.algVersion ?? ALG_VERSION_POLICY.hybrid;
        const webhookService = new WebhookService(db);
        webhookService.emit(qrCode.organizationId, {
          event: 'qr.scanned',
          data: {
            qrCodeId,
            scanId: scan.id,
            token: qrCode.token,
            trustScore,
            proxyDetected,
            securityContext: {
              algVersion,
              algVersionStatus: checkAlgVersion(algVersion),
              // After legacy-ecdsa drop every accepted row is PQC-protected.
              pqcProtected: true,
              merkleBatchId: qrCode.merkleBatchId ?? null,
            },
            payloadVersion: 'v2',
          },
        }).catch(() => {});
      }

      fraudQueue.add('extract-features', {
        scanId: scan.id,
        qrCodeId: job.data.qrCodeId,
        orgId: qrCode?.organizationId,
        clientIpHash: job.data.clientIpHash,
        userAgent: job.data.userAgent,
        trustScore: fraudResult.trustScore,
      }).catch(() => {}); // fire-and-forget
    },
    {
      connection: createQueueConnection(),
      concurrency: 10,
    },
  );
}

// ---------------------------------------------------------------------------
// Worker: qrauth-fraud
// ---------------------------------------------------------------------------

/**
 * Real-time feature extraction and dynamic rule evaluation worker.
 *
 * Receives jobs enqueued by the scan worker after inline fraud analysis.
 * Extracts Redis-backed feature vectors and evaluates dynamic DB rules,
 * creating additional FraudIncident rows for any newly fired rules.
 */
function createFraudWorker(): Worker {
  return new Worker(
    'qrauth-fraud',
    async (job: Job) => {
      const { scanId, qrCodeId, orgId, clientIpHash, userAgent, trustScore } = job.data;

      const featureService = new FeatureExtractionService();
      const ruleEngine = new DynamicRuleEngine(db);

      // 1. Extract features
      const features = await featureService.extractFeatures({
        qrCodeId,
        clientIpHash,
        userAgent,
        trustScore,
      });

      // 2. Evaluate dynamic rules
      const firedRules = await ruleEngine.evaluate(features);

      // 3. Create incidents for fired rules
      for (const result of firedRules) {
        try {
          await db.fraudIncident.create({
            data: {
              qrCodeId,
              scanId,
              type: result.action.type as any,
              severity: result.action.severity as any,
              details: {
                reason: result.action.reason,
                ruleName: result.ruleName,
                ruleId: result.ruleId,
                features,
              } as any,
            },
          });
        } catch {
          // Ignore duplicate incidents
        }
      }

      // 4. Store features for batch flush
      await featureService.storePendingFeatures(scanId || 'unknown', orgId || 'unknown', features);
    },
    {
      connection: createQueueConnection(),
      concurrency: 5,
    },
  );
}

// ---------------------------------------------------------------------------
// Worker: qrauth-alerts
// ---------------------------------------------------------------------------

/**
 * Processes fraud alert jobs added by AlertService.sendFraudAlert().
 * Delegates to AlertService.processAlertJob() which logs the incident and
 * is designed to be replaced with real notification dispatch (email / SMS /
 * webhook) without touching this wiring layer.
 */
function createAlertWorker(): Worker<FraudAlertJobData> {
  return new Worker<FraudAlertJobData>(
    'qrauth-alerts',
    async (job: Job<FraudAlertJobData>) => {
      // A fresh AlertService instance per job — alertQueue is only needed by
      // sendFraudAlert(), which is not called from within processAlertJob().
      // We pass alertQueue as a dummy to satisfy the constructor signature.
      const alertService = new AlertService(db, alertQueue);
      await alertService.processAlertJob(job);
    },
    {
      connection: createQueueConnection(),
      concurrency: 3,
    },
  );
}

// ---------------------------------------------------------------------------
// Worker: qrauth-webhooks
// ---------------------------------------------------------------------------

/**
 * Delivers webhook payloads to third-party app endpoints.
 *
 * Each job carries a pre-signed payload. On success (2xx), the WebhookDelivery
 * record is marked delivered. On failure the error is persisted and BullMQ
 * retries with exponential backoff. After all retries are exhausted the record
 * is marked permanently failed.
 */
function createWebhookWorker(): Worker<WebhookJobData | SecurityWebhookJobData> {
  return new Worker<WebhookJobData | SecurityWebhookJobData>(
    'qrauth-webhooks',
    async (job: Job<WebhookJobData | SecurityWebhookJobData>) => {
      // AUDIT-2 M-13: security-webhook deliveries live on the same
      // queue as the app-level webhook fanout so operators only have
      // one Redis surface to monitor. The two job shapes are
      // discriminated by `job.name` — anything we didn't tag as a
      // security delivery falls through to the legacy path below.
      if (job.name === SECURITY_WEBHOOK_JOB_NAME) {
        await deliverSecurityWebhook(job as Job<SecurityWebhookJobData>);
        return;
      }

      const { deliveryId, url, payload, signature, appId } = job.data as WebhookJobData;

      // SSRF protection: validate webhook URL before making the request
      const { isSafeWebhookUrl } = await import('../lib/url-validation.js');
      const urlCheck = isSafeWebhookUrl(url);
      if (!urlCheck.safe) {
        await db.webhookDelivery.update({
          where: { id: deliveryId },
          data: {
            attempts: 1,
            lastAttemptAt: new Date(),
            error: `Blocked: ${urlCheck.reason}`,
            failedAt: new Date(),
          },
        });
        return; // Don't retry — URL is permanently invalid
      }

      // Parse the event name from the stored payload for the header.
      let eventName = 'unknown';
      try {
        eventName = (JSON.parse(payload) as { event: string }).event;
      } catch {
        // Leave as 'unknown' if parsing fails.
      }

      const now = new Date();
      let statusCode: number | undefined;
      let responseBody: string | undefined;

      try {
        let response: Response;
        response = await fetch(url, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-QRAuth-Signature': `sha256=${signature}`,
            'X-QRAuth-Event': eventName,
            'User-Agent': 'QRAuth-Webhooks/1.0',
          },
          body: payload,
          signal: AbortSignal.timeout(10_000),
        });

        statusCode = response.status;
        // Limit response body to 100KB to prevent memory abuse
        const reader = response.body?.getReader();
        if (reader) {
          const chunks: Uint8Array[] = [];
          let totalSize = 0;
          const maxSize = 100_000;
          while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            totalSize += value.length;
            if (totalSize > maxSize) {
              reader.cancel();
              responseBody = '(response truncated — exceeded 100KB)';
              break;
            }
            chunks.push(value);
          }
          if (!responseBody) {
            responseBody = Buffer.concat(chunks).toString('utf-8');
          }
        }

        if (response.ok) {
          // Success — mark delivered.
          await db.webhookDelivery.update({
            where: { id: deliveryId },
            data: {
              statusCode,
              responseBody: responseBody ?? null,
              attempts: job.attemptsMade + 1,
              lastAttemptAt: now,
              deliveredAt: now,
            },
          });
          return;
        }

        // Non-2xx — record the failure and let BullMQ retry.
        await db.webhookDelivery.update({
          where: { id: deliveryId },
          data: {
            statusCode,
            responseBody: responseBody ?? null,
            attempts: job.attemptsMade + 1,
            lastAttemptAt: now,
            error: `HTTP ${statusCode}`,
            // Mark permanently failed only when this was the last attempt.
            ...(job.attemptsMade + 1 >= (job.opts.attempts ?? 5)
              ? { failedAt: now }
              : {}),
          },
        });

        throw new Error(`Webhook endpoint returned HTTP ${statusCode}`);
      } catch (err) {
        if (err instanceof Error && err.message.startsWith('Webhook endpoint returned')) {
          throw err; // already persisted above — re-throw for BullMQ retry
        }

        // Network / timeout error.
        const message = err instanceof Error ? err.message : String(err);

        await db.webhookDelivery.update({
          where: { id: deliveryId },
          data: {
            statusCode: statusCode ?? null,
            attempts: job.attemptsMade + 1,
            lastAttemptAt: now,
            error: message,
            ...(job.attemptsMade + 1 >= (job.opts.attempts ?? 5)
              ? { failedAt: now }
              : {}),
          },
        });

        throw err; // re-throw so BullMQ schedules the next retry
      }
    },
    {
      connection: createQueueConnection(),
      concurrency: 5,
      settings: {
        // AUDIT-2 M-13: custom backoff for security-webhook jobs so
        // the plan-spec 1s / 5s / 30s retry ladder is hit exactly.
        // Jobs with any other backoff type fall through to the
        // BullMQ default (zero delay).
        backoffStrategy: (attemptsMade: number, type?: string): number => {
          if (type !== SECURITY_WEBHOOK_BACKOFF) return 0;
          const delay = SECURITY_WEBHOOK_BACKOFF_MS[attemptsMade - 1];
          return typeof delay === 'number' ? delay : -1;
        },
      },
    },
  );
}

// ---------------------------------------------------------------------------
// Security webhook delivery (AUDIT-2 M-13)
// ---------------------------------------------------------------------------

/**
 * Delivers a `signing-key.created` security webhook to the org's
 * configured endpoint. Runs on the shared `qrauth-webhooks` worker,
 * discriminated by job name. On non-2xx or network failure the job is
 * re-thrown so BullMQ schedules the next retry; the custom backoff
 * strategy above produces 1s / 5s / 30s steps. Final failure is
 * logged with a distinctive prefix so operator log pipelines can
 * trigger on sustained delivery gaps.
 *
 * There is no `WebhookDelivery` row for these deliveries — the plan
 * spec does not require one, and the existing `WebhookDelivery`
 * model is tightly bound to `appId`, so reusing it would widen the
 * schema change beyond M-13's Files list. Console-level logs are the
 * authoritative record until a dedicated `SecurityWebhookDelivery`
 * table lands in a follow-up.
 */
async function deliverSecurityWebhook(job: Job<SecurityWebhookJobData>): Promise<void> {
  const { url, rawBody, signatureHeader, eventType, eventId, organizationId } = job.data;
  const attempt = job.attemptsMade + 1;
  const maxAttempts = job.opts.attempts ?? 1;

  // SSRF protection: same defence the legacy webhook path uses. An
  // integrator could (accidentally or deliberately) point their
  // endpoint at 169.254.169.254, localhost, or a cloud-metadata
  // service; refuse to reach out in that case.
  //
  // Narrow dev/test bypass: when the API runs under NODE_ENV !==
  // 'production' AND the host is an explicit loopback literal, allow
  // the delivery through so the E2E suite can capture the webhook on
  // a local HTTP server. Production is still fail-closed — the
  // bypass only exists on non-prod builds and does not widen the
  // legacy webhook path.
  const { isSafeWebhookUrl } = await import('../lib/url-validation.js');
  const urlCheck = isSafeWebhookUrl(url);
  let allowed = urlCheck.safe;
  if (!allowed && process.env.NODE_ENV !== 'production') {
    try {
      const host = new URL(url).hostname.toLowerCase();
      if (host === '127.0.0.1' || host === 'localhost' || host === '::1') {
        allowed = true;
      }
    } catch {
      // fall through — allowed stays false
    }
  }
  if (!allowed) {
    console.error(
      `[security-webhook] ${eventType} ${eventId} blocked for org ` +
        `${organizationId}: unsafe URL (${urlCheck.reason}). No retry.`,
    );
    return; // Don't retry — URL is permanently invalid.
  }

  let response: Response;
  try {
    response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-QRAuth-Event': eventType,
        'X-QRAuth-Signature': signatureHeader,
        'User-Agent': SECURITY_WEBHOOK_USER_AGENT,
      },
      body: rawBody,
      signal: AbortSignal.timeout(10_000),
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    console.warn(
      `[security-webhook] attempt ${attempt}/${maxAttempts} for ` +
        `${eventType} ${eventId} (org ${organizationId}) failed: ${message}`,
    );
    if (attempt >= maxAttempts) {
      console.error(
        `[security-webhook] SUSTAINED FAILURE: ${eventType} ${eventId} ` +
          `for org ${organizationId} exhausted ${maxAttempts} attempts ` +
          `against ${url} — operator alert.`,
      );
      return; // Swallow after final retry so BullMQ marks the job as failed.
    }
    throw err; // Re-throw so BullMQ schedules the next retry.
  }

  if (response.ok) {
    console.info(
      `[security-webhook] delivered ${eventType} ${eventId} for org ` +
        `${organizationId} → HTTP ${response.status} (attempt ${attempt}/${maxAttempts}).`,
    );
    return;
  }

  console.warn(
    `[security-webhook] attempt ${attempt}/${maxAttempts} for ${eventType} ` +
      `${eventId} (org ${organizationId}) got HTTP ${response.status}.`,
  );
  if (attempt >= maxAttempts) {
    console.error(
      `[security-webhook] SUSTAINED FAILURE: ${eventType} ${eventId} ` +
        `for org ${organizationId} exhausted ${maxAttempts} attempts ` +
        `against ${url} (last HTTP ${response.status}) — operator alert.`,
    );
    return;
  }
  throw new Error(`security webhook got HTTP ${response.status}`);
}

// ---------------------------------------------------------------------------
// Worker: qrauth-cleanup
// ---------------------------------------------------------------------------

/**
 * Runs periodic housekeeping tasks for data retention compliance.
 *
 * GDPR Art. 5(1)(e) / ISO 27001 A.8.10: Data should not be kept longer
 * than necessary for its purpose.
 *
 * Retention schedule:
 *   • AuthSession     — 24 hours after resolution/expiry
 *   • RefreshToken     — immediately after expiry + revocation
 *   • LoginEvent       — 90 days (security monitoring window)
 *   • Scan metadata    — 365 days (anonymise PII fields, keep aggregates)
 *   • AuditLog         — 730 days / 2 years (SOC 2 requires ≥1 year)
 */
function createCleanupWorker(): Worker {
  return new Worker(
    'qrauth-cleanup',
    async () => {
      // 1. Auth sessions — 24h after resolution
      const sessionCutoff = new Date(Date.now() - 24 * 60 * 60 * 1000);
      const { count: sessions } = await db.authSession.deleteMany({
        where: {
          OR: [
            { status: 'EXPIRED',  expiresAt:   { lt: sessionCutoff } },
            { status: { in: ['APPROVED', 'DENIED'] }, resolvedAt: { lt: sessionCutoff } },
          ],
        },
      });
      if (sessions > 0) {
        console.log(`[cleanup] Deleted ${sessions} expired auth sessions`);
      }

      // 2. Expired + revoked refresh tokens — clean up immediately
      const { count: tokens } = await db.refreshToken.deleteMany({
        where: {
          OR: [
            { expiresAt: { lt: new Date() } },
            { revokedAt: { not: null } },
          ],
        },
      });
      if (tokens > 0) {
        console.log(`[cleanup] Deleted ${tokens} expired/revoked refresh tokens`);
      }

      // 3. Login events — delete after 90 days
      const loginCutoff = new Date(Date.now() - 90 * 24 * 60 * 60 * 1000);
      const { count: loginEvents } = await db.loginEvent.deleteMany({
        where: { createdAt: { lt: loginCutoff } },
      });
      if (loginEvents > 0) {
        console.log(`[cleanup] Deleted ${loginEvents} login events older than 90 days`);
      }

      // 4. Scan metadata — anonymise PII after 365 days
      //    Keep the scan record for analytics, but strip IP hash and user agent.
      const scanCutoff = new Date(Date.now() - 365 * 24 * 60 * 60 * 1000);
      const { count: scans } = await db.scan.updateMany({
        where: {
          createdAt: { lt: scanCutoff },
          clientIpHash: { not: 'anonymized' },
        },
        data: {
          clientIpHash: 'anonymized',
          userAgent: null,
          metadata: undefined,
        },
      });
      if (scans > 0) {
        console.log(`[cleanup] Anonymised ${scans} scans older than 365 days`);
      }

      // 5. Audit logs — delete after 2 years (SOC 2 requires ≥1 year retention)
      const auditCutoff = new Date(Date.now() - 730 * 24 * 60 * 60 * 1000);
      const { count: auditLogs } = await db.auditLog.deleteMany({
        where: { createdAt: { lt: auditCutoff } },
      });
      if (auditLogs > 0) {
        console.log(`[cleanup] Deleted ${auditLogs} audit logs older than 2 years`);
      }

      // 6. Auto-revoke stale devices based on per-org DevicePolicy.autoRevokeAfterDays
      const policiesWithAutoRevoke = await db.devicePolicy.findMany({
        where: { autoRevokeAfterDays: { not: null } },
        select: { organizationId: true, autoRevokeAfterDays: true },
      });

      for (const policy of policiesWithAutoRevoke) {
        const cutoff = new Date(Date.now() - policy.autoRevokeAfterDays! * 24 * 60 * 60 * 1000);
        const { count: revoked } = await db.trustedDevice.updateMany({
          where: {
            user: {
              memberships: {
                some: { organizationId: policy.organizationId },
              },
            },
            trustLevel: { not: 'REVOKED' },
            lastSeenAt: { lt: cutoff },
          },
          data: { trustLevel: 'REVOKED', revokedAt: new Date() },
        });

        if (revoked > 0) {
          console.log(`[cleanup] Auto-revoked ${revoked} stale devices for org ${policy.organizationId} (policy: ${policy.autoRevokeAfterDays} days)`);
        }
      }

      // 7. Auto-rotate signing keys older than 90 days (ISO 27001 A.10.1.2)
      const keyRotationCutoff = new Date(Date.now() - 90 * 24 * 60 * 60 * 1000);
      const staleKeys = await db.signingKey.findMany({
        where: {
          status: 'ACTIVE',
          createdAt: { lt: keyRotationCutoff },
        },
        select: { organizationId: true, keyId: true },
      });

      if (staleKeys.length > 0) {
        let ecdsaSigner: EcdsaSigner;
        if (config.ecdsaSigner.backend === 'http') {
          ecdsaSigner = new HttpEcdsaSigner(config.ecdsaSigner.url!, config.ecdsaSigner.token!);
        } else {
          ecdsaSigner = new LocalEcdsaSigner();
        }
        const signingService = new SigningService(db, ecdsaSigner);
        // Deduplicate by org (each org has at most one active key)
        const orgIds = [...new Set(staleKeys.map((k) => k.organizationId))];
        for (const orgId of orgIds) {
          try {
            const newKey = await signingService.rotateKey(orgId);
            console.log(`[cleanup] Auto-rotated signing key for org ${orgId}: ${newKey.keyId}`);
          } catch (err) {
            console.error(`[cleanup] Failed to auto-rotate key for org ${orgId}:`, err);
          }
        }
      }

      // 8. MAC key lifecycle (ALGORITHM.md §10.3). Three transitions, each
      //    age-gated:
      //      ACTIVE   → ROTATED  after 90 days  (mints a fresh ACTIVE row)
      //      ROTATED  → RETIRED  30 days after rotation (grace window over)
      //      RETIRED  → deleted   7 days after retirement (purge)
      //
      //    Rotation grouped by organization since each org owns its own
      //    versioned key ring. The 30-day grace window is long enough for
      //    in-flight QRs signed under the previous key to still verify on
      //    the fast path; after grace they fall through to the asymmetric
      //    legs, which is the correct degradation.
      const macRotationCutoff = new Date(Date.now() - 90 * 24 * 60 * 60 * 1000);
      const staleMacKeys = await db.orgMacKey.findMany({
        where: {
          status: 'ACTIVE',
          createdAt: { lt: macRotationCutoff },
        },
        select: { organizationId: true, version: true },
      });

      if (staleMacKeys.length > 0) {
        const macService = new MacService(db);
        const orgIds = [...new Set(staleMacKeys.map((k) => k.organizationId))];
        for (const orgId of orgIds) {
          try {
            const next = await macService.rotateKey(orgId);
            console.log(`[cleanup] Rotated MAC key for org ${orgId}: v${next.version}`);
          } catch (err) {
            console.error(`[cleanup] Failed to rotate MAC key for org ${orgId}:`, err);
          }
        }
      }

      // 9. Retire MAC keys whose 30-day grace window has elapsed. Once a key
      //    is RETIRED it is no longer offered to MacService.verifyCanonical,
      //    so any QR still bearing this version's MAC will miss the fast
      //    path and fall through to ECDSA + Merkle (which is fine — the
      //    asymmetric legs remain authoritative).
      const macRetirementCutoff = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
      const { count: retiredMacKeys } = await db.orgMacKey.updateMany({
        where: {
          status: 'ROTATED',
          rotatedAt: { lt: macRetirementCutoff },
        },
        data: { status: 'RETIRED', retiredAt: new Date() },
      });
      if (retiredMacKeys > 0) {
        console.log(`[cleanup] Retired ${retiredMacKeys} MAC keys past 30-day grace window`);
      }

      // 10. Purge RETIRED MAC keys whose secrets have been unused for 7 days.
      //     Hard delete: the secret bytes are gone for good. By this point
      //     no in-flight verify can possibly reach this version (any QR
      //     scanned now would have fallen through 7+ days ago).
      const macPurgeCutoff = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
      const { count: purgedMacKeys } = await db.orgMacKey.deleteMany({
        where: {
          status: 'RETIRED',
          retiredAt: { lt: macPurgeCutoff },
        },
      });
      if (purgedMacKeys > 0) {
        console.log(`[cleanup] Purged ${purgedMacKeys} retired MAC keys (>7d past retirement)`);
      }
    },
    {
      connection: createQueueConnection(),
      concurrency: 1,
    },
  );
}

// ---------------------------------------------------------------------------
// Worker: qrauth-reconcile
// ---------------------------------------------------------------------------

/**
 * Recovers QR rows stuck in the `ecdsa-pending-slhdsa-v1` state.
 *
 * Single QR creation takes the async issuance path: ECDSA leg returns
 * synchronously, merkle leg fires through the BatchSigner. The route's
 * inline `.then()` handler upgrades the row when the batch flushes — but
 * if the process crashes between insert and flush, or if the SLH-DSA sign
 * itself fails, the row is left pending forever. This worker is the
 * safety net.
 *
 * Strategy: every minute, find rows older than 5 minutes still in the
 * pending state. Re-enqueue each through the SAME process-wide
 * BatchSigner that route handlers use, so reconciler-driven QRs land in
 * the same batches as live traffic. On success, update the row + write
 * the commitment-only transparency log entry.
 *
 * The 5-minute stale threshold is comfortably longer than any healthy
 * batch flush window (200ms wait + ~2.3s SLH-DSA sign), so fresh pending
 * rows are never touched by the reconciler.
 */
function createReconcileWorker(batchSigner: BatchSigner): Worker {
  return new Worker(
    'qrauth-reconcile',
    async () => {
      const staleCutoff = new Date(Date.now() - 5 * 60 * 1000);
      const stale = await db.qRCode.findMany({
        where: {
          algVersion: ALGORITHM_VERSION_PENDING,
          createdAt: { lt: staleCutoff },
        },
        select: {
          id: true,
          token: true,
          organizationId: true,
          contentType: true,
          content: true,
          destinationUrl: true,
          geoHash: true,
          latitude: true,
          longitude: true,
          radiusM: true,
          expiresAt: true,
          signingKeyId: true,
          signingKey: { select: { keyId: true, slhdsaPublicKey: true } },
        },
        take: 100,
      });

      if (stale.length === 0) return;
      console.log(`[reconcile] found ${stale.length} stale ecdsa-pending QR(s)`);

      const transparencyService = new TransparencyLogService(db);

      // Process sequentially so a single failing row doesn't mass-reject a
      // batch that contained other healthy reconciler enqueues. The
      // BatchSigner amortizes across the row set automatically.
      for (const row of stale) {
        if (!row.signingKey.slhdsaPublicKey) {
          console.warn(
            `[reconcile] qrCode ${row.id} signing key has no SLH-DSA material; cannot reconcile`,
          );
          continue;
        }

        try {
          let rowContentHashHex = '';
          if (row.content && row.contentType !== 'url') {
            rowContentHashHex = hashString(stableStringify(row.content));
          }
          const batch = await batchSigner.enqueue({
            organizationId: row.organizationId,
            signingKeyDbId: row.signingKeyId,
            signingKeyId: row.signingKey.keyId,
            payload: {
              algVersion: ALG_VERSION_POLICY.hybrid,
              token: row.token,
              tenantId: row.organizationId,
              contentType: row.contentType ?? 'url',
              destinationUrl: row.destinationUrl,
              contentHashHex: rowContentHashHex,
              lat: row.latitude,
              lng: row.longitude,
              radiusM: row.radiusM,
              expiresAt: row.expiresAt?.toISOString() ?? '',
            },
          });

          await db.qRCode.update({
            where: { id: row.id },
            data: {
              algVersion: batch.algVersion,
              merkleBatchId: batch.batchId,
              merkleLeafIndex: batch.leafIndex,
              merkleLeafHash: batch.leafHash,
              merkleLeafNonce: batch.leafNonce,
              merklePath: batch.merklePath as never,
            },
          });

          // The original async handler also writes the transparency log.
          // It may have succeeded or failed before the crash. Use upsert
          // semantics: if an entry already exists for this qrCodeId, the
          // unique constraint kicks in and we swallow the error — the
          // existing entry is good enough.
          try {
            await transparencyService.appendEntry({
              id: row.id,
              token: row.token,
              organizationId: row.organizationId,
              destinationUrl: row.destinationUrl,
              geoHash: row.geoHash,
              pqc: {
                algVersion: batch.algVersion,
                leafHash: batch.leafHash,
                batchRootRef: TransparencyLogService.computeBatchRootRef(batch.merkleRoot),
                merkleInclusionProof: batch.merklePath,
              },
            });
          } catch (err) {
            // Unique violation on qrCodeId is benign — entry already exists
            // from a prior partial reconcile. Anything else is worth logging.
            const msg = (err as Error)?.message ?? '';
            if (!msg.includes('Unique constraint')) {
              console.warn(`[reconcile] qrCode ${row.id} transparency append failed:`, msg);
            }
          }

          console.log(`[reconcile] upgraded qrCode ${row.id} → hybrid (batch ${batch.batchId.slice(0, 16)}…)`);
          // AUDIT-2 N-1 counter. Structured log line — matches the
          // `[pending-reconciler] pqc_orphaned` prefix on the revoke
          // path so operator log pipelines can compute both rates
          // against the same rescue worker tick.
          console.log(`[pending-reconciler] pqc_promoted qr=${row.id} org=${row.organizationId} batch=${batch.batchId.slice(0, 16)}`);
        } catch (err) {
          console.error(`[reconcile] qrCode ${row.id} reconcile failed:`, (err as Error).message);
          // Leave the row pending. The next rescue tick may succeed;
          // if not, the N-1 revoke branch below terminates the row
          // at the 1-hour mark.
        }
      }

      // AUDIT-2 N-1 revoke branch. After the rescue loop has had
      // its chance, sweep any pending rows older than 1 hour and
      // revoke them as orphaned. The thresholds are strictly
      // ordered (5 min rescue, 1 h revoke) so a row reaching the
      // revoke branch has already been re-enqueued multiple times
      // without success. Webhook emission goes through the
      // app-level WebhookService — NOT the M-13 security webhook —
      // because this is operational information for the integrator,
      // not a T-9 security event.
      try {
        const result = await revokeOrphanedPending({
          prisma: db,
          webhookService: new WebhookService(db),
        });
        if (result.revoked > 0) {
          console.log(
            `[pending-reconciler] revoke-tick scanned=${result.scanned} revoked=${result.revoked} webhooks=${result.webhooksEmitted}`,
          );
        }
      } catch (err) {
        // Revoke-branch failure must never abort the worker. The
        // rescue path above has already run for this tick; retry
        // the revoke on the next 60 s tick.
        console.error(
          '[pending-reconciler] revoke branch failed:',
          (err as Error).message,
        );
      }
    },
    {
      connection: createQueueConnection(),
      concurrency: 1,
    },
  );
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

let scanWorker: Worker<ScanJobData> | null = null;
let fraudWorker: Worker | null = null;
let alertWorker: Worker<FraudAlertJobData> | null = null;
let webhookWorker: Worker<WebhookJobData | SecurityWebhookJobData> | null = null;
let cleanupWorker: Worker | null = null;
let reconcileWorker: Worker | null = null;

/**
 * Instantiate and start all BullMQ workers.
 * Returns all worker instances so callers can attach event listeners
 * or inspect their state if needed.
 */
export function registerWorkers(batchSigner: BatchSigner): {
  scanWorker: Worker<ScanJobData>;
  fraudWorker: Worker;
  alertWorker: Worker<FraudAlertJobData>;
  webhookWorker: Worker<WebhookJobData | SecurityWebhookJobData>;
  cleanupWorker: Worker;
  reconcileWorker: Worker;
} {
  scanWorker = createScanWorker();
  fraudWorker = createFraudWorker();
  alertWorker = createAlertWorker();
  webhookWorker = createWebhookWorker();
  cleanupWorker = createCleanupWorker();
  reconcileWorker = createReconcileWorker(batchSigner);

  scanWorker.on('failed', (job, err) => {
    console.error(`[scan-worker] job ${job?.id} failed:`, err.message);
  });

  fraudWorker.on('failed', (job, err) => {
    console.error(`[fraud-worker] job ${job?.id} failed:`, err.message);
  });

  alertWorker.on('failed', (job, err) => {
    console.error(`[alert-worker] job ${job?.id} failed:`, err.message);
  });

  webhookWorker.on('failed', (job, err) => {
    console.error(`[webhook-worker] job ${job?.id} failed:`, err.message);
  });

  cleanupWorker.on('failed', (job, err) => {
    console.error(`[cleanup-worker] job ${job?.id} failed:`, err.message);
  });

  reconcileWorker.on('failed', (job, err) => {
    console.error(`[reconcile-worker] job ${job?.id} failed:`, err.message);
  });

  // Schedule the hourly repeating cleanup job.  addJob is idempotent when the
  // same jobId already exists, so restarting the process does not pile up
  // duplicate schedules.
  cleanupQueue
    .add('cleanup', {}, {
      repeat:  { every: 60 * 60 * 1000 },
      jobId:   'session-cleanup',
    })
    .catch((err) => console.error('[cleanup] Failed to schedule cleanup job:', err));

  // Schedule the merkle reconciler — runs every 60s. Same idempotent
  // jobId pattern so restart doesn't stack schedules.
  reconcileQueue
    .add('reconcile', {}, {
      repeat: { every: 60 * 1000 },
      jobId: 'merkle-reconcile',
    })
    .catch((err) => console.error('[reconcile] Failed to schedule reconcile job:', err));

  console.info('[workers] scan, fraud, alert, webhook, cleanup, and reconcile workers registered.');

  return { scanWorker, fraudWorker, alertWorker, webhookWorker, cleanupWorker, reconcileWorker };
}

/**
 * Gracefully close all running workers.
 * Waits for active jobs to finish before tearing down connections.
 */
export async function closeWorkers(): Promise<void> {
  await Promise.all([
    scanWorker?.close(),
    fraudWorker?.close(),
    alertWorker?.close(),
    webhookWorker?.close(),
    cleanupWorker?.close(),
    reconcileWorker?.close(),
  ]);

  scanWorker = null;
  fraudWorker = null;
  alertWorker = null;
  webhookWorker = null;
  cleanupWorker = null;
  reconcileWorker = null;

  console.info('[workers] all workers closed.');
}
