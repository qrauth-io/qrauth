import { Worker } from 'bullmq';
import type { Job } from 'bullmq';
import type { Prisma } from '@prisma/client';
import { createQueueConnection, alertQueue, fraudQueue, webhookQueue } from '../lib/queue.js';
import { db } from '../lib/db.js';
import { GeoService } from '../services/geo.js';
import { AlertService } from '../services/alerts.js';
import { FraudDetectionService } from '../services/fraud.js';
import type { FraudAlertJobData } from '../services/alerts.js';
import { FeatureExtractionService } from '../services/feature-extraction.js';
import { DynamicRuleEngine } from '../services/dynamic-rules.js';
import { WebhookService } from '../services/webhook.js';
import type { WebhookJobData } from '../services/webhook.js';

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
        select: { organizationId: true },
      });

      // Emit qr.scanned webhook (fire-and-forget).
      if (qrCode?.organizationId) {
        const webhookService = new WebhookService(db);
        webhookService.emit(qrCode.organizationId, {
          event: 'qr.scanned',
          data: { qrCodeId, scanId: scan.id, trustScore, proxyDetected },
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
function createWebhookWorker(): Worker<WebhookJobData> {
  return new Worker<WebhookJobData>(
    'qrauth-webhooks',
    async (job: Job<WebhookJobData>) => {
      const { deliveryId, url, payload, signature, appId } = job.data;

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
        responseBody = await response.text().catch(() => undefined);

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
    },
  );
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

let scanWorker: Worker<ScanJobData> | null = null;
let fraudWorker: Worker | null = null;
let alertWorker: Worker<FraudAlertJobData> | null = null;
let webhookWorker: Worker<WebhookJobData> | null = null;

/**
 * Instantiate and start all BullMQ workers.
 * Returns all worker instances so callers can attach event listeners
 * or inspect their state if needed.
 */
export function registerWorkers(): {
  scanWorker: Worker<ScanJobData>;
  fraudWorker: Worker;
  alertWorker: Worker<FraudAlertJobData>;
  webhookWorker: Worker<WebhookJobData>;
} {
  scanWorker = createScanWorker();
  fraudWorker = createFraudWorker();
  alertWorker = createAlertWorker();
  webhookWorker = createWebhookWorker();

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

  console.info('[workers] scan, fraud, alert, and webhook workers registered.');

  return { scanWorker, fraudWorker, alertWorker, webhookWorker };
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
  ]);

  scanWorker = null;
  fraudWorker = null;
  alertWorker = null;
  webhookWorker = null;

  console.info('[workers] all workers closed.');
}
