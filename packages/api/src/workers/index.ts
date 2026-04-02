import { Worker } from 'bullmq';
import type { Job } from 'bullmq';
import type { Prisma } from '@prisma/client';
import { createQueueConnection, alertQueue, fraudQueue } from '../lib/queue.js';
import { db } from '../lib/db.js';
import { GeoService } from '../services/geo.js';
import { AlertService } from '../services/alerts.js';
import { FraudDetectionService } from '../services/fraud.js';
import type { FraudAlertJobData } from '../services/alerts.js';
import { FeatureExtractionService } from '../services/feature-extraction.js';
import { DynamicRuleEngine } from '../services/dynamic-rules.js';

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
// Worker: vqr-scans
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
    'vqr-scans',
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
// Worker: vqr-fraud
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
    'vqr-fraud',
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
// Worker: vqr-alerts
// ---------------------------------------------------------------------------

/**
 * Processes fraud alert jobs added by AlertService.sendFraudAlert().
 * Delegates to AlertService.processAlertJob() which logs the incident and
 * is designed to be replaced with real notification dispatch (email / SMS /
 * webhook) without touching this wiring layer.
 */
function createAlertWorker(): Worker<FraudAlertJobData> {
  return new Worker<FraudAlertJobData>(
    'vqr-alerts',
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
// Public API
// ---------------------------------------------------------------------------

let scanWorker: Worker<ScanJobData> | null = null;
let fraudWorker: Worker | null = null;
let alertWorker: Worker<FraudAlertJobData> | null = null;

/**
 * Instantiate and start all BullMQ workers.
 * Returns the three worker instances so callers can attach event listeners
 * or inspect their state if needed.
 */
export function registerWorkers(): {
  scanWorker: Worker<ScanJobData>;
  fraudWorker: Worker;
  alertWorker: Worker<FraudAlertJobData>;
} {
  scanWorker = createScanWorker();
  fraudWorker = createFraudWorker();
  alertWorker = createAlertWorker();

  scanWorker.on('failed', (job, err) => {
    console.error(`[scan-worker] job ${job?.id} failed:`, err.message);
  });

  fraudWorker.on('failed', (job, err) => {
    console.error(`[fraud-worker] job ${job?.id} failed:`, err.message);
  });

  alertWorker.on('failed', (job, err) => {
    console.error(`[alert-worker] job ${job?.id} failed:`, err.message);
  });

  console.info('[workers] scan, fraud, and alert workers registered.');

  return { scanWorker, fraudWorker, alertWorker };
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
  ]);

  scanWorker = null;
  fraudWorker = null;
  alertWorker = null;

  console.info('[workers] all workers closed.');
}
