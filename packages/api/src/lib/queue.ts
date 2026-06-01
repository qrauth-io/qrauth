import { Queue, QueueOptions } from 'bullmq';
import { Redis } from 'ioredis';
import { config } from './config.js';

// ---------------------------------------------------------------------------
// Connection factory
// ---------------------------------------------------------------------------

/**
 * Create a dedicated ioredis connection suitable for BullMQ.
 *
 * BullMQ requires its own connection instances – it must not share a
 * connection that is also used for pub/sub or blocking commands.
 * Each call to this function returns a fresh connection.
 */
export function createQueueConnection(): Redis {
  return new Redis(config.redis.url, {
    // BullMQ calls BLPOP and similar blocking commands, so we disable the
    // ready-check which is incompatible with those command sets.
    enableReadyCheck: false,
    maxRetriesPerRequest: null,
    retryStrategy(times: number) {
      return Math.min(times * 100, 30_000);
    },
  });
}

// ---------------------------------------------------------------------------
// Shared queue defaults
// ---------------------------------------------------------------------------

const sharedQueueOptions: Partial<QueueOptions> = {
  defaultJobOptions: {
    removeOnComplete: {
      // Keep last 500 completed jobs for observability.
      count: 500,
    },
    removeOnFail: {
      // Retain failed jobs for 7 days for post-mortem investigation.
      age: 7 * 24 * 60 * 60,
    },
    attempts: 3,
    backoff: {
      type: 'exponential',
      delay: 1_000,
    },
  },
};

// ---------------------------------------------------------------------------
// Named queues
// ---------------------------------------------------------------------------

/**
 * Receives a job for every QR code scan.
 * Processors run fraud checks, update trust scores, and write Scan records.
 */
export const scanQueue = new Queue('qrauth-scans', {
  connection: createQueueConnection(),
  ...sharedQueueOptions,
});

/**
 * Receives fraud-detection jobs triggered by the scan processor or manual
 * reports. Processors classify, persist FraudIncidents, and may enqueue
 * alert jobs.
 */
export const fraudQueue = new Queue('qrauth-fraud', {
  connection: createQueueConnection(),
  ...sharedQueueOptions,
  defaultJobOptions: {
    ...sharedQueueOptions.defaultJobOptions,
    // Fraud jobs are higher priority – retry faster.
    backoff: {
      type: 'exponential',
      delay: 500,
    },
  },
});

/**
 * Handles outbound alert delivery (webhooks, emails, SMS) when fraud
 * incidents exceed a severity threshold or require issuer notification.
 */
export const alertQueue = new Queue('qrauth-alerts', {
  connection: createQueueConnection(),
  ...sharedQueueOptions,
  defaultJobOptions: {
    ...sharedQueueOptions.defaultJobOptions,
    attempts: 5,
    backoff: {
      type: 'exponential',
      delay: 2_000,
    },
  },
});

/**
 * Delivers outbound webhook events to third-party app endpoints.
 * Uses exponential backoff with up to 5 attempts to ensure reliable delivery.
 */
export const webhookQueue = new Queue('qrauth-webhooks', {
  connection: createQueueConnection(),
  ...sharedQueueOptions,
  defaultJobOptions: {
    ...sharedQueueOptions.defaultJobOptions,
    attempts: 5,
    backoff: {
      type: 'exponential',
      delay: 2_000,
    },
  },
});

/**
 * Drives periodic housekeeping tasks (e.g. expired auth-session deletion).
 * A single repeating job is scheduled by the worker registration code.
 */
export const cleanupQueue = new Queue('qrauth-cleanup', {
  connection: createQueueConnection(),
  ...sharedQueueOptions,
});

/**
 * Drives the merkle reconciler — finds QR rows stuck in
 * `ecdsa-pending-slhdsa-v1` and re-enqueues their SLH-DSA leg.
 *
 * Async issuance returns the ECDSA leg synchronously and fires the merkle
 * sign in the background. If the process restarts (or the merkle sign
 * fails) before the upgrade lands, the row stays pending. This queue runs
 * a fast cadence (~60s) so stuck rows are picked up promptly — much
 * shorter than the hourly cleanup pass.
 */
export const reconcileQueue = new Queue('qrauth-reconcile', {
  connection: createQueueConnection(),
  ...sharedQueueOptions,
});

// ---------------------------------------------------------------------------
// Shutdown helper
// ---------------------------------------------------------------------------

/**
 * Gracefully close all queue instances and their underlying Redis connections.
 * Call this during process shutdown before disconnecting the main Redis client.
 */
export async function closeQueues(): Promise<void> {
  await Promise.all([
    scanQueue.close(),
    fraudQueue.close(),
    alertQueue.close(),
    webhookQueue.close(),
    cleanupQueue.close(),
    reconcileQueue.close(),
  ]);
}
