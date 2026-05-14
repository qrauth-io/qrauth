import type { PrismaClient } from '@prisma/client';
import type { Job, Queue } from 'bullmq';
import { sendFraudAlertEmail } from '../lib/email.js';

// ---------------------------------------------------------------------------
// Job payload shapes
// ---------------------------------------------------------------------------

export interface FraudIncidentRef {
  id: string;
  type: string;
  severity: string;
  qrCodeId: string;
}

export interface FraudAlertJobData {
  organizationId: string;
  incident: FraudIncidentRef;
}

// ---------------------------------------------------------------------------
// AlertService
// ---------------------------------------------------------------------------

export class AlertService {
  constructor(
    private prisma: PrismaClient,
    private alertQueue: Queue,
  ) {}

  /**
   * Enqueue a fraud alert job for async delivery.
   *
   * The job is added to the alertQueue with the incident details and the
   * organization ID so the worker can look up contact information at processing
   * time (where the data is guaranteed to be current).
   *
   * @param organizationId - ID of the organization whose QR code was involved.
   * @param incident - Summary of the fraud incident.
   */
  async sendFraudAlert(
    organizationId: string,
    incident: FraudIncidentRef,
  ): Promise<void> {
    const jobData: FraudAlertJobData = { organizationId, incident };

    await this.alertQueue.add('fraud-alert', jobData, {
      // Use the incident ID as the job ID so we avoid duplicate alerts when
      // the same incident triggers multiple code paths concurrently.
      jobId: `fraud-alert:${incident.id}`,
    });
  }

  /**
   * BullMQ worker handler for 'fraud-alert' jobs.
   *
   * For the MVP this logs the alert details to stdout. In production this
   * method would dispatch emails, webhooks, or SMS notifications.
   *
   * @param job - BullMQ Job containing FraudAlertJobData in job.data.
   */
  async processAlertJob(job: Job<FraudAlertJobData>): Promise<void> {
    const { organizationId, incident } = job.data;

    // Look up the organization's contact details so the log line is informative.
    const organization = await this.prisma.organization.findUnique({
      where: { id: organizationId },
      select: { name: true, email: true },
    });

    if (!organization) {
      // The organization may have been deleted between enqueue and processing.
      console.warn(
        `[alerts] fraud-alert job ${job.id}: organization "${organizationId}" not found — skipping.`,
      );
      return;
    }

    console.log(
      `FRAUD ALERT: [${incident.severity.toUpperCase()}] [${incident.type}] ` +
        `for organization ${organization.name} (${organization.email}) — ` +
        `incident ${incident.id} on QR code ${incident.qrCodeId}`,
    );

    if (organization.email) {
      await sendFraudAlertEmail(
        organization.email,
        organization.name,
        {
          type: incident.type,
          severity: incident.severity,
          qrCodeToken: incident.qrCodeId,
        },
      );
    }
  }
}
