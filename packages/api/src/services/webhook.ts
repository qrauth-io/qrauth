import { createHmac } from 'node:crypto';
import type { PrismaClient } from '@prisma/client';
import { webhookQueue } from '../lib/queue.js';

export interface WebhookEvent {
  event: string;
  data: Record<string, unknown>;
}

export interface WebhookJobData {
  deliveryId: string;
  url: string;
  payload: string; // JSON string
  signature: string;
  appId: string;
}

export class WebhookService {
  constructor(private prisma: PrismaClient) {}

  /**
   * Enqueue webhook delivery for all apps in the organization that have a webhookUrl.
   */
  async emit(organizationId: string, event: WebhookEvent): Promise<void> {
    const apps = await this.prisma.app.findMany({
      where: {
        organizationId,
        status: 'ACTIVE',
        webhookUrl: { not: null },
      },
      select: {
        id: true,
        webhookUrl: true,
        clientSecretHash: true,
      },
    });

    for (const app of apps) {
      if (!app.webhookUrl) continue;

      const payload = JSON.stringify({
        event: event.event,
        timestamp: new Date().toISOString(),
        data: event.data,
      });

      // Sign with HMAC-SHA256 using the app's client secret hash as the key
      const signature = createHmac('sha256', app.clientSecretHash)
        .update(payload)
        .digest('hex');

      const delivery = await this.prisma.webhookDelivery.create({
        data: {
          appId: app.id,
          event: event.event,
          url: app.webhookUrl,
          payload: JSON.parse(payload),
        },
      });

      await webhookQueue.add('deliver', {
        deliveryId: delivery.id,
        url: app.webhookUrl,
        payload,
        signature,
        appId: app.id,
      } satisfies WebhookJobData);
    }
  }
}
