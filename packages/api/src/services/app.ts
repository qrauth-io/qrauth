import type { PrismaClient } from '@prisma/client';
import { randomBytes, createHash, timingSafeEqual } from 'node:crypto';

export class AppService {
  constructor(private prisma: PrismaClient) {}

  /**
   * Generate a client ID and secret for an app.
   * clientId: "qrauth_app_" + 16 random hex chars (public, shown in dashboards)
   * clientSecret: "qrauth_secret_" + 64 random hex chars (shown ONCE at creation)
   * We store only the SHA-256 hash of the secret.
   */
  generateCredentials(): { clientId: string; clientSecret: string; clientSecretHash: string } {
    const clientId = `qrauth_app_${randomBytes(8).toString('hex')}`;
    const clientSecret = `qrauth_secret_${randomBytes(32).toString('hex')}`;
    const clientSecretHash = createHash('sha256').update(clientSecret).digest('hex');
    return { clientId, clientSecret, clientSecretHash };
  }

  /**
   * Verify a client secret against the stored hash using constant-time comparison.
   */
  verifySecret(providedSecret: string, storedHash: string): boolean {
    const providedHash = createHash('sha256').update(providedSecret).digest('hex');
    try {
      return timingSafeEqual(Buffer.from(providedHash, 'hex'), Buffer.from(storedHash, 'hex'));
    } catch {
      return false;
    }
  }

  /**
   * Create a new app for an organization.
   * Returns the app record PLUS the raw clientSecret (shown once).
   */
  async createApp(organizationId: string, data: {
    name: string;
    description?: string;
    redirectUrls: string[];
    webhookUrl?: string;
    allowedScopes?: string[];
    logoUrl?: string;
  }) {
    const { clientId, clientSecret, clientSecretHash } = this.generateCredentials();

    // Generate slug from name
    const baseSlug = data.name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
    // Check uniqueness, append random suffix if needed
    const existing = await this.prisma.app.findUnique({ where: { slug: baseSlug } });
    const slug = existing ? `${baseSlug}-${randomBytes(2).toString('hex')}` : baseSlug;

    const app = await this.prisma.app.create({
      data: {
        organizationId,
        name: data.name,
        slug,
        clientId,
        clientSecretHash,
        redirectUrls: data.redirectUrls,
        webhookUrl: data.webhookUrl,
        allowedScopes: data.allowedScopes ?? ['identity'],
        logoUrl: data.logoUrl,
        description: data.description,
      },
    });

    return { ...app, clientSecret }; // clientSecret returned ONLY here
  }

  /**
   * List apps for an organization.
   */
  async listApps(organizationId: string) {
    return this.prisma.app.findMany({
      where: { organizationId, status: { not: 'DELETED' } },
      orderBy: { createdAt: 'desc' },
      select: {
        id: true,
        name: true,
        slug: true,
        clientId: true,
        redirectUrls: true,
        webhookUrl: true,
        allowedScopes: true,
        logoUrl: true,
        description: true,
        status: true,
        createdAt: true,
        updatedAt: true,
        _count: { select: { authSessions: true } },
      },
    });
  }

  /**
   * Get a single app by ID. Verifies org ownership.
   */
  async getApp(appId: string, organizationId: string) {
    const app = await this.prisma.app.findUnique({
      where: { id: appId },
      include: {
        _count: { select: { authSessions: true } },
      },
    });
    if (!app || app.organizationId !== organizationId) return null;
    if (app.status === 'DELETED') return null;
    return app;
  }

  /**
   * Update app fields.
   */
  async updateApp(appId: string, organizationId: string, data: {
    name?: string;
    description?: string;
    redirectUrls?: string[];
    webhookUrl?: string;
    allowedScopes?: string[];
    logoUrl?: string;
  }) {
    const app = await this.getApp(appId, organizationId);
    if (!app) throw new Error('App not found');

    return this.prisma.app.update({
      where: { id: appId },
      data: {
        ...data,
        ...(data.name ? { slug: data.name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '') } : {}),
      },
    });
  }

  /**
   * Soft-delete an app.
   */
  async deleteApp(appId: string, organizationId: string) {
    const app = await this.getApp(appId, organizationId);
    if (!app) throw new Error('App not found');

    return this.prisma.app.update({
      where: { id: appId },
      data: { status: 'DELETED' },
    });
  }

  /**
   * Rotate the client secret. Returns the new raw secret (shown once).
   */
  async rotateSecret(appId: string, organizationId: string) {
    const app = await this.getApp(appId, organizationId);
    if (!app) throw new Error('App not found');

    const clientSecret = `qrauth_secret_${randomBytes(32).toString('hex')}`;
    const clientSecretHash = createHash('sha256').update(clientSecret).digest('hex');

    await this.prisma.app.update({
      where: { id: appId },
      data: { clientSecretHash },
    });

    return { clientSecret }; // shown once
  }

  /**
   * Authenticate an app by clientId + clientSecret.
   * Used by third-party apps calling the auth-sessions endpoints.
   */
  async authenticateApp(clientId: string, clientSecret: string) {
    const app = await this.prisma.app.findUnique({
      where: { clientId },
    });
    if (!app || app.status !== 'ACTIVE') return null;
    if (!this.verifySecret(clientSecret, app.clientSecretHash)) return null;
    return app;
  }
}
