import type {
  FraudIncident,
  FraudSeverity,
  FraudType,
  PrismaClient,
  Prisma,
} from '@prisma/client';
import type { AlertService } from './alerts.js';
import { haversineDistance, type GeoService } from './geo.js';

// ---------------------------------------------------------------------------
// Input / output shapes
// ---------------------------------------------------------------------------

export interface ScanAnalysisInput {
  qrCodeId: string;
  clientIpHash: string;
  clientLat?: number;
  clientLng?: number;
  metadata?: Record<string, unknown>;
}

export interface ScanAnalysisResult {
  trustScore: number;
  incidents: FraudIncident[];
}

export interface ReportIncidentInput {
  qrCodeId: string;
  scanId?: string;
  type: FraudType;
  severity: FraudSeverity;
  details: Record<string, unknown>;
}

export interface GetIncidentsOptions {
  resolved?: boolean;
  severity?: FraudSeverity;
  page: number;
  pageSize: number;
}

// ---------------------------------------------------------------------------
// Internal constants
// ---------------------------------------------------------------------------

/**
 * Radius in metres within which a second QR code from a *different* organization
 * is considered a duplicate-location conflict.
 */
const DUPLICATE_LOCATION_RADIUS_M = 20;

/**
 * Maximum believable travel distance (metres) in a 30-minute window.
 * ~500 km / 30 min ≈ 1000 km/h, faster than any commercial aircraft at
 * cruise altitude — treat this as geo-impossible.
 */
const GEO_IMPOSSIBLE_DISTANCE_M = 500_000;
const GEO_IMPOSSIBLE_WINDOW_MS = 30 * 60 * 1000; // 30 minutes

// Trust-score deductions per detected fraud signal.
const DEDUCTION = {
  DUPLICATE_LOCATION: 30,
  PROXY_DETECTED: 25,
  GEO_IMPOSSIBLE: 40,
} as const;

// ---------------------------------------------------------------------------
// FraudDetectionService
// ---------------------------------------------------------------------------

export class FraudDetectionService {
  constructor(
    private prisma: PrismaClient,
    private geoService: GeoService,
    private alertService: AlertService,
  ) {}

  /**
   * Analyse a freshly recorded scan for fraud signals.
   *
   * Checks performed (in order):
   *  1. Duplicate-location: another organization's active QR code is within 20 m.
   *  2. Proxy detection: metadata.proxyDetected is truthy.
   *  3. Geo-impossibility: the same clientIpHash scanned from a location
   *     >500 km away within the past 30 minutes.
   *
   * For every detected signal a FraudIncident record is created. If any
   * incident is HIGH or CRITICAL severity, an alert job is enqueued.
   *
   * @returns Composite trust score (0–100) and the list of created incidents.
   */
  async analyzeScan(input: ScanAnalysisInput): Promise<ScanAnalysisResult> {
    // 1. Load the QR code with its organization.
    const qrCode = await this.prisma.qRCode.findUnique({
      where: { id: input.qrCodeId },
      include: { organization: true },
    });

    if (!qrCode) {
      throw new Error(`QR code "${input.qrCodeId}" not found.`);
    }

    let trustScore = 100;
    const createdIncidents: FraudIncident[] = [];

    // ------------------------------------------------------------------
    // Signal 1: Duplicate location
    // ------------------------------------------------------------------
    if (qrCode.latitude !== null && qrCode.longitude !== null) {
      const nearby = await this.geoService.findNearbyQRCodes(
        qrCode.latitude,
        qrCode.longitude,
        DUPLICATE_LOCATION_RADIUS_M,
      );

      // Exclude this QR code's own organization; we are looking for collisions
      // with QR codes registered by *different* organizations.
      const duplicates = nearby.filter(
        (qr) => qr.id !== qrCode.id && qr.organizationId !== qrCode.organizationId,
      );

      if (duplicates.length > 0) {
        trustScore -= DEDUCTION.DUPLICATE_LOCATION;

        const incident = await this.prisma.fraudIncident.create({
          data: {
            qrCodeId: qrCode.id,
            type: 'DUPLICATE_LOCATION',
            severity: 'HIGH',
            details: {
              conflictingQRCodeIds: duplicates.map((d) => d.id),
              registeredLat: qrCode.latitude,
              registeredLng: qrCode.longitude,
              radiusCheckedM: DUPLICATE_LOCATION_RADIUS_M,
            },
          },
        });

        createdIncidents.push(incident);
      }
    }

    // ------------------------------------------------------------------
    // Signal 2: Proxy detection
    // ------------------------------------------------------------------
    const proxyDetected =
      input.metadata !== undefined && Boolean(input.metadata.proxyDetected);

    if (proxyDetected) {
      trustScore -= DEDUCTION.PROXY_DETECTED;

      const incident = await this.prisma.fraudIncident.create({
        data: {
          qrCodeId: qrCode.id,
          type: 'PROXY_DETECTED',
          severity: 'MEDIUM',
          details: {
            clientIpHash: input.clientIpHash,
            metadata: input.metadata ?? {},
          } as Prisma.InputJsonValue,
        },
      });

      createdIncidents.push(incident);
    }

    // ------------------------------------------------------------------
    // Signal 3: Geo-impossibility
    // ------------------------------------------------------------------
    if (input.clientLat !== undefined && input.clientLng !== undefined) {
      const windowStart = new Date(Date.now() - GEO_IMPOSSIBLE_WINDOW_MS);

      // Fetch recent scans from the same (hashed) IP in the last 30 minutes
      // that have a reported position.
      const recentScans = await this.prisma.scan.findMany({
        where: {
          clientIpHash: input.clientIpHash,
          qrCodeId: { not: qrCode.id },
          createdAt: { gte: windowStart },
          clientLat: { not: null },
          clientLng: { not: null },
        },
        orderBy: { createdAt: 'desc' },
        take: 20,
      });

      const impossibleScan = recentScans.find((scan) => {
        if (scan.clientLat === null || scan.clientLng === null) return false;
        const distanceM = haversineDistance(
          input.clientLat as number,
          input.clientLng as number,
          scan.clientLat,
          scan.clientLng,
        );
        return distanceM > GEO_IMPOSSIBLE_DISTANCE_M;
      });

      if (impossibleScan) {
        trustScore -= DEDUCTION.GEO_IMPOSSIBLE;

        const distanceM = haversineDistance(
          input.clientLat,
          input.clientLng,
          impossibleScan.clientLat as number,
          impossibleScan.clientLng as number,
        );

        const incident = await this.prisma.fraudIncident.create({
          data: {
            qrCodeId: qrCode.id,
            type: 'GEO_IMPOSSIBLE',
            severity: 'CRITICAL',
            details: {
              clientIpHash: input.clientIpHash,
              currentLat: input.clientLat,
              currentLng: input.clientLng,
              priorScanId: impossibleScan.id,
              priorLat: impossibleScan.clientLat,
              priorLng: impossibleScan.clientLng,
              priorScannedAt: impossibleScan.createdAt.toISOString(),
              distanceM: Math.round(distanceM),
              windowMs: GEO_IMPOSSIBLE_WINDOW_MS,
            },
          },
        });

        createdIncidents.push(incident);
      }
    }

    // Clamp trust score to [0, 100].
    trustScore = Math.max(0, Math.min(100, trustScore));

    // ------------------------------------------------------------------
    // Alerts: send for any HIGH or CRITICAL incidents.
    // ------------------------------------------------------------------
    const alertableSeverities: FraudSeverity[] = ['HIGH', 'CRITICAL'];

    for (const incident of createdIncidents) {
      if (alertableSeverities.includes(incident.severity)) {
        await this.alertService.sendFraudAlert(qrCode.organizationId, {
          id: incident.id,
          type: incident.type,
          severity: incident.severity,
          qrCodeId: incident.qrCodeId,
        });
      }
    }

    return { trustScore, incidents: createdIncidents };
  }

  /**
   * Manually report a fraud incident for a QR code.
   * If the severity is HIGH or CRITICAL, an alert is enqueued immediately.
   */
  async reportIncident(data: ReportIncidentInput): Promise<FraudIncident> {
    const qrCode = await this.prisma.qRCode.findUnique({
      where: { id: data.qrCodeId },
      select: { id: true, organizationId: true },
    });

    if (!qrCode) {
      throw new Error(`QR code "${data.qrCodeId}" not found.`);
    }

    const incident = await this.prisma.fraudIncident.create({
      data: {
        qrCodeId: data.qrCodeId,
        scanId: data.scanId,
        type: data.type,
        severity: data.severity,
        details: data.details as Prisma.InputJsonValue,
      },
    });

    const alertableSeverities: FraudSeverity[] = ['HIGH', 'CRITICAL'];
    if (alertableSeverities.includes(incident.severity)) {
      await this.alertService.sendFraudAlert(qrCode.organizationId, {
        id: incident.id,
        type: incident.type,
        severity: incident.severity,
        qrCodeId: incident.qrCodeId,
      });
    }

    return incident;
  }

  /**
   * Mark a fraud incident as resolved.
   * Throws when the incident does not exist.
   *
   * @param id - Primary key of the FraudIncident record.
   */
  async resolveIncident(id: string): Promise<FraudIncident> {
    const existing = await this.prisma.fraudIncident.findUnique({
      where: { id },
    });

    if (!existing) {
      throw new Error(`Fraud incident "${id}" not found.`);
    }

    return this.prisma.fraudIncident.update({
      where: { id },
      data: { resolved: true, resolvedAt: new Date() },
    });
  }

  /**
   * Return a paginated list of fraud incidents for all QR codes belonging to
   * the specified organization.
   *
   * @param organizationId - Filter to this organization's QR codes.
   * @param options  - Optional filters and pagination parameters.
   */
  async getIncidents(
    organizationId: string,
    options: GetIncidentsOptions,
  ): Promise<{ data: FraudIncident[]; total: number }> {
    const { resolved, severity, page, pageSize } = options;

    const where = {
      qrCode: { organizationId },
      ...(resolved !== undefined ? { resolved } : {}),
      ...(severity !== undefined ? { severity } : {}),
    };

    const skip = (page - 1) * pageSize;

    const [data, total] = await Promise.all([
      this.prisma.fraudIncident.findMany({
        where,
        orderBy: { createdAt: 'desc' },
        skip,
        take: pageSize,
      }),
      this.prisma.fraudIncident.count({ where }),
    ]);

    return { data, total };
  }
}
