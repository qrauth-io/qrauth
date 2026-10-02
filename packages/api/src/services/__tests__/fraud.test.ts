import { describe, it, expect, vi } from 'vitest';
import { FraudDetectionService } from '../fraud.js';

type Any = any;

interface Opts {
  qrCode?: Any;
  findNearby?: Any[];
  recentScans?: Any[];
  scanCount?: number;
  groupByRows?: Any[];
  activeIncidents?: Any[];
  existingIncident?: Any;
  alertService?: Any | null;
}

const NO_GEO_QR = { id: 'qr_1', organizationId: 'org_1', latitude: null, longitude: null };

function makeService(opts: Opts = {}) {
  let incId = 0;
  const created: Any[] = [];

  const prisma = {
    qRCode: { findUnique: vi.fn(async () => ('qrCode' in opts ? opts.qrCode : NO_GEO_QR)) },
    fraudIncident: {
      create: vi.fn(async ({ data }: Any) => {
        const inc = { id: `inc_${++incId}`, resolved: false, createdAt: new Date(), ...data };
        created.push(inc);
        return inc;
      }),
      findMany: vi.fn(async () => opts.activeIncidents ?? []),
      findUnique: vi.fn(async () => opts.existingIncident ?? null),
      update: vi.fn(async ({ data }: Any) => ({ id: 'inc_x', ...data })),
      count: vi.fn(async () => 0),
    },
    scan: {
      findMany: vi.fn(async () => opts.recentScans ?? []),
      count: vi.fn(async () => opts.scanCount ?? 0),
      groupBy: vi.fn(async () => opts.groupByRows ?? []),
    },
  } as Any;

  const geoService = { findNearbyQRCodes: vi.fn(async () => opts.findNearby ?? []) } as Any;
  const alertService =
    opts.alertService === null ? null : (opts.alertService ?? { sendFraudAlert: vi.fn(async () => {}) });

  const service = new FraudDetectionService(prisma, geoService, alertService);
  return { service, prisma, geoService, alertService, created };
}

const BASE_INPUT = { qrCodeId: 'qr_1', clientIpHash: 'iphash-1' };

describe('FraudDetectionService.analyzeScan — happy path', () => {
  it('returns trustScore 100 with no incidents when nothing is suspicious', async () => {
    const { service } = makeService();
    const result = await service.analyzeScan({ ...BASE_INPUT });
    expect(result.trustScore).toBe(100);
    expect(result.incidents).toHaveLength(0);
  });

  it('throws when the QR code does not exist', async () => {
    const { service } = makeService({ qrCode: null });
    await expect(service.analyzeScan({ ...BASE_INPUT })).rejects.toThrow(/not found/);
  });
});

describe('FraudDetectionService.analyzeScan — the 6 signals', () => {
  it('Signal 1: duplicate location from a DIFFERENT org → HIGH, -30', async () => {
    const { service, created } = makeService({
      qrCode: { id: 'qr_1', organizationId: 'org_1', latitude: 1, longitude: 2 },
      findNearby: [{ id: 'qr_2', organizationId: 'org_2' }],
    });
    const result = await service.analyzeScan({ ...BASE_INPUT });
    expect(result.trustScore).toBe(70);
    expect(created).toHaveLength(1);
    expect(created[0]).toMatchObject({ type: 'DUPLICATE_LOCATION', severity: 'HIGH' });
  });

  it('Signal 1 edge: same-org / self collisions are ignored', async () => {
    const { service } = makeService({
      qrCode: { id: 'qr_1', organizationId: 'org_1', latitude: 1, longitude: 2 },
      findNearby: [
        { id: 'qr_1', organizationId: 'org_1' }, // self
        { id: 'qr_3', organizationId: 'org_1' }, // same org
      ],
    });
    const result = await service.analyzeScan({ ...BASE_INPUT });
    expect(result.trustScore).toBe(100);
    expect(result.incidents).toHaveLength(0);
  });

  it('Signal 2: proxy detected → MEDIUM, -25', async () => {
    const { service, created } = makeService();
    const result = await service.analyzeScan({ ...BASE_INPUT, metadata: { proxyDetected: true } });
    expect(result.trustScore).toBe(75);
    expect(created[0]).toMatchObject({ type: 'PROXY_DETECTED', severity: 'MEDIUM' });
  });

  it('Signal 3: geo-impossible travel → CRITICAL, -40', async () => {
    const { service, created } = makeService({
      recentScans: [{ id: 's_prior', clientLat: 10, clientLng: 10, createdAt: new Date() }],
    });
    const result = await service.analyzeScan({ ...BASE_INPUT, clientLat: 0, clientLng: 0 });
    expect(result.trustScore).toBe(60);
    expect(created[0]).toMatchObject({ type: 'GEO_IMPOSSIBLE', severity: 'CRITICAL' });
  });

  it('Signal 3 edge: a nearby prior scan is NOT geo-impossible', async () => {
    const { service } = makeService({
      recentScans: [{ id: 's_prior', clientLat: 0.001, clientLng: 0.001, createdAt: new Date() }],
    });
    const result = await service.analyzeScan({ ...BASE_INPUT, clientLat: 0, clientLng: 0 });
    expect(result.trustScore).toBe(100);
    expect(result.incidents).toHaveLength(0);
  });

  it('Signal 3 edge: missing client geo skips the check entirely', async () => {
    const { service, prisma } = makeService();
    await service.analyzeScan({ ...BASE_INPUT }); // no clientLat/Lng
    expect(prisma.scan.findMany).not.toHaveBeenCalled();
  });

  it('Signal 4: scan velocity over the threshold → MEDIUM, -20', async () => {
    const { service, created } = makeService({ scanCount: 51 });
    const result = await service.analyzeScan({ ...BASE_INPUT });
    expect(result.trustScore).toBe(80);
    expect(created[0]).toMatchObject({ type: 'PATTERN_ANOMALY', severity: 'MEDIUM' });
  });

  it('Signal 5: bot user-agent → MEDIUM, -15', async () => {
    const { service, created } = makeService();
    const result = await service.analyzeScan({
      ...BASE_INPUT,
      userAgent: 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
    });
    expect(result.trustScore).toBe(85);
    expect(created[0]).toMatchObject({ type: 'PATTERN_ANOMALY', severity: 'MEDIUM' });
  });

  it('Signal 6: device clustering across many QR codes → HIGH, -25', async () => {
    const groupByRows = Array.from({ length: 22 }, (_, i) => ({ qrCodeId: `qr_${i}` }));
    const { service, created } = makeService({ groupByRows });
    const result = await service.analyzeScan({ ...BASE_INPUT });
    expect(result.trustScore).toBe(75);
    expect(created[0]).toMatchObject({ type: 'PATTERN_ANOMALY', severity: 'HIGH' });
  });

  it('clamps the trust score to a floor of 0 when many signals stack', async () => {
    const { service } = makeService({
      qrCode: { id: 'qr_1', organizationId: 'org_1', latitude: 1, longitude: 2 },
      findNearby: [{ id: 'qr_2', organizationId: 'org_2' }], // -30
      recentScans: [{ id: 's', clientLat: 10, clientLng: 10, createdAt: new Date() }], // -40
      scanCount: 60, // -20
      groupByRows: Array.from({ length: 25 }, (_, i) => ({ qrCodeId: `q${i}` })), // -25
    });
    const result = await service.analyzeScan({
      ...BASE_INPUT,
      clientLat: 0,
      clientLng: 0,
      metadata: { proxyDetected: true }, // -25
    });
    expect(result.trustScore).toBe(0);
  });
});

describe('FraudDetectionService.analyzeScan — alerting', () => {
  it('sends an alert for a HIGH/CRITICAL incident', async () => {
    const alertService = { sendFraudAlert: vi.fn(async () => {}) };
    const { service } = makeService({
      qrCode: { id: 'qr_1', organizationId: 'org_1', latitude: 1, longitude: 2 },
      findNearby: [{ id: 'qr_2', organizationId: 'org_2' }],
      alertService,
    });
    await service.analyzeScan({ ...BASE_INPUT });
    expect(alertService.sendFraudAlert).toHaveBeenCalledTimes(1);
    expect(alertService.sendFraudAlert).toHaveBeenCalledWith(
      'org_1',
      expect.objectContaining({ type: 'DUPLICATE_LOCATION', severity: 'HIGH' }),
    );
  });

  it('does NOT alert for a MEDIUM-only incident', async () => {
    const alertService = { sendFraudAlert: vi.fn(async () => {}) };
    const { service } = makeService({ alertService });
    await service.analyzeScan({ ...BASE_INPUT, metadata: { proxyDetected: true } });
    expect(alertService.sendFraudAlert).not.toHaveBeenCalled();
  });

  it('does not crash when no AlertService is wired (null)', async () => {
    const { service } = makeService({
      qrCode: { id: 'qr_1', organizationId: 'org_1', latitude: 1, longitude: 2 },
      findNearby: [{ id: 'qr_2', organizationId: 'org_2' }],
      alertService: null,
    });
    const result = await service.analyzeScan({ ...BASE_INPUT });
    expect(result.trustScore).toBe(70);
  });
});

describe('FraudDetectionService.getQuickTrustScore', () => {
  it('returns 100 when there are no active incidents and low velocity', async () => {
    const { service } = makeService();
    expect(await service.getQuickTrustScore('qr_1')).toBe(100);
  });

  it('deducts per UNIQUE incident type by severity', async () => {
    const { service } = makeService({
      activeIncidents: [
        { severity: 'CRITICAL', type: 'GEO_IMPOSSIBLE' }, // -30
        { severity: 'HIGH', type: 'DUPLICATE_LOCATION' }, // -20
      ],
    });
    expect(await service.getQuickTrustScore('qr_1')).toBe(50);
  });

  it('counts each incident type only once (no stacking of duplicates)', async () => {
    const { service } = makeService({
      activeIncidents: [
        { severity: 'HIGH', type: 'DUPLICATE_LOCATION' },
        { severity: 'HIGH', type: 'DUPLICATE_LOCATION' },
        { severity: 'HIGH', type: 'DUPLICATE_LOCATION' },
      ],
    });
    expect(await service.getQuickTrustScore('qr_1')).toBe(80);
  });

  it('deducts for high recent scan velocity', async () => {
    const { service } = makeService({ scanCount: 25 });
    expect(await service.getQuickTrustScore('qr_1')).toBe(90);
  });

  it('floors the score at 30 even with many incidents', async () => {
    const { service } = makeService({
      activeIncidents: [
        { severity: 'CRITICAL', type: 'GEO_IMPOSSIBLE' },
        { severity: 'CRITICAL', type: 'DUPLICATE_LOCATION' },
        { severity: 'CRITICAL', type: 'PROXY_DETECTED' },
        { severity: 'CRITICAL', type: 'PATTERN_ANOMALY' },
      ],
      scanCount: 25,
    });
    expect(await service.getQuickTrustScore('qr_1')).toBe(30);
  });
});

describe('FraudDetectionService.reportIncident / resolveIncident / getIncidents', () => {
  it('reportIncident creates the incident and alerts on HIGH severity', async () => {
    const alertService = { sendFraudAlert: vi.fn(async () => {}) };
    const { service } = makeService({ qrCode: { id: 'qr_1', organizationId: 'org_1' }, alertService });

    const incident = await service.reportIncident({
      qrCodeId: 'qr_1',
      type: 'DUPLICATE_LOCATION',
      severity: 'HIGH',
      details: { note: 'manual' },
    });

    expect(incident).toMatchObject({ type: 'DUPLICATE_LOCATION', severity: 'HIGH' });
    expect(alertService.sendFraudAlert).toHaveBeenCalledTimes(1);
  });

  it('reportIncident does not alert on MEDIUM severity', async () => {
    const alertService = { sendFraudAlert: vi.fn(async () => {}) };
    const { service } = makeService({ qrCode: { id: 'qr_1', organizationId: 'org_1' }, alertService });

    await service.reportIncident({ qrCodeId: 'qr_1', type: 'PROXY_DETECTED', severity: 'MEDIUM', details: {} });
    expect(alertService.sendFraudAlert).not.toHaveBeenCalled();
  });

  it('reportIncident throws for an unknown QR code', async () => {
    const { service } = makeService({ qrCode: null });
    await expect(
      service.reportIncident({ qrCodeId: 'nope', type: 'PROXY_DETECTED', severity: 'LOW', details: {} }),
    ).rejects.toThrow(/not found/);
  });

  it('resolveIncident marks an existing incident resolved', async () => {
    const { service } = makeService({ existingIncident: { id: 'inc_1', resolved: false } });
    const resolved = await service.resolveIncident('inc_1');
    expect(resolved).toMatchObject({ resolved: true });
  });

  it('resolveIncident throws when the incident is missing', async () => {
    const { service } = makeService({ existingIncident: null });
    await expect(service.resolveIncident('missing')).rejects.toThrow(/not found/);
  });

  it('getIncidents returns a { data, total } page scoped to the org', async () => {
    const { service, prisma } = makeService({
      activeIncidents: [{ id: 'inc_1', severity: 'HIGH', type: 'DUPLICATE_LOCATION' }],
    });

    const result = await service.getIncidents('org_1', { page: 1, pageSize: 10 });

    expect(result.data).toHaveLength(1);
    expect(prisma.fraudIncident.findMany).toHaveBeenCalledWith(
      expect.objectContaining({ where: expect.objectContaining({ qrCode: { organizationId: 'org_1' } }) }),
    );
  });
});
