/**
 * Database seeder for the QRAuth API.
 *
 * Run with:
 *   yarn workspace @qrauth/api db:seed
 *
 * The script is idempotent at the organization level: it upserts the test
 * organization by slug so it can be re-run safely against a database that was
 * already seeded.  QR codes and scans are only created if the organization has
 * no existing QR codes.
 */

import { PrismaClient } from '@prisma/client';
import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { generateKeyPair, __test_signPayload as signPayload, hashString } from '../src/lib/crypto.js';
import {
  generateToken,
  canonicalizeCore,
  canonicalGeoHash,
  computeDestHash,
  ALG_VERSION_POLICY,
} from '@qrauth/shared';
import { GeoService } from '../src/services/geo.js';
import { TransparencyLogService } from '../src/services/transparency.js';
import { hashPassword } from '../src/lib/password.js';
import { seedPreviewBench } from '../scripts/seed-preview-bench.js';

const prisma = new PrismaClient({
  log: [{ level: 'warn', emit: 'stdout' }],
});

// ---------------------------------------------------------------------------
// Thessaloniki locations
// ---------------------------------------------------------------------------

const THESSALONIKI_LOCATIONS = [
  {
    label: 'Parking Zone A - Aristotelous Square',
    lat: 40.6323,
    lng: 22.9417,
    url: 'https://parking.thessaloniki.gr/zone-a/aristotelous',
  },
  {
    label: 'Parking Zone B - Tsimiski Street',
    lat: 40.6321,
    lng: 22.9414,
    url: 'https://parking.thessaloniki.gr/zone-b/tsimiski',
  },
  {
    label: 'City Museum Entrance',
    lat: 40.6264,
    lng: 22.9483,
    url: 'https://museum.thessaloniki.gr/entrance',
  },
  {
    label: 'White Tower Visitor Info',
    lat: 40.6262,
    lng: 22.9485,
    url: 'https://whitetower.thessaloniki.gr/info',
  },
  {
    label: 'Port Authority Payment',
    lat: 40.635,
    lng: 22.939,
    url: 'https://port.thessaloniki.gr/payment',
  },
] as const;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Generate a slight coordinate offset to simulate a nearby-but-not-identical
 * scan position (within a ~50 m radius of the QR code).
 */
function jitterCoord(value: number, magnitudeM: number = 30): number {
  // 1 degree latitude ≈ 111 000 m; 1 degree longitude ≈ 111 000 * cos(lat) m.
  // For small offsets near Thessaloniki (lat ≈ 40.6°) both are roughly 84 km/°.
  const degreesPerMetre = 1 / 85_000;
  const offset = (Math.random() - 0.5) * 2 * magnitudeM * degreesPerMetre;
  return Math.round((value + offset) * 1_000_000) / 1_000_000;
}

// ---------------------------------------------------------------------------
// Main seeder
// ---------------------------------------------------------------------------

async function seed(): Promise<void> {
  console.log('=== QRAuth seed script starting ===\n');

  // --------------------------------------------------------------------------
  // a. Create (or fetch) the test organization
  // --------------------------------------------------------------------------

  console.log('Creating organization: Municipality of Thessaloniki…');

  const org = await prisma.organization.upsert({
    where: { slug: 'municipality-thessaloniki' },
    update: {},
    create: {
      name: 'Municipality of Thessaloniki',
      slug: 'municipality-thessaloniki',
      email: 'admin@thessaloniki.gr',
      domain: 'thessaloniki.gr',
      trustLevel: 'GOVERNMENT',
      kycStatus: 'VERIFIED',
      plan: 'ENTERPRISE',
    },
  });

  console.log(`  Organization id: ${org.id}`);

  // --------------------------------------------------------------------------
  // b. Create (or fetch) the demo admin user
  // --------------------------------------------------------------------------

  console.log('\nCreating demo admin user…');

  const passwordHash = await hashPassword('password123');

  const user = await prisma.user.upsert({
    where: { email: 'admin@thessaloniki.gr' },
    update: {},
    create: {
      name: 'Demo Admin',
      email: 'admin@thessaloniki.gr',
      passwordHash,
      emailVerified: true,
    },
  });

  console.log(`  User id: ${user.id}`);

  // --------------------------------------------------------------------------
  // c. Create (or fetch) the OWNER membership
  // --------------------------------------------------------------------------

  console.log('\nCreating OWNER membership…');

  const existingMembership = await prisma.membership.findFirst({
    where: { userId: user.id, organizationId: org.id },
  });

  let membership = existingMembership;

  if (!membership) {
    membership = await prisma.membership.create({
      data: {
        userId: user.id,
        organizationId: org.id,
        role: 'OWNER',
      },
    });
    console.log(`  Membership id: ${membership.id}`);
  } else {
    console.log(`  Membership already exists (id: ${membership.id}) — skipping.`);
  }

  // --------------------------------------------------------------------------
  // d. Generate a signing key pair for the organization
  // --------------------------------------------------------------------------

  // Check whether an ACTIVE signing key already exists so re-runs are safe.
  let signingKey = await prisma.signingKey.findFirst({
    where: { organizationId: org.id, status: 'ACTIVE' },
    orderBy: { createdAt: 'desc' },
  });

  if (!signingKey) {
    console.log('\nGenerating ECDSA P-256 key pair…');

    const { publicKey, privateKey, keyId } = await generateKeyPair();

    // Write the private key to the keys/ directory (same convention as
    // SigningService.createKeyPair()).
    const keysDir = './keys';
    await mkdir(keysDir, { recursive: true });
    const keyPath = join(keysDir, `${keyId}.pem`);
    await writeFile(keyPath, privateKey, { mode: 0o600 });

    signingKey = await prisma.signingKey.create({
      data: {
        organizationId: org.id,
        publicKey,
        keyId,
        algorithm: 'ES256',
        status: 'ACTIVE',
      },
    });

    console.log(`  Key id   : ${keyId}`);
    console.log(`  PEM path : ${keyPath}`);
    console.log(`  DB id    : ${signingKey.id}`);
  } else {
    console.log(`\nUsing existing signing key: ${signingKey.keyId}`);
  }

  // Read the private key back from disk for signing the QR payloads.
  const { readFile } = await import('node:fs/promises');
  const privateKeyPem = await readFile(
    join('./keys', `${signingKey.keyId}.pem`),
    'utf8',
  );

  // --------------------------------------------------------------------------
  // e. Create sample QR codes
  // --------------------------------------------------------------------------

  // Check whether QR codes were already seeded for this organization.
  const existingQrCount = await prisma.qRCode.count({
    where: { organizationId: org.id },
  });

  const geoService = new GeoService(prisma);
  const transparencyService = new TransparencyLogService(prisma);

  let createdQrCodes: Array<{ id: string; label: string }> = [];

  if (existingQrCount > 0) {
    console.log(
      `\nFound ${existingQrCount} existing QR codes — skipping QR code creation.`,
    );

    const existing = await prisma.qRCode.findMany({
      where: { organizationId: org.id },
      select: { id: true, label: true },
    });

    createdQrCodes = existing.map((qr) => ({
      id: qr.id,
      label: qr.label ?? '(no label)',
    }));
  } else {
    console.log('\nCreating 5 sample QR codes…');

    for (const location of THESSALONIKI_LOCATIONS) {
      const token = generateToken();
      const geoHash = geoService.encodeGeoHash(location.lat, location.lng, 7);
      const expiresAt = new Date(
        Date.now() + 365 * 24 * 60 * 60 * 1000,
      ).toISOString(); // 1 year from now

      // Build the unified canonical core and sign it. Note the seed only
      // produces ECDSA-signed demo rows — the Merkle/SLH-DSA leg requires
      // the full BatchSigner pipeline and is out of scope for seeding. The
      // transparency log will mark these rows as legacy-shaped until they
      // are re-issued through the production hybrid route.
      const destHash = await computeDestHash('url', location.url, '');
      const seedGeoHash = await canonicalGeoHash(location.lat, location.lng, 50);
      const payload = canonicalizeCore({
        algVersion: ALG_VERSION_POLICY.hybrid,
        token,
        tenantId: org.id,
        destHash,
        geoHash: seedGeoHash,
        expiresAt,
      });
      const signature = signPayload(privateKeyPem, payload);

      const qrCode = await prisma.qRCode.create({
        data: {
          token,
          organizationId: org.id,
          signingKeyId: signingKey.id,
          keyId: signingKey.keyId,
          destinationUrl: location.url,
          label: location.label,
          signature,
          geoHash,
          latitude: location.lat,
          longitude: location.lng,
          radiusM: 50,
          status: 'ACTIVE',
          expiresAt: new Date(expiresAt),
        },
      });

      // Append the QR code to the tamper-evident transparency log.
      await transparencyService.appendEntry({
        id: qrCode.id,
        token: qrCode.token,
        organizationId: qrCode.organizationId,
        destinationUrl: qrCode.destinationUrl,
        geoHash: qrCode.geoHash,
      });

      console.log(`  [+] ${location.label} (token: ${token})`);

      createdQrCodes.push({ id: qrCode.id, label: location.label });
    }
  }

  // --------------------------------------------------------------------------
  // f. Create sample scans for each QR code
  // --------------------------------------------------------------------------

  console.log('\nCreating sample scans…');

  let totalScansCreated = 0;

  for (const qr of createdQrCodes) {
    // Find the QR code to get its registered coordinates.
    const qrRecord = await prisma.qRCode.findUnique({
      where: { id: qr.id },
      select: { latitude: true, longitude: true },
    });

    if (!qrRecord?.latitude || !qrRecord?.longitude) {
      console.warn(`  Skipping scans for ${qr.label} — no coordinates.`);
      continue;
    }

    const existingScans = await prisma.scan.count({ where: { qrCodeId: qr.id } });
    if (existingScans > 0) {
      console.log(`  Scans already exist for "${qr.label}" — skipping.`);
      continue;
    }

    // Create 2–3 scans with slight location jitter.
    const scanCount = 2 + Math.round(Math.random()); // 2 or 3

    for (let i = 0; i < scanCount; i++) {
      const clientLat = jitterCoord(qrRecord.latitude);
      const clientLng = jitterCoord(qrRecord.longitude);
      const clientIp = `192.168.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
      const clientIpHash = hashString(clientIp);

      await prisma.scan.create({
        data: {
          qrCodeId: qr.id,
          clientIpHash,
          clientLat,
          clientLng,
          userAgent:
            'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15',
          trustScore: 100,
          proxyDetected: false,
          metadata: { source: 'seed', scanIndex: i },
        },
      });

      totalScansCreated++;
    }

    console.log(`  Created ${scanCount} scans for "${qr.label}"`);
  }

  // --------------------------------------------------------------------------
  // g. Create one sample fraud incident
  // --------------------------------------------------------------------------

  console.log('\nCreating sample fraud incident…');

  const firstQr = createdQrCodes[0];

  if (firstQr) {
    const existingIncident = await prisma.fraudIncident.findFirst({
      where: { qrCodeId: firstQr.id, type: 'DUPLICATE_LOCATION' },
    });

    if (!existingIncident) {
      const incident = await prisma.fraudIncident.create({
        data: {
          qrCodeId: firstQr.id,
          type: 'DUPLICATE_LOCATION',
          severity: 'MEDIUM',
          details: {
            note: 'Seeded sample incident — another QR code was found within 20 m.',
            conflictingQRCodeIds: [],
            registeredLat: 40.6323,
            registeredLng: 22.9417,
            radiusCheckedM: 20,
          },
          resolved: false,
        },
      });

      console.log(
        `  Created DUPLICATE_LOCATION incident (id: ${incident.id}) for "${firstQr.label}"`,
      );
    } else {
      console.log(`  Fraud incident already exists — skipping.`);
    }
  }

  // --------------------------------------------------------------------------
  // Summary
  // --------------------------------------------------------------------------

  const [
    totalOrganizations,
    totalUsers,
    totalMemberships,
    totalKeys,
    totalQrCodes,
    totalScans,
    totalIncidents,
    totalLogEntries,
  ] = await Promise.all([
    prisma.organization.count(),
    prisma.user.count(),
    prisma.membership.count(),
    prisma.signingKey.count(),
    prisma.qRCode.count(),
    prisma.scan.count(),
    prisma.fraudIncident.count(),
    prisma.transparencyLogEntry.count(),
  ]);

  // ---------------------------------------------------------------------------
  // z. PreviewBench QR — benchmark page uses `/v/PreviewBench` as its scan
  //    destination. Seeded here so `npm run db:seed` also provisions it for
  //    local dev. A standalone one-off runner lives at
  //    `scripts/seed-preview-bench.ts` and is used on production via
  //    `npm run db:seed:preview-bench -w packages/api`.
  // ---------------------------------------------------------------------------
  console.log('\nSeeding PreviewBench QR code…');
  await seedPreviewBench(prisma);

  console.log('\n=== Seed complete ===');
  console.log(`  Organizations        : ${totalOrganizations}`);
  console.log(`  Users                : ${totalUsers}`);
  console.log(`  Memberships          : ${totalMemberships}`);
  console.log(`  Signing keys         : ${totalKeys}`);
  console.log(`  QR codes             : ${totalQrCodes}`);
  console.log(`  Scans                : ${totalScans} (new: ${totalScansCreated})`);
  console.log(`  Fraud incidents      : ${totalIncidents}`);
  console.log(`  Transparency entries : ${totalLogEntries}`);
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

seed()
  .then(async () => {
    await prisma.$disconnect();
  })
  .catch(async (err) => {
    console.error('\nSeed script failed:', err);
    await prisma.$disconnect();
    process.exit(1);
  });
