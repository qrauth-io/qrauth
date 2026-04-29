/**
 * Seed the `PreviewBench` QRCode row used by the Living Codes benchmark
 * page (`packages/web/src/pages/benchmark-qr-renderer.tsx`).
 *
 * The benchmark page's "Live Preview" renders an animated QR whose frames
 * encode `https://{origin}/v/PreviewBench?f=…&t=…&h=…`. When a phone
 * scans one of those frames the QR app opens `/v/PreviewBench`. Without
 * a corresponding `QRCode` row the verify route 404s.
 *
 * This seed creates a long-lived ACTIVE `QRCode` row with `token` fixed
 * at `PreviewBench`, owned by a "QRAuth"-flavoured org so the preview
 * data is cleanly segregated from tenant orgs. The row is signed with
 * the same ECDSA P-256 flow the main seed uses, so on-scan signature
 * verification passes.
 *
 * Idempotent: re-runs are safe. The org + signing key are upserted or
 * reused; the QRCode is upserted on its unique `token`. The transparency
 * log entry is appended only on first creation.
 *
 * The benchmark page itself keeps using a client-random frame secret for
 * rendering, so the animated frames themselves DO NOT validate against
 * `POST /animated-qr/validate` — they just decode to a URL that resolves
 * to this QR's verification page. That trade-off is called out in the
 * preview panel UI.
 *
 * Run locally (from repo root):
 *
 *   npm run db:seed:preview-bench -w packages/api
 *
 * Run on prod host as the API service user (adjust paths as needed):
 *
 *   ssh progressnet@<api-host>
 *   cd /home/progressnet/vqr/packages/api
 *   npx tsx scripts/seed-preview-bench.ts
 *
 * The script writes the ECDSA private key to `./keys/<keyId>.pem` mode
 * 0600 when it has to create a new signing key, matching the convention
 * used by `SigningService.createKeyPair()`.
 */

import { PrismaClient } from '@prisma/client';
import { mkdir, writeFile, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import {
  generateKeyPair,
  __test_signPayload as signPayload,
} from '../src/lib/crypto.js';
import {
  canonicalizeCore,
  canonicalGeoHash,
  computeDestHash,
  ALG_VERSION_POLICY,
} from '@qrauth/shared';
import { TransparencyLogService } from '../src/services/transparency.js';
import { config } from '../src/lib/config.js';
import { HttpEcdsaSigner } from '../src/services/ecdsa-signer/http.js';

// Domain-separation prefix applied by the production ECDSA signer on both
// legs (packages/api/src/services/ecdsa-signer/local.ts:30,
// packages/signer-service/src/server.ts:314) and reconstructed by the
// verifier (packages/api/src/services/signing.ts:199-201).
//
// LOCAL-backend seed path prepends this manually before the raw
// __test_signPayload so verifier-reconstructed bytes match. HTTP-backend
// seed path does NOT prepend it — the remote signer adds its own
// byte-identical prefix inside /v1/sign-ecdsa. Prepending twice would
// produce a signature over PREFIX+PREFIX+canonical and verification
// would fail silently.
const ECDSA_CANONICAL_DOMAIN_PREFIX = 'qrauth:ecdsa-canonical:v1:';

/**
 * Sign `canonical` as ECDSA-P256 for the seeded QRCode row, using
 * whichever signer backend is configured.
 *
 *   - ECDSA_SIGNER=local → sign in-process with the PEM the caller
 *     supplies. Domain prefix prepended here.
 *   - ECDSA_SIGNER=http  → POST to the remote signer service. The
 *     signer prepends its own domain prefix; we pass raw canonical.
 *     No PEM needed on this host — which is the whole point (prod's
 *     signing-key PEMs live only on the signer host).
 *
 * Mirrors how production signing works: `SigningService` is
 * backend-agnostic at the call site; the plugin wires the right signer
 * in. The seed runs standalone, so we do the selection inline here
 * rather than pulling in the full Fastify plugin graph.
 */
async function signCanonicalForSeed(args: {
  keyId: string;
  canonical: string;
  privateKeyPem: string | null;
}): Promise<string> {
  if (config.ecdsaSigner.backend === 'http') {
    if (!config.ecdsaSigner.url || !config.ecdsaSigner.token) {
      throw new Error(
        'ECDSA_SIGNER=http requires ECDSA_SIGNER_URL and ECDSA_SIGNER_TOKEN',
      );
    }
    const signer = new HttpEcdsaSigner(
      config.ecdsaSigner.url,
      config.ecdsaSigner.token,
    );
    return signer.signCanonical(args.keyId, args.canonical);
  }
  if (!args.privateKeyPem) {
    throw new Error(
      'Local ECDSA signing requires a PEM on disk — seed found the signing ' +
        'key row but could not read the private PEM file.',
    );
  }
  return signPayload(
    args.privateKeyPem,
    ECDSA_CANONICAL_DOMAIN_PREFIX + args.canonical,
  );
}

const PREVIEW_TOKEN = 'PreviewBench';
const PREVIEW_DESTINATION = 'https://qrauth.io/living-codes';
const PREVIEW_LABEL = 'Living Codes benchmark preview';
const PREVIEW_EXPIRES_AT = new Date('2036-04-20T00:00:00.000Z'); // 10-year lifetime

export async function seedPreviewBench(prisma: PrismaClient): Promise<{
  qrCode: { id: string; token: string; organizationId: string };
  organization: { id: string; slug: string; name: string };
  signingKeyId: string;
  created: boolean;
}> {
  // --- 1. Find or create the preview-container org ------------------------
  //
  // Priority: reuse an existing "QRAuth"-flavoured org if present
  // (production already has one at slug `qrauth`). On environments without
  // it, fall through to creating a dedicated `qrauth-demo` org so the row
  // never attributes to a tenant.
  let org = await prisma.organization.findFirst({
    where: { slug: { in: ['qrauth', 'qrauth-demo'] } },
    orderBy: { createdAt: 'asc' },
    select: { id: true, slug: true, name: true },
  });

  if (!org) {
    org = await prisma.organization.upsert({
      where: { slug: 'qrauth-demo' },
      update: {},
      create: {
        name: 'QRAuth Demo',
        slug: 'qrauth-demo',
        email: 'demo@qrauth.io',
        trustLevel: 'INDIVIDUAL',
        plan: 'FREE',
      },
      select: { id: true, slug: true, name: true },
    });
    console.log(`[preview-bench] created org ${org.slug} (${org.id})`);
  } else {
    console.log(`[preview-bench] reusing org ${org.slug} (${org.id})`);
  }

  // --- 2. Pick a signing key the configured backend can actually use ------
  //
  // On ECDSA_SIGNER=http the remote signer holds the PEMs; the API host
  // holds zero private-key material. The seed MUST reuse an existing
  // ACTIVE key — minting a new one here would produce an orphaned key
  // (private half on this box, no provisioning to the signer) that would
  // then become the most-recent-active key `SigningService.getActiveKey`
  // picks for subsequent QR creation and break future signing under
  // this org.
  //
  // On ECDSA_SIGNER=local the PEM lives at `./keys/<keyId>.pem`. If the
  // row is present but the PEM was written in a different format (e.g.
  // LocalEcdsaSigner's `.ecdsa.enc` envelope), we fall through and mint
  // a fresh plain-PEM key scoped to this seed.
  let signingKey = await prisma.signingKey.findFirst({
    where: { organizationId: org.id, status: 'ACTIVE' },
    orderBy: { createdAt: 'desc' },
    select: { id: true, keyId: true },
  });

  let privateKeyPem: string | null = null;

  if (config.ecdsaSigner.backend === 'http') {
    if (!signingKey) {
      throw new Error(
        `[preview-bench] ECDSA_SIGNER=http but org ${org.slug} has no ACTIVE ` +
          `signing key. The remote signer cannot be provisioned from this ` +
          `seed — run the normal onboarding flow (signup) under this org so ` +
          `a key gets created and pushed to the signer host first.`,
      );
    }
    console.log(
      `[preview-bench] reusing ACTIVE signing key ${signingKey.keyId} — ` +
        `signing via remote HTTP signer (no PEM on this host)`,
    );
    // privateKeyPem stays null — HttpEcdsaSigner does not need it.
  } else {
    // Local backend. Try to reuse the existing key's PEM; if it's not
    // readable (e.g. only `.ecdsa.enc` envelope is present and we don't
    // have SIGNER_MASTER_KEY to decrypt), mint a fresh plain-PEM key.
    if (signingKey) {
      const candidate = join('./keys', `${signingKey.keyId}.pem`);
      try {
        privateKeyPem = await readFile(candidate, 'utf8');
        console.log(`[preview-bench] reusing signing key ${signingKey.keyId} (local PEM)`);
      } catch {
        console.log(
          `[preview-bench] existing signing key ${signingKey.keyId} has no ` +
            `local PEM — minting a fresh key for this seed`,
        );
        signingKey = null;
      }
    }

    if (!signingKey) {
      console.log('[preview-bench] generating ECDSA P-256 key pair…');
      const gen = await generateKeyPair();
      const keysDir = './keys';
      await mkdir(keysDir, { recursive: true });
      const pemPath = join(keysDir, `${gen.keyId}.pem`);
      await writeFile(pemPath, gen.privateKey, { mode: 0o600 });

      signingKey = await prisma.signingKey.create({
        data: {
          organizationId: org.id,
          publicKey: gen.publicKey,
          keyId: gen.keyId,
          algorithm: 'ES256',
          status: 'ACTIVE',
        },
        select: { id: true, keyId: true },
      });
      privateKeyPem = gen.privateKey;
      console.log(`[preview-bench] created signing key ${gen.keyId} → ${pemPath}`);
    }
  }

  // --- 3. Upsert the PreviewBench QRCode row ------------------------------
  const existing = await prisma.qRCode.findUnique({
    where: { token: PREVIEW_TOKEN },
    select: { id: true, organizationId: true, token: true },
  });

  if (existing) {
    console.log(
      `[preview-bench] QRCode ${PREVIEW_TOKEN} already present ` +
        `(id: ${existing.id}, org: ${existing.organizationId}) — skipping`,
    );
    return {
      qrCode: existing,
      organization: org,
      signingKeyId: signingKey.id,
      created: false,
    };
  }

  // Canonicalize + sign using the same pattern as `prisma/seed.ts`.
  // Preview QR has no geo binding — `canonicalGeoHash(null, null, null)`
  // canonicalises to `"none"` so the signature binds to the unlocated
  // variant.
  const destHash = await computeDestHash('url', PREVIEW_DESTINATION, '');
  const geoHash = await canonicalGeoHash(null, null, null);
  const payload = canonicalizeCore({
    algVersion: ALG_VERSION_POLICY.hybrid,
    token: PREVIEW_TOKEN,
    tenantId: org.id,
    destHash,
    geoHash,
    expiresAt: PREVIEW_EXPIRES_AT.toISOString(),
  });
  const signature = await signCanonicalForSeed({
    keyId: signingKey.keyId,
    canonical: payload,
    privateKeyPem,
  });

  // algVersion MUST be explicitly set. The Prisma schema defaults it to
  // `ecdsa-p256-sha256-v1`, which is in `REJECTED_ALG_VERSIONS`
  // (packages/shared/src/alg-versions.ts) — that would make every scan
  // verify fail with "algorithm no longer supported". We stamp the row as
  // `hybrid-ecdsa-slhdsa-v1` (the value that was canonicalised above).
  // With all three merkle fields left null the row does NOT trigger
  // `isHybridRow` in `verify-signatures.ts` — verification falls through
  // to the ECDSA leg alone, which matches what we actually produced here.
  // The pending-reconciler only targets rows with
  // `algVersion = 'ecdsa-pending-slhdsa-v1'`, so this row is not subject
  // to orphan auto-revoke and stays alive for the full 10-year TTL.
  const qrCode = await prisma.qRCode.create({
    data: {
      token: PREVIEW_TOKEN,
      organizationId: org.id,
      signingKeyId: signingKey.id,
      keyId: signingKey.keyId,
      destinationUrl: PREVIEW_DESTINATION,
      label: PREVIEW_LABEL,
      contentType: 'url',
      content: { url: PREVIEW_DESTINATION },
      signature,
      algVersion: ALG_VERSION_POLICY.hybrid,
      status: 'ACTIVE',
      expiresAt: PREVIEW_EXPIRES_AT,
    },
    select: { id: true, token: true, organizationId: true },
  });

  // Append to the tamper-evident transparency log. Only on first creation
  // — subsequent seed runs skip this branch entirely.
  const transparencyService = new TransparencyLogService(prisma);
  await transparencyService.appendEntry({
    id: qrCode.id,
    token: qrCode.token,
    organizationId: qrCode.organizationId,
    destinationUrl: PREVIEW_DESTINATION,
    geoHash: null,
  });

  console.log(
    `[preview-bench] created QRCode ${PREVIEW_TOKEN} ` +
      `(id: ${qrCode.id}, org: ${org.slug})`,
  );

  return {
    qrCode,
    organization: org,
    signingKeyId: signingKey.id,
    created: true,
  };
}

// When invoked directly (`npx tsx scripts/seed-preview-bench.ts`), run
// against a fresh PrismaClient and exit.
const isMain =
  typeof process !== 'undefined' &&
  process.argv[1] &&
  import.meta.url === `file://${process.argv[1]}`;

if (isMain) {
  const prisma = new PrismaClient({
    log: [{ level: 'warn', emit: 'stdout' }],
  });
  seedPreviewBench(prisma)
    .then((result) => {
      console.log(
        `[preview-bench] done — created=${result.created}, ` +
          `token=${result.qrCode.token}, org=${result.organization.slug}`,
      );
      return prisma.$disconnect();
    })
    .catch(async (err) => {
      console.error('[preview-bench] FAILED:', err);
      await prisma.$disconnect();
      process.exit(1);
    });
}
