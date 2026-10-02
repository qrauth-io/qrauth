/**
 * One-time production data repair for the signing-key rotation loop
 * (docs/ops/signing-key-rotation-loop.md).
 *
 * What it does, in order:
 *   1. VERIFIES the platform org's RS256 key private half is present and
 *      loadable on disk (decrypts the at-rest envelope, parses the PEM,
 *      matches it against the stored public key, and runs a local
 *      sign/verify round-trip). Aborts before touching anything if not.
 *   2. Sets that RS256 key back to ACTIVE (it was wrongly demoted to
 *      ROTATED by the algorithm-blind rotation — defect 1).
 *   3. Classifies the orphaned ES256 pile (~220 hourly-minted keys) and
 *      sets the safe subset to REVOKED so JWKS stops serving them.
 *      EXCLUDED from revocation (queried, not assumed):
 *        - the newest ACTIVE ES256 key (stays the org's signer);
 *        - any key referenced by qr_codes or signed_batches;
 *        - any key created or rotated within the last 48 h — the
 *          longest-lived signature verified through a status-filtered
 *          path is the auth-session approval (sessions live <= 24 h;
 *          ID tokens 1 h, proximity attestations 5 min), so 48 h is a
 *          2x margin. Excluded ACTIVE duplicates are demoted to ROTATED
 *          (never left ACTIVE — the partial unique index requires one
 *          ACTIVE key per (org, algorithm)); excluded ROTATED keys stay
 *          ROTATED and age out via the cleanup worker's grace window.
 *
 * DRY-RUN BY DEFAULT — prints the full diff and counts, writes nothing.
 *   npx tsx --env-file=.env scripts/repair-signing-key-rotation.ts
 * Apply (writes, and saves an undo file next to the script):
 *   npx tsx --env-file=.env scripts/repair-signing-key-rotation.ts --apply
 * Revert a previous apply:
 *   npx tsx --env-file=.env scripts/repair-signing-key-rotation.ts --undo <undo-file.json>
 *   (If the partial unique index migration is already applied, an undo that
 *   would restore two ACTIVE keys of the same algorithm fails on that
 *   constraint — expected, since the pre-repair state violated the invariant.)
 *
 * IDEMPOTENT: a second run finds zero rows to change.
 * NEVER deletes rows (qr_codes.signingKeyId is ON DELETE RESTRICT).
 *
 * NOTE: this verifies the LOCAL envelope. In production
 * (ECDSA_SIGNER=http) the standalone signer must also hold the RSA
 * envelope for /token to sign — the bootstrap script pushed it at mint
 * time. After applying, confirm end to end:
 *   curl -s https://id.qrauth.io/.well-known/jwks.json | jq '[.keys[].alg] | group_by(.) | map({alg: .[0], n: length})'
 *   …then run an RS256 client auth-code flow and check the id_token header.
 */

import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import {
  createPrivateKey,
  createPublicKey,
  sign as cryptoSign,
  verify as cryptoVerify,
} from 'node:crypto';
import { PrismaClient } from '@prisma/client';
import { config } from '../src/lib/config.js';
import { decryptAtRest } from '../src/lib/key-at-rest.js';
import { QRAUTH_PLATFORM_ORG_SLUG } from '../src/lib/oidc-signing-keys.js';

/** The platform RS256 key demoted by the first buggy rotation run. */
const RS256_KEY_ID = '899197a5-619a-4a27-92bb-18f915f65afa';

/** See the header comment for the derivation of this window. */
const RECENT_SIGNATURE_WINDOW_MS = 48 * 60 * 60 * 1000;

interface PlannedChange {
  id: string;
  keyId: string;
  algorithm: string;
  from: string;
  to: 'ACTIVE' | 'ROTATED' | 'REVOKED';
  reason: string;
  prior: { status: string; rotatedAt: string | null; revokedAt: string | null };
}

function normalizePem(pem: string): string {
  return pem.replace(/\s+/g, '');
}

async function verifyRsaPrivateHalf(publicKeyPem: string): Promise<void> {
  const path = join(config.kms.ecdsaPrivateKeyPath, `${RS256_KEY_ID}.rsa.enc`);
  let envelope: string;
  try {
    envelope = await readFile(path, 'utf8');
  } catch (err) {
    throw new Error(
      `RS256 private envelope not readable at ${path} — aborting before any write. ` +
        `(${(err as Error).message})`,
    );
  }

  let privatePem: string;
  try {
    privatePem = decryptAtRest(envelope.trim()).toString('utf8');
  } catch (err) {
    throw new Error(
      `RS256 private envelope at ${path} failed to decrypt (check SIGNER_MASTER_KEY) — ` +
        `aborting. (${(err as Error).message})`,
    );
  }

  const privateKey = createPrivateKey(privatePem);
  if (privateKey.asymmetricKeyType !== 'rsa') {
    throw new Error(
      `Decrypted key at ${path} is ${privateKey.asymmetricKeyType}, expected rsa — aborting.`,
    );
  }

  const derivedPublicPem = createPublicKey(privateKey)
    .export({ type: 'spki', format: 'pem' })
    .toString();
  if (normalizePem(derivedPublicPem) !== normalizePem(publicKeyPem)) {
    throw new Error(
      `Decrypted private key at ${path} does NOT match the stored public key for ` +
        `${RS256_KEY_ID} — aborting.`,
    );
  }

  const probe = Buffer.from(`repair-probe:${Date.now()}`);
  const signature = cryptoSign('sha256', probe, privateKey);
  const ok = cryptoVerify('sha256', probe, createPublicKey(publicKeyPem), signature);
  if (!ok) {
    throw new Error(`RS256 sign/verify probe failed for ${RS256_KEY_ID} — aborting.`);
  }

  console.log(`[repair] RS256 private half verified: present, decryptable, matches public key, signs. (${path})`);
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const apply = args.includes('--apply');
  const undoIdx = args.indexOf('--undo');
  const undoFile = undoIdx !== -1 ? args[undoIdx + 1] : null;
  if (undoIdx !== -1 && !undoFile) {
    throw new Error('--undo requires a file path');
  }

  const prisma = new PrismaClient();
  try {
    if (undoFile) {
      await runUndo(prisma, undoFile);
      return;
    }

    const org = await prisma.organization.findUnique({
      where: { slug: QRAUTH_PLATFORM_ORG_SLUG },
      select: { id: true, slug: true },
    });
    if (!org) throw new Error(`Platform org "${QRAUTH_PLATFORM_ORG_SLUG}" not found — aborting.`);

    const rsaKey = await prisma.signingKey.findUnique({ where: { keyId: RS256_KEY_ID } });
    if (!rsaKey) throw new Error(`RS256 key ${RS256_KEY_ID} not found — aborting.`);
    if (rsaKey.organizationId !== org.id) {
      throw new Error(`RS256 key ${RS256_KEY_ID} does not belong to the platform org — aborting.`);
    }
    if (rsaKey.algorithm !== 'RS256') {
      throw new Error(`Key ${RS256_KEY_ID} has algorithm ${rsaKey.algorithm}, expected RS256 — aborting.`);
    }

    // Gate: the private half must be present and usable BEFORE any write.
    await verifyRsaPrivateHalf(rsaKey.publicKey);

    // No OTHER ACTIVE RS256 key may exist (would violate the invariant).
    const otherActiveRsa = await prisma.signingKey.findFirst({
      where: {
        organizationId: org.id,
        algorithm: 'RS256',
        status: 'ACTIVE',
        keyId: { not: RS256_KEY_ID },
      },
    });
    if (otherActiveRsa) {
      throw new Error(
        `Another ACTIVE RS256 key exists (${otherActiveRsa.keyId}) — manual review required, aborting.`,
      );
    }

    const now = new Date();
    const changes: PlannedChange[] = [];
    const prior = (k: { status: string; rotatedAt: Date | null; revokedAt: Date | null }) => ({
      status: k.status,
      rotatedAt: k.rotatedAt?.toISOString() ?? null,
      revokedAt: k.revokedAt?.toISOString() ?? null,
    });

    // --- Change 1: restore the RS256 key.
    if (rsaKey.status !== 'ACTIVE') {
      changes.push({
        id: rsaKey.id,
        keyId: rsaKey.keyId,
        algorithm: 'RS256',
        from: rsaKey.status,
        to: 'ACTIVE',
        reason: 'wrongly demoted by algorithm-blind rotation; private half verified above',
        prior: prior(rsaKey),
      });
    }

    // --- Change set 2: the orphaned ES256 pile.
    const es256Keys = await prisma.signingKey.findMany({
      where: {
        organizationId: org.id,
        algorithm: 'ES256',
        status: { in: ['ACTIVE', 'ROTATED'] },
      },
      orderBy: { createdAt: 'desc' },
    });

    const newestActive = es256Keys.find((k) => k.status === 'ACTIVE') ?? null;
    if (!newestActive) {
      console.warn('[repair] WARNING: no ACTIVE ES256 key on the platform org — nothing kept as signer.');
    }

    // Referenced keys — queried, not assumed. Both FKs point at SigningKey.id.
    const rowIds = es256Keys.map((k) => k.id);
    const [qrRefs, batchRefs] = await Promise.all([
      prisma.qRCode.groupBy({
        by: ['signingKeyId'],
        where: { signingKeyId: { in: rowIds } },
        _count: { _all: true },
      }),
      prisma.signedBatch.groupBy({
        by: ['signingKeyId'],
        where: { signingKeyId: { in: rowIds } },
        _count: { _all: true },
      }),
    ]);
    const referencedIds = new Map<string, string>();
    for (const r of qrRefs) referencedIds.set(r.signingKeyId, `${r._count._all} qr_codes`);
    for (const r of batchRefs) {
      referencedIds.set(
        r.signingKeyId,
        [referencedIds.get(r.signingKeyId), `${r._count._all} signed_batches`].filter(Boolean).join(' + '),
      );
    }

    const recentCutoff = new Date(now.getTime() - RECENT_SIGNATURE_WINDOW_MS);

    for (const key of es256Keys) {
      if (newestActive && key.id === newestActive.id) continue; // stays the org's ES256 signer

      const refs = referencedIds.get(key.id);
      const isRecent = key.createdAt >= recentCutoff || (key.rotatedAt !== null && key.rotatedAt >= recentCutoff);

      if (refs || isRecent) {
        // Not safe to revoke now. ACTIVE duplicates still must lose ACTIVE.
        if (key.status === 'ACTIVE') {
          changes.push({
            id: key.id,
            keyId: key.keyId,
            algorithm: 'ES256',
            from: key.status,
            to: 'ROTATED',
            reason: `duplicate ACTIVE demoted; kept out of REVOKED (${refs ?? 'signed within 48 h'})`,
            prior: prior(key),
          });
        }
        continue;
      }

      changes.push({
        id: key.id,
        keyId: key.keyId,
        algorithm: 'ES256',
        from: key.status,
        to: 'REVOKED',
        reason: 'orphaned hourly-loop mint; unreferenced and past the 48 h signature window',
        prior: prior(key),
      });
    }

    // --- Report.
    console.log(`\n[repair] Platform org: ${org.slug} (${org.id})`);
    console.log(`[repair] ES256 keys inspected (ACTIVE|ROTATED): ${es256Keys.length}`);
    console.log(`[repair] Kept as ES256 signer: ${newestActive ? newestActive.keyId : '(none)'}`);
    console.log(`[repair] Planned changes: ${changes.length}\n`);
    for (const c of changes) {
      console.log(`  ${c.keyId}  ${c.algorithm.padEnd(5)}  ${c.from} -> ${c.to}  (${c.reason})`);
    }
    const counts = changes.reduce<Record<string, number>>((acc, c) => {
      const label = `${c.from}->${c.to}`;
      return { ...acc, [label]: (acc[label] ?? 0) + 1 };
    }, {});
    console.log(`\n[repair] Counts: ${JSON.stringify(counts)}`);

    if (changes.length === 0) {
      console.log('[repair] Nothing to do — state already repaired (idempotent no-op).');
      return;
    }

    if (!apply) {
      console.log('\n[repair] DRY RUN — no writes performed. Re-run with --apply to execute.');
      return;
    }

    // --- Apply. Demotions before the RS256 activation so the partial unique
    // index (if already migrated in) is never transiently violated.
    const undoPath = join(
      process.cwd(),
      `repair-signing-key-rotation.undo.${now.toISOString().replace(/[:.]/g, '-')}.json`,
    );
    await writeFile(undoPath, JSON.stringify({ createdAt: now.toISOString(), changes }, null, 2), {
      mode: 0o600,
    });
    console.log(`\n[repair] Undo file written: ${undoPath}`);

    const ordered = [...changes].sort((a, b) => (a.to === 'ACTIVE' ? 1 : 0) - (b.to === 'ACTIVE' ? 1 : 0));
    await prisma.$transaction(async (tx) => {
      for (const c of ordered) {
        await tx.signingKey.update({
          where: { id: c.id },
          data:
            c.to === 'ACTIVE'
              ? { status: 'ACTIVE', rotatedAt: null, revokedAt: null }
              : c.to === 'ROTATED'
                ? { status: 'ROTATED', rotatedAt: now }
                : { status: 'REVOKED', revokedAt: now },
        });
      }
    });
    console.log(`[repair] Applied ${changes.length} change(s).`);
    console.log('[repair] Verify now: JWKS key count, RS256 auth-code flow, /health.');
  } finally {
    await prisma.$disconnect();
  }
}

async function runUndo(prisma: PrismaClient, undoFile: string): Promise<void> {
  const parsed = JSON.parse(await readFile(undoFile, 'utf8')) as { changes: PlannedChange[] };
  if (!Array.isArray(parsed.changes)) throw new Error(`Malformed undo file: ${undoFile}`);
  console.log(`[repair] Reverting ${parsed.changes.length} change(s) from ${undoFile}…`);
  await prisma.$transaction(async (tx) => {
    for (const c of parsed.changes) {
      await tx.signingKey.update({
        where: { id: c.id },
        data: {
          status: c.prior.status as 'ACTIVE' | 'ROTATED' | 'REVOKED',
          rotatedAt: c.prior.rotatedAt ? new Date(c.prior.rotatedAt) : null,
          revokedAt: c.prior.revokedAt ? new Date(c.prior.revokedAt) : null,
        },
      });
    }
  });
  console.log('[repair] Undo complete.');
}

main().catch((err) => {
  console.error('[repair] FAILED:', (err as Error).message);
  process.exitCode = 1;
});
