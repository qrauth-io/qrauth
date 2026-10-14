/**
 * Surgical rollback for a BAD ROTATION — the recovery instrument for "the
 * rotation minted a new key, the signer push returned 2xx, but the envelope
 * is unusable and /token broke while /health reads green"
 * (docs/ops/rs256-repair-runbook.md step 6b).
 *
 * Why this exists as its own script (2026-09-08):
 *   - the repair script's undo file rolls back the whole REPAIR (re-demoting
 *     the restored key, un-revoking ~197 keys) — wrong surgery;
 *   - the repair script cannot re-activate a key while the bad key holds
 *     ACTIVE — the partial unique index on (organizationId, algorithm)
 *     WHERE status = 'ACTIVE' blocks it, by design;
 *   - hand-written SQL on SigningKey status is forbidden by the standing rule.
 *
 * What it does, in ONE transaction (so the unique index is never violated
 * mid-flight): demote the bad key ACTIVE -> ROTATED, restore the target key
 * ROTATED -> ACTIVE (clearing rotatedAt/revokedAt). Both updates are
 * conditional on the expected current status and the transaction aborts if
 * either misses — a concurrent change can never be half-applied.
 *
 * Pre-flight, before ANY write (mirrors the repair script, plus the signer):
 *   - both keys exist, same organization, same algorithm, not the same key;
 *   - the bad key is currently ACTIVE and the restore target is ROTATED —
 *     refused otherwise;
 *   - the restore target's private half is present and loadable on disk
 *     (decrypts, parses, matches the stored public key, signs locally);
 *   - when the signer backend is http, the SIGNER HOST is asked to sign a
 *     probe with the restore target and the signature is verified against
 *     the stored public key — restoring a key the signer cannot use would
 *     recreate the exact failure this script exists to fix.
 *
 * DRY-RUN BY DEFAULT — prints the diff, writes nothing.
 *   npx tsx --env-file=.env scripts/rollback-bad-rotation.ts --bad <keyId> --restore <keyId>
 * Apply (writes an undo file first):
 *   ... --bad <keyId> --restore <keyId> --apply
 * Revert a previous apply:
 *   ... --undo <undo-file.json>
 *
 * NEVER run automatically. Operator-run only, per the runbook's division of
 * labour. Do not delete rows; do not touch any other key.
 */

import { readFile, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import {
  createPrivateKey,
  createPublicKey,
  sign as cryptoSign,
  verify as cryptoVerify,
} from 'node:crypto';
import { importSPKI, flattenedVerify } from 'jose';
import { PrismaClient, type SigningKey } from '@prisma/client';
import { config } from '../src/lib/config.js';
import { decryptAtRest } from '../src/lib/key-at-rest.js';

type Algorithm = 'ES256' | 'RS256';

interface KeyPriorState {
  id: string;
  keyId: string;
  status: string;
  rotatedAt: string | null;
  revokedAt: string | null;
}

export interface RollbackPlan {
  organizationId: string;
  algorithm: Algorithm;
  bad: KeyPriorState;
  restore: KeyPriorState;
}

const priorState = (k: SigningKey): KeyPriorState => ({
  id: k.id,
  keyId: k.keyId,
  status: k.status,
  rotatedAt: k.rotatedAt?.toISOString() ?? null,
  revokedAt: k.revokedAt?.toISOString() ?? null,
});

/**
 * Validate the two keys and build the plan. Throws on every refusal path;
 * performs NO writes. Exported for the unit suite.
 */
export async function planRollback(
  prisma: PrismaClient,
  opts: { badKeyId: string; restoreKeyId: string },
): Promise<RollbackPlan> {
  if (opts.badKeyId === opts.restoreKeyId) {
    throw new Error('badKeyId and restoreKeyId are the same key — nothing to roll back.');
  }

  const bad = await prisma.signingKey.findUnique({ where: { keyId: opts.badKeyId } });
  if (!bad) throw new Error(`Bad key "${opts.badKeyId}" not found — aborting.`);
  const restore = await prisma.signingKey.findUnique({ where: { keyId: opts.restoreKeyId } });
  if (!restore) throw new Error(`Restore target "${opts.restoreKeyId}" not found — aborting.`);

  if (bad.organizationId !== restore.organizationId) {
    throw new Error(
      `Keys belong to different organizations (${bad.organizationId} vs ${restore.organizationId}) — aborting.`,
    );
  }
  if (bad.algorithm !== restore.algorithm) {
    throw new Error(
      `Algorithm mismatch: bad key is ${bad.algorithm}, restore target is ${restore.algorithm} — aborting.`,
    );
  }
  if (bad.algorithm !== 'ES256' && bad.algorithm !== 'RS256') {
    throw new Error(`Unsupported algorithm "${bad.algorithm}" — aborting.`);
  }
  if (bad.status !== 'ACTIVE') {
    throw new Error(
      `Bad key "${bad.keyId}" is ${bad.status}, not ACTIVE — this script swaps the CURRENT ` +
        'ACTIVE key for its predecessor; refusing to run.',
    );
  }
  if (restore.status !== 'ROTATED') {
    throw new Error(
      `Restore target "${restore.keyId}" is ${restore.status}, not ROTATED — refusing to run ` +
        '(a REVOKED key needs deliberate review; use the repair-script pattern instead).',
    );
  }

  return {
    organizationId: bad.organizationId,
    algorithm: bad.algorithm,
    bad: priorState(bad),
    restore: priorState(restore),
  };
}

/**
 * Execute the swap in one transaction. Both updates are conditional on the
 * status the plan observed; if either misses (concurrent change), the
 * transaction throws and NOTHING is applied — the partial unique index is
 * never violated because the demote runs before the restore. Exported for
 * the unit suite.
 */
export async function executeRollback(
  prisma: PrismaClient,
  plan: RollbackPlan,
  now: Date = new Date(),
): Promise<void> {
  await prisma.$transaction(async (tx) => {
    const demoted = await tx.signingKey.updateMany({
      where: { id: plan.bad.id, status: 'ACTIVE' },
      data: { status: 'ROTATED', rotatedAt: now },
    });
    if (demoted.count !== 1) {
      throw new Error(
        `Bad key "${plan.bad.keyId}" was not ACTIVE at execution time — state changed since ` +
          'the plan was built; nothing applied.',
      );
    }
    const restored = await tx.signingKey.updateMany({
      where: { id: plan.restore.id, status: 'ROTATED' },
      data: { status: 'ACTIVE', rotatedAt: null, revokedAt: null },
    });
    if (restored.count !== 1) {
      throw new Error(
        `Restore target "${plan.restore.keyId}" was not ROTATED at execution time — state ` +
          'changed since the plan was built; nothing applied (transaction rolled back).',
      );
    }
  });
}

// ---------------------------------------------------------------------------
// Pre-flight signability checks (main-only; network + disk).
// ---------------------------------------------------------------------------

function envelopePath(keyId: string, algorithm: Algorithm): string {
  const ext = algorithm === 'RS256' ? 'rsa.enc' : 'ecdsa.enc';
  return join(config.kms.ecdsaPrivateKeyPath, `${keyId}.${ext}`);
}

function normalizePem(pem: string): string {
  return pem.replace(/\s+/g, '');
}

async function verifyLocalPrivateHalf(keyId: string, algorithm: Algorithm, publicKeyPem: string): Promise<void> {
  const path = envelopePath(keyId, algorithm);
  let envelope: string;
  try {
    envelope = await readFile(path, 'utf8');
  } catch (err) {
    throw new Error(`Private envelope not readable at ${path} — aborting. (${(err as Error).message})`);
  }
  const privatePem = decryptAtRest(envelope.trim()).toString('utf8');
  const privateKey = createPrivateKey(privatePem);
  const derivedPublic = createPublicKey(privateKey).export({ type: 'spki', format: 'pem' }).toString();
  if (normalizePem(derivedPublic) !== normalizePem(publicKeyPem)) {
    throw new Error(`Private key at ${path} does NOT match the stored public key — aborting.`);
  }
  const probe = Buffer.from(`rollback-probe:${Date.now()}`);
  const signature = cryptoSign('sha256', probe, privateKey);
  if (!cryptoVerify('sha256', probe, createPublicKey(publicKeyPem), signature)) {
    throw new Error(`Local sign/verify probe failed for ${keyId} — aborting.`);
  }
  console.log(`[rollback] local private half verified for ${keyId} (${path})`);
}

/**
 * Ask the SIGNER HOST to sign a probe with the restore target and verify the
 * JWS signature against the stored public key. Restoring a key the signer
 * cannot use would recreate the exact failure this script exists to fix.
 */
async function verifySignerCanSign(keyId: string, algorithm: Algorithm, publicKeyPem: string): Promise<void> {
  if (config.ecdsaSigner.backend !== 'http') {
    console.log('[rollback] signer backend is local — the local probe above is authoritative.');
    return;
  }
  const url = config.ecdsaSigner.url;
  const token = config.ecdsaSigner.token;
  if (!url || !token) {
    throw new Error('ECDSA_SIGNER=http but ECDSA_SIGNER_URL/TOKEN missing — cannot pre-flight the signer; aborting.');
  }

  // base64url(header).base64url(payload) — satisfies the signer's JWS shape guard.
  const header = Buffer.from(JSON.stringify({ alg: algorithm, typ: 'JWT', kid: keyId })).toString('base64url');
  const payload = Buffer.from(JSON.stringify({ probe: 'rollback-preflight' })).toString('base64url');
  const canonicalInput = `${header}.${payload}`;

  const endpoint = algorithm === 'RS256' ? '/v1/sign-rsa-jws' : '/v1/sign-ecdsa-jws';
  const res = await fetch(`${url}${endpoint}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    body: JSON.stringify({ keyId, canonicalInput }),
  });
  if (!res.ok) {
    throw new Error(`Signer refused to sign with ${keyId}: HTTP ${res.status} ${await res.text()} — aborting.`);
  }
  const { signature } = (await res.json()) as { signature: string };

  const key = await importSPKI(publicKeyPem, algorithm);
  try {
    await flattenedVerify({ protected: header, payload, signature }, key, { algorithms: [algorithm] });
  } catch {
    throw new Error(
      `Signer returned a signature for ${keyId} that does NOT verify against the stored ` +
        'public key — the signer holds a different or corrupt private half; aborting.',
    );
  }
  console.log(`[rollback] signer host signs with ${keyId} and the signature verifies.`);
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

async function runUndo(prisma: PrismaClient, undoFile: string): Promise<void> {
  const parsed = JSON.parse(await readFile(undoFile, 'utf8')) as { changes: KeyPriorState[] };
  if (!Array.isArray(parsed.changes)) throw new Error(`Malformed undo file: ${undoFile}`);
  console.log(`[rollback] Reverting ${parsed.changes.length} row(s) from ${undoFile}…`);
  await prisma.$transaction(async (tx) => {
    for (const c of parsed.changes) {
      await tx.signingKey.update({
        where: { id: c.id },
        data: {
          status: c.status as 'ACTIVE' | 'ROTATED' | 'REVOKED',
          rotatedAt: c.rotatedAt ? new Date(c.rotatedAt) : null,
          revokedAt: c.revokedAt ? new Date(c.revokedAt) : null,
        },
      });
    }
  });
  console.log('[rollback] Undo complete.');
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const apply = args.includes('--apply');
  const argOf = (flag: string): string | null => {
    const i = args.indexOf(flag);
    if (i === -1) return null;
    const v = args[i + 1];
    if (!v || v.startsWith('--')) throw new Error(`${flag} requires a value`);
    return v;
  };
  const undoFile = argOf('--undo');

  const prisma = new PrismaClient();
  try {
    if (undoFile) {
      await runUndo(prisma, undoFile);
      return;
    }

    const badKeyId = argOf('--bad');
    const restoreKeyId = argOf('--restore');
    if (!badKeyId || !restoreKeyId) {
      throw new Error('Usage: rollback-bad-rotation.ts --bad <keyId> --restore <keyId> [--apply]');
    }

    const plan = await planRollback(prisma, { badKeyId, restoreKeyId });

    // Gate: the restore target must be provably usable BEFORE any write.
    const restoreRow = await prisma.signingKey.findUnique({ where: { keyId: restoreKeyId } });
    await verifyLocalPrivateHalf(restoreKeyId, plan.algorithm, restoreRow!.publicKey);
    await verifySignerCanSign(restoreKeyId, plan.algorithm, restoreRow!.publicKey);

    console.log(`\n[rollback] Plan (org ${plan.organizationId}, ${plan.algorithm}):`);
    console.log(`  ${plan.bad.keyId}  ACTIVE  -> ROTATED  (bad rotation product)`);
    console.log(`  ${plan.restore.keyId}  ROTATED -> ACTIVE  (restore)`);

    if (!apply) {
      console.log('\n[rollback] DRY RUN — no writes performed. Re-run with --apply to execute.');
      return;
    }

    const now = new Date();
    const undoPath = join(
      process.cwd(),
      `rollback-bad-rotation.undo.${now.toISOString().replace(/[:.]/g, '-')}.json`,
    );
    await writeFile(
      undoPath,
      JSON.stringify({ createdAt: now.toISOString(), changes: [plan.bad, plan.restore] }, null, 2),
      { mode: 0o600 },
    );
    console.log(`[rollback] Undo file written: ${undoPath}`);

    await executeRollback(prisma, plan, now);
    console.log('[rollback] Applied. Verify now: /health, JWKS, and an end-to-end token flow.');
  } finally {
    await prisma.$disconnect();
  }
}

// Only run the CLI when executed directly — the unit suite imports the
// exported functions without side effects.
const invokedDirectly = (() => {
  try {
    return (
      process.argv[1] !== undefined &&
      import.meta.url === pathToFileURL(resolve(process.argv[1])).href
    );
  } catch {
    return false;
  }
})();

if (invokedDirectly) {
  main().catch((err) => {
    console.error('[rollback] FAILED:', (err as Error).message);
    process.exitCode = 1;
  });
}
