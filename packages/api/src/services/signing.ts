import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import type { PrismaClient, SigningKey } from '@prisma/client';
import { config } from '../lib/config.js';
import { generateKeyPair, verifySignature } from '../lib/crypto.js';
import { encryptAtRest, decryptAtRest } from '../lib/key-at-rest.js';

const signerPushUrl = config.slhdsaSigner.url;
const signerPushToken = config.slhdsaSigner.token;

/**
 * AUDIT-2 N-2: domain-separation prefix applied to every ECDSA canonical
 * signing and verification operation. Byte-identical to the constant in
 * `packages/signer-service/src/server.ts` and
 * `packages/api/src/services/ecdsa-signer/local.ts`. Pinned in
 * `ALGORITHM.md §12`; changing the literal is a protocol-version bump.
 */
const ECDSA_CANONICAL_DOMAIN_PREFIX = 'qrauth:ecdsa-canonical:v1:';
import {
  slhDsaGenerateKeyPair,
  type SlhDsaKeyPair,
} from './slhdsa-adapter.js';
import type { EcdsaSigner } from './ecdsa-signer/index.js';
import { LocalEcdsaSigner } from './ecdsa-signer/local.js';
import { enqueueSigningKeyCreatedWebhook } from './security-webhook.js';

function ecdsaKeyPath(keyId: string): string {
  return join(config.kms.ecdsaPrivateKeyPath, `${keyId}.ecdsa.enc`);
}

function slhdsaKeyPath(keyId: string): string {
  return join(config.kms.ecdsaPrivateKeyPath, `${keyId}.slhdsa.enc`);
}

/**
 * Write a file atomically: write to a sibling temp path, then rename.
 * `fs.rename` is atomic on POSIX within the same directory, so a crash
 * mid-write either leaves the temp file behind (cleanup-safe) or the
 * final file in a consistent state (crash-safe). AUDIT-FINDING-016.
 */
async function atomicWriteFile(path: string, contents: string): Promise<void> {
  const tmp = `${path}.tmp.${randomBytes(8).toString('hex')}`;
  await writeFile(tmp, contents, { mode: 0o600 });
  await rename(tmp, path);
}

export class SigningService {
  /**
   * ECDSA signer backend. Injected so routes / proximity / auth-session
   * all share the same instance. Defaults to the local (in-process)
   * backend if the caller does not supply one — the server boot path
   * constructs an `HttpEcdsaSigner` when `ECDSA_SIGNER=http`.
   */
  private ecdsaSigner: EcdsaSigner;

  constructor(private prisma: PrismaClient, ecdsaSigner?: EcdsaSigner) {
    this.ecdsaSigner = ecdsaSigner ?? new LocalEcdsaSigner();
  }

  /**
   * Push encrypted key envelopes to the remote signer service so it can
   * serve sign requests for this keyId. No-op when both signers are local.
   * Failures are logged but never thrown — the key exists locally and
   * signing can fall back to local if needed.
   */
  private async pushKeysToSigner(keyId: string, ecdsaEnvelope: string, slhdsaEnvelope: string): Promise<void> {
    const needsPush =
      config.slhdsaSigner.backend === 'http' || config.ecdsaSigner.backend === 'http';
    if (!needsPush || !signerPushUrl || !signerPushToken) return;

    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 10_000);
      const res = await fetch(`${signerPushUrl}/v1/keys/${keyId}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${signerPushToken}`,
        },
        body: JSON.stringify({ ecdsa: ecdsaEnvelope, slhdsa: slhdsaEnvelope }),
        signal: controller.signal,
      });
      clearTimeout(timeout);
      if (!res.ok) {
        const body = await res.text();
        // eslint-disable-next-line no-console
        console.error(`[signing] pushKeysToSigner ${keyId}: ${res.status} ${body}`);
      }
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error(`[signing] pushKeysToSigner ${keyId} failed:`, err);
    }
  }

  /**
   * Generate a fresh ECDSA P-256 key pair for the given organization.
   *
   * AUDIT-FINDING-016: keys are written atomically (temp + rename) and
   * encrypted at rest via `encryptAtRest`. Both halves use the new
   * `.ecdsa.enc` / `.slhdsa.enc` extensions. A crash mid-generation
   * never leaves partial material on disk.
   */
  async createKeyPair(organizationId: string): Promise<SigningKey> {
    const { publicKey, privateKey, keyId } = await generateKeyPair();

    const keysDir = config.kms.ecdsaPrivateKeyPath;
    await mkdir(keysDir, { recursive: true });

    // Persist the ECDSA private key as an encrypted envelope.
    const ecdsaEnvelope = encryptAtRest(Buffer.from(privateKey, 'utf8'));
    await atomicWriteFile(ecdsaKeyPath(keyId), ecdsaEnvelope);

    // Generate the paired SLH-DSA keypair. Both legs share a single
    // keyId so rotation/revocation/audit live in one row.
    const slhPair = await slhDsaGenerateKeyPair();
    const slhdsaEnvelope = encryptAtRest(slhPair.privateKey);
    await atomicWriteFile(slhdsaKeyPath(keyId), slhdsaEnvelope);

    // Push to remote signer so it can serve sign requests for this key.
    await this.pushKeysToSigner(keyId, ecdsaEnvelope, slhdsaEnvelope);

    // Persist the public key and metadata to the database.
    const signingKey = await this.prisma.signingKey.create({
      data: {
        organizationId,
        publicKey,
        keyId,
        algorithm: 'ES256',
        status: 'ACTIVE',
        slhdsaPublicKey: slhPair.publicKey.toString('base64'),
        slhdsaAlgorithm: 'slh-dsa-sha2-128s',
      },
    });

    // AUDIT-2 M-13: emit the signing-key.created webhook so the
    // organization can detect an unauthorized key insertion (T-9).
    // Fire-and-forget — `enqueueSigningKeyCreatedWebhook` swallows
    // every error path internally so key creation is never blocked by
    // a missing endpoint, a bad secret, or Redis being unreachable.
    void enqueueSigningKeyCreatedWebhook(this.prisma, signingKey);

    return signingKey;
  }

  /**
   * Load the SLH-DSA keypair for `keyId`. Returns `null` when the
   * on-disk file is missing or the row has no `slhdsaPublicKey`.
   */
  async loadSlhDsaKeyPair(keyId: string): Promise<SlhDsaKeyPair | null> {
    let envelope: string;
    try {
      envelope = await readFile(slhdsaKeyPath(keyId), 'utf8');
    } catch {
      return null;
    }

    let privateKey: Buffer;
    try {
      const decrypted = decryptAtRest(envelope.trim());
      if (decrypted.length !== 64) {
        return null; // SLH-DSA-SHA2-128s secret keys are exactly 64 bytes per FIPS 205
      }
      privateKey = decrypted;
    } catch {
      return null;
    }

    const row = await this.prisma.signingKey.findUnique({ where: { keyId } });
    if (!row?.slhdsaPublicKey) return null;

    return {
      publicKey: Buffer.from(row.slhdsaPublicKey, 'base64'),
      privateKey,
    };
  }

  /**
   * Sign a pre-built canonical payload string with the ECDSA private
   * key identified by `keyId`. Delegates to the injected `EcdsaSigner`
   * backend — the API server no longer reads PEM files directly
   * (AUDIT-FINDING-016). Returns the DER-encoded signature as base64.
   */
  async signCanonical(keyId: string, canonical: string): Promise<string> {
    return this.ecdsaSigner.signCanonical(keyId, canonical);
  }

  /**
   * Verify an ECDSA signature against a pre-built canonical payload
   * string using the provided PEM public key. Returns `true` on valid,
   * `false` otherwise. Never throws.
   *
   * AUDIT-2 N-2: the verifier reconstructs the domain-separation prefix
   * the signer prepends on the signing side. Keeping the wrap here means
   * every caller gets the domain tag for free — they pass the same
   * canonical bytes they would pass to `signCanonical`, and both sides
   * line up on the prefixed form.
   */
  verifyCanonical(publicKey: string, signature: string, canonical: string): boolean {
    return verifySignature(publicKey, signature, ECDSA_CANONICAL_DOMAIN_PREFIX + canonical);
  }

  /**
   * Return the ACTIVE signing key for the given organization.
   */
  async getActiveKey(organizationId: string): Promise<SigningKey> {
    const key = await this.prisma.signingKey.findFirst({
      where: { organizationId, status: 'ACTIVE' },
      orderBy: { createdAt: 'desc' },
    });

    if (!key) {
      throw new Error(
        `No active signing key found for organization "${organizationId}". ` +
          'Generate a key pair first.',
      );
    }

    return key;
  }

  /**
   * Rotate the active signing key for an organization.
   *
   * AUDIT-2 M-13: this path also issues a `SigningKey.create` inside
   * the transaction below, so we emit the same `signing-key.created`
   * webhook the `createKeyPair` path does. The plan's target state
   * pins the invariant to "every SigningKey.create call" — the Files
   * list names `createKeyPair` explicitly but omits rotateKey; the
   * omission is inconsistent with the target state and with the
   * E2E acceptance criterion (which needs a path that creates a
   * signing key *after* the user has registered a webhook endpoint —
   * only rotateKey fits, since createKeyPair fires during signup
   * before the user can authenticate).
   */
  async rotateKey(organizationId: string): Promise<SigningKey> {
    const current = await this.getActiveKey(organizationId);

    const { publicKey, privateKey, keyId } = await generateKeyPair();

    const keysDir = config.kms.ecdsaPrivateKeyPath;
    await mkdir(keysDir, { recursive: true });

    const ecdsaEnvelope = encryptAtRest(Buffer.from(privateKey, 'utf8'));
    await atomicWriteFile(ecdsaKeyPath(keyId), ecdsaEnvelope);

    const slhPair = await slhDsaGenerateKeyPair();
    const slhdsaEnvelope = encryptAtRest(slhPair.privateKey);
    await atomicWriteFile(slhdsaKeyPath(keyId), slhdsaEnvelope);

    await this.pushKeysToSigner(keyId, ecdsaEnvelope, slhdsaEnvelope);

    const newKey = await this.prisma.$transaction(async (tx) => {
      await tx.signingKey.update({
        where: { id: current.id },
        data: { status: 'ROTATED', rotatedAt: new Date() },
      });

      return tx.signingKey.create({
        data: {
          organizationId,
          publicKey,
          keyId,
          algorithm: 'ES256',
          status: 'ACTIVE',
          slhdsaPublicKey: slhPair.publicKey.toString('base64'),
          slhdsaAlgorithm: 'slh-dsa-sha2-128s',
        },
      });
    });

    // AUDIT-2 M-13: emit the signing-key.created webhook for the new
    // key. Fire-and-forget — `enqueueSigningKeyCreatedWebhook`
    // swallows every error path internally so rotation is never
    // blocked by a webhook emission failure.
    void enqueueSigningKeyCreatedWebhook(this.prisma, newKey);

    return newKey;
  }
}
