import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { importSPKI, flattenedVerify } from 'jose';
import type { PrismaClient, SigningKey } from '@prisma/client';
import { config } from '../lib/config.js';
import { generateKeyPair, generateRsaKeyPair, verifySignature } from '../lib/crypto.js';
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
import type { RsaSigner } from './rsa-signer/index.js';
import { LocalRsaSigner } from './rsa-signer/local.js';
import { enqueueSigningKeyCreatedWebhook } from './security-webhook.js';

function ecdsaKeyPath(keyId: string): string {
  return join(config.kms.ecdsaPrivateKeyPath, `${keyId}.ecdsa.enc`);
}

function rsaKeyPath(keyId: string): string {
  return join(config.kms.ecdsaPrivateKeyPath, `${keyId}.rsa.enc`);
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

  /**
   * RSA signer backend (ADR-0003 Slice 7a). Injected like `ecdsaSigner`;
   * defaults to the local (in-process) backend. The server boot path
   * constructs an `HttpRsaSigner` when `RSA_SIGNER=http` (wired in Slice 7b).
   * Used only for the OIDC RS256 ID-token JWS path.
   */
  private rsaSigner: RsaSigner;

  constructor(private prisma: PrismaClient, ecdsaSigner?: EcdsaSigner, rsaSigner?: RsaSigner) {
    this.ecdsaSigner = ecdsaSigner ?? new LocalEcdsaSigner();
    this.rsaSigner = rsaSigner ?? new LocalRsaSigner();
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
   * Push the encrypted RSA envelope to the signer so it can serve
   * `/v1/sign-rsa-jws` for this keyId (ADR-0003 Slice 7b). Mirrors
   * {@link pushKeysToSigner}; gated on the ECDSA signer backend (the RSA
   * endpoint lives on the same signer host). No-op when local. Failures are
   * logged but never thrown — the bootstrap probe is the loud end-to-end check.
   */
  private async pushRsaKeyToSigner(keyId: string, rsaEnvelope: string): Promise<void> {
    const needsPush = config.ecdsaSigner.backend === 'http';
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
        body: JSON.stringify({ rsa: rsaEnvelope }),
        signal: controller.signal,
      });
      clearTimeout(timeout);
      if (!res.ok) {
        const body = await res.text();
        // eslint-disable-next-line no-console
        console.error(`[signing] pushRsaKeyToSigner ${keyId}: ${res.status} ${body}`);
      }
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error(`[signing] pushRsaKeyToSigner ${keyId} failed:`, err);
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
   * Generate a fresh RSA-2048 signing key for `organizationId` — the OIDC
   * RS256 ID-token key (ADR-0003 Slice 7b; OIDC Core §15.1 mandatory). Same
   * custody posture as {@link createKeyPair}: the private bytes are generated,
   * encrypted at rest (`.rsa.enc`), and pushed to the signer; the API box
   * never serves signatures from local PEM in production. No SLH-DSA leg — the
   * RSA key is OIDC-only (the QR/proximity hybrid path stays ECDSA+SLH-DSA).
   */
  async createRsaKeyPair(organizationId: string): Promise<SigningKey> {
    const { publicKey, privateKey, keyId } = await generateRsaKeyPair();

    const keysDir = config.kms.ecdsaPrivateKeyPath;
    await mkdir(keysDir, { recursive: true });

    const rsaEnvelope = encryptAtRest(Buffer.from(privateKey, 'utf8'));
    await atomicWriteFile(rsaKeyPath(keyId), rsaEnvelope);

    // Push to the remote signer so it can serve /v1/sign-rsa-jws for this key.
    await this.pushRsaKeyToSigner(keyId, rsaEnvelope);

    const signingKey = await this.prisma.signingKey.create({
      data: {
        organizationId,
        publicKey,
        keyId,
        algorithm: 'RS256',
        status: 'ACTIVE',
        // No SLH-DSA pairing: this key signs OIDC ID tokens only.
      },
    });

    // AUDIT-2 M-13: same signing-key.created webhook as the ECDSA path (T-9).
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
   * Sign a JWS canonical input (`base64url(header).base64url(payload)`)
   * via the signer. Returns the compact-JWS-ready base64url `R||S`
   * signature (IEEE P1363).
   *
   * Use ONLY for JWS / OIDC ID tokens. For all other signing (Living Code
   * frames, proximity attestations, audit assertions) continue using
   * `signCanonical`, which applies the `qrauth:ecdsa-canonical:v1:`
   * domain-separation prefix. ADR-0003 Slice 3a.
   */
  async signJws(keyId: string, canonicalInput: string): Promise<string> {
    return this.ecdsaSigner.signJws(keyId, canonicalInput);
  }

  /**
   * Verify a JWS signature the way a stock OIDC client would — over
   * exactly `canonicalInput` (no domain prefix), expecting the IEEE P1363
   * raw `R||S` encoding. Verify-only: never touches the signer or any
   * private key material. Returns `true` on valid, `false` otherwise
   * (never throws). ADR-0003 Slice 3a.
   *
   * Used by tests to round-trip `signJws` output without depending on
   * `jose` in production call sites.
   */
  async verifyJws(
    publicKeyPem: string,
    canonicalInput: string,
    signatureB64url: string,
  ): Promise<boolean> {
    try {
      const [protectedHeader, payload] = canonicalInput.split('.');
      if (!protectedHeader || !payload) return false;
      const key = await importSPKI(publicKeyPem, 'ES256');
      await flattenedVerify(
        { protected: protectedHeader, payload, signature: signatureB64url },
        key,
        { algorithms: ['ES256'] },
      );
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Sign a JWS canonical input (`base64url(header).base64url(payload)`) with
   * RS256 via the signer. Returns the compact-JWS-ready base64url signature.
   * Use ONLY for OIDC ID tokens (RS256 — OIDC Core §15.1 mandatory). Mirrors
   * {@link signJws}; routes through the injected `RsaSigner`. ADR-0003 Slice 7a.
   */
  async signRsaJws(keyId: string, canonicalInput: string): Promise<string> {
    return this.rsaSigner.signJws(keyId, canonicalInput);
  }

  /**
   * Verify an RS256 JWS the way a stock OIDC client would — over exactly
   * `canonicalInput` (no domain prefix). Verify-only: never touches the signer
   * or any private key. Returns `true` on valid, `false` otherwise (never
   * throws). Used by tests to round-trip `signRsaJws`. ADR-0003 Slice 7a.
   */
  async verifyRsaJws(
    publicKeyPem: string,
    canonicalInput: string,
    signatureB64url: string,
  ): Promise<boolean> {
    try {
      const [protectedHeader, payload] = canonicalInput.split('.');
      if (!protectedHeader || !payload) return false;
      const key = await importSPKI(publicKeyPem, 'RS256');
      await flattenedVerify(
        { protected: protectedHeader, payload, signature: signatureB64url },
        key,
        { algorithms: ['RS256'] },
      );
      return true;
    } catch {
      return false;
    }
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
