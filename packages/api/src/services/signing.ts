import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { PrismaClient, SigningKey } from '@prisma/client';
import { config } from '../lib/config.js';
import {
  generateKeyPair,
  signPayload,
  verifySignature,
} from '../lib/crypto.js';
import { hashPayload } from '@qrauth/shared';
import {
  slhDsaGenerateKeyPair,
  type SlhDsaKeyPair,
} from './slhdsa-adapter.js';

/**
 * On-disk filename for an SLH-DSA private key. Sits alongside the ECDSA PEM
 * file in `config.kms.ecdsaPrivateKeyPath`. The bytes are stored base64 so the
 * file is grep-friendly and the format is identical to how the public key
 * lives in the database.
 */
function slhdsaKeyPath(keyId: string): string {
  return join(config.kms.ecdsaPrivateKeyPath, `${keyId}.slhdsa.key`);
}

export class SigningService {
  constructor(private prisma: PrismaClient) {}

  /**
   * Generate a fresh ECDSA P-256 key pair for the given organization.
   * The public key is persisted to the database; the private key is written
   * to the local filesystem under config.kms.ecdsaPrivateKeyPath.
   */
  async createKeyPair(organizationId: string): Promise<SigningKey> {
    const { publicKey, privateKey, keyId } = await generateKeyPair();

    // Ensure the keys directory exists before writing.
    const keysDir = config.kms.ecdsaPrivateKeyPath;
    await mkdir(keysDir, { recursive: true });

    // Persist the ECDSA private key as a PEM file named by its keyId.
    const keyPath = join(keysDir, `${keyId}.pem`);
    await writeFile(keyPath, privateKey, { mode: 0o600 });

    // Generate the paired SLH-DSA keypair. Both legs of the hybrid signing
    // model share a single keyId so rotation, revocation, and audit live in
    // one row. The SLH-DSA secret key is base64-encoded raw bytes — there is
    // no PEM format for SLH-DSA in any standard yet.
    const slhPair = await slhDsaGenerateKeyPair();
    await writeFile(
      slhdsaKeyPath(keyId),
      slhPair.privateKey.toString('base64'),
      { mode: 0o600 },
    );

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

    return signingKey;
  }

  /**
   * Load the SLH-DSA keypair that was generated alongside the ECDSA PEM for
   * `keyId`. Returns `null` when the SLH-DSA file is missing — this is the
   * case for legacy keys created before the PQC layer landed, and the caller
   * MUST be prepared to fall back to ECDSA-only signing for those.
   */
  async loadSlhDsaKeyPair(keyId: string): Promise<SlhDsaKeyPair | null> {
    const path = slhdsaKeyPath(keyId);
    let secretB64: string;
    try {
      secretB64 = await readFile(path, 'utf8');
    } catch {
      return null;
    }
    const privateKey = Buffer.from(secretB64.trim(), 'base64');

    const row = await this.prisma.signingKey.findUnique({ where: { keyId } });
    if (!row?.slhdsaPublicKey) return null;

    return {
      publicKey: Buffer.from(row.slhdsaPublicKey, 'base64'),
      privateKey,
    };
  }

  /**
   * Sign a QR code's canonical payload using the private key identified by
   * keyId. The private key PEM is read from the filesystem at call time so
   * it is never held in memory longer than necessary.
   *
   * Returns the DER-encoded signature as a base64 string.
   */
  async signQRCode(
    keyId: string,
    token: string,
    destinationUrl: string,
    geoHash: string,
    expiresAt: string,
    contentHash: string = '',
  ): Promise<string> {
    const keyPath = join(config.kms.ecdsaPrivateKeyPath, `${keyId}.pem`);

    let privateKey: string;
    try {
      privateKey = await readFile(keyPath, 'utf8');
    } catch (err) {
      throw new Error(
        `Private key not found for keyId "${keyId}": ${(err as NodeJS.ErrnoException).message}`,
      );
    }

    const payload = hashPayload(token, destinationUrl, geoHash, expiresAt, contentHash);
    return signPayload(privateKey, payload);
  }

  /**
   * Verify a QR code's signature using the provided PEM public key.
   * Returns true when the signature is cryptographically valid, false
   * otherwise. This method never throws.
   */
  verifyQRCode(
    publicKey: string,
    signature: string,
    token: string,
    destinationUrl: string,
    geoHash: string,
    expiresAt: string,
    contentHash: string = '',
  ): boolean {
    const payload = hashPayload(token, destinationUrl, geoHash, expiresAt, contentHash);
    return verifySignature(publicKey, signature, payload);
  }

  /**
   * Return the ACTIVE signing key for the given organization.
   * Throws when no active key exists (the organization has not yet generated one,
   * or all keys have been rotated / revoked).
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
   * 1. Mark the current ACTIVE key as ROTATED (sets rotatedAt).
   * 2. Generate a new ECDSA key pair and persist it.
   *
   * Both operations run inside a single Prisma transaction so the organization
   * is never left without a usable active key.
   *
   * Returns the newly created SigningKey record.
   */
  async rotateKey(organizationId: string): Promise<SigningKey> {
    const current = await this.getActiveKey(organizationId);

    // Generate the new key pair before the transaction so we minimise the
    // time the transaction is open while doing I/O.
    const { publicKey, privateKey, keyId } = await generateKeyPair();

    const keysDir = config.kms.ecdsaPrivateKeyPath;
    await mkdir(keysDir, { recursive: true });

    const keyPath = join(keysDir, `${keyId}.pem`);
    await writeFile(keyPath, privateKey, { mode: 0o600 });

    // Generate paired SLH-DSA key for the new keyId.
    const slhPair = await slhDsaGenerateKeyPair();
    await writeFile(slhdsaKeyPath(keyId), slhPair.privateKey.toString('base64'), { mode: 0o600 });

    const newKey = await this.prisma.$transaction(async (tx) => {
      // Mark the current key as ROTATED.
      await tx.signingKey.update({
        where: { id: current.id },
        data: { status: 'ROTATED', rotatedAt: new Date() },
      });

      // Create the replacement key.
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

    return newKey;
  }
}
