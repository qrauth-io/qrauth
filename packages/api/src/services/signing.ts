import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { PrismaClient, SigningKey } from '@prisma/client';
import { config } from '../lib/config.js';
import {
  generateKeyPair,
  signPayload,
  verifySignature,
} from '../lib/crypto.js';
import { hashPayload } from '@vqr/shared';

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

    // Persist the private key as a PEM file named by its keyId.
    const keyPath = join(keysDir, `${keyId}.pem`);
    await writeFile(keyPath, privateKey, { mode: 0o600 });

    // Persist the public key and metadata to the database.
    const signingKey = await this.prisma.signingKey.create({
      data: {
        organizationId,
        publicKey,
        keyId,
        algorithm: 'ES256',
        status: 'ACTIVE',
      },
    });

    return signingKey;
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
  ): boolean {
    const payload = hashPayload(token, destinationUrl, geoHash, expiresAt);
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
        },
      });
    });

    return newKey;
  }
}
