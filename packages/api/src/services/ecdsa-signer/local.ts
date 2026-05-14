/**
 * In-process ECDSA signer (AUDIT-FINDING-016 dev fallback).
 *
 * Reads the encrypted envelope from disk, decrypts via
 * `lib/key-at-rest.ts`, and signs with Node's built-in ECDSA. Does not
 * talk to the signer service. Inherits the same blast radius as the API
 * server box — a compromise of this process yields the decrypted PEM in
 * memory for the duration of the sign call.
 *
 * Production deployments MUST set `ECDSA_SIGNER=http` and run the
 * standalone signer on a private network. This backend exists so
 * `npm run dev`, the protocol tests, and the smoke harness all work
 * without standing up an extra process.
 */
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { createSign } from 'node:crypto';
import type { EcdsaSigner } from './index.js';
import { config } from '../../lib/config.js';
import { decryptAtRest } from '../../lib/key-at-rest.js';

/**
 * AUDIT-2 N-2: domain-separation prefix applied to every ECDSA canonical
 * signing operation. Byte-identical to the constant in
 * `packages/signer-service/src/server.ts` so local and remote backends
 * produce interchangeable signatures over the same canonical string.
 * Pinned in `ALGORITHM.md §12`; changing the literal is a protocol
 * version bump because verifiers reconstruct it byte-for-byte.
 */
const ECDSA_CANONICAL_DOMAIN_PREFIX = 'qrauth:ecdsa-canonical:v1:';

export class LocalEcdsaSigner implements EcdsaSigner {
  async signCanonical(keyId: string, canonical: string): Promise<string> {
    const pem = await this.loadPem(keyId);
    const signer = createSign('SHA256');
    signer.update(ECDSA_CANONICAL_DOMAIN_PREFIX + canonical, 'utf8');
    signer.end();
    return signer.sign(pem, 'base64');
  }

  private async loadPem(keyId: string): Promise<string> {
    // AUDIT-FINDING-016: only the encrypted envelope is read here. No
    // legacy plaintext fallback — pre-production re-seed at cutover is
    // the migration story. Keys minted before this PR must be
    // re-generated with the new on-disk format.
    const encPath = join(config.kms.ecdsaPrivateKeyPath, `${keyId}.ecdsa.enc`);
    let envelope: string;
    try {
      envelope = await readFile(encPath, 'utf8');
    } catch (err) {
      throw new Error(
        `LocalEcdsaSigner: key "${keyId}" not found on disk: ${(err as Error).message}`,
      );
    }
    const decrypted = decryptAtRest(envelope.trim()).toString('utf8');
    if (!decrypted.includes('-----BEGIN')) {
      throw new Error(`LocalEcdsaSigner: key "${keyId}" decrypted to non-PEM content`);
    }
    return decrypted;
  }
}
