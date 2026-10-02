/**
 * In-process RSA signer (ADR-0003 Slice 7a dev/test fallback).
 *
 * Reads the encrypted RSA envelope from disk, decrypts via
 * `lib/key-at-rest.ts`, and signs with Node's RSA-SHA256 (RS256). Does not
 * talk to the signer service. Inherits the same blast radius as the API box.
 *
 * Production deployments MUST set `RSA_SIGNER=http` (Slice 7b) and run the
 * standalone signer. This backend exists so `npm run dev`, the protocol
 * tests, and the smoke harness work without a second process. Mirrors
 * `LocalEcdsaSigner.signJws`; only the algorithm (RSA-SHA256) and the on-disk
 * envelope extension (`.rsa.enc`) differ.
 */
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { createSign } from 'node:crypto';
import type { RsaSigner } from './index.js';
import { JWS_CANONICAL_INPUT_RE } from '../ecdsa-signer/jws-input.js';
import { config } from '../../lib/config.js';
import { decryptAtRest } from '../../lib/key-at-rest.js';

export class LocalRsaSigner implements RsaSigner {
  /**
   * Sign a JWS canonical input prefix-free with RSA-SHA256 (RS256), returning
   * the base64url signature. The JWS-shape guard mirrors the signer service's
   * server-side validation so the local (dev) backend cannot be used to sign
   * arbitrary bytes through this path either.
   */
  async signJws(keyId: string, canonicalInput: string): Promise<string> {
    if (!JWS_CANONICAL_INPUT_RE.test(canonicalInput)) {
      throw new Error('LocalRsaSigner: canonicalInput must match base64url.base64url');
    }
    const pem = await this.loadPem(keyId);
    const signer = createSign('RSA-SHA256');
    signer.update(canonicalInput, 'utf8');
    signer.end();
    return signer.sign(pem).toString('base64url');
  }

  private async loadPem(keyId: string): Promise<string> {
    // Only the encrypted envelope is read (Finding-016 posture). RSA envelopes
    // live alongside ECDSA ones under the same key path, distinguished by the
    // `.rsa.enc` extension.
    const encPath = join(config.kms.ecdsaPrivateKeyPath, `${keyId}.rsa.enc`);
    let envelope: string;
    try {
      envelope = await readFile(encPath, 'utf8');
    } catch (err) {
      throw new Error(
        `LocalRsaSigner: key "${keyId}" not found on disk: ${(err as Error).message}`,
      );
    }
    const decrypted = decryptAtRest(envelope.trim()).toString('utf8');
    if (!decrypted.includes('-----BEGIN')) {
      throw new Error(`LocalRsaSigner: key "${keyId}" decrypted to non-PEM content`);
    }
    return decrypted;
  }
}
