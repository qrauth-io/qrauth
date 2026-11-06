import type { SlhDsaSigner } from './index.js';
import type { SigningService } from '../signing.js';
import { slhDsaSign } from '../slhdsa-adapter.js';

/**
 * AUDIT-FINDING-010: domain-separation prefix the local signer prepends
 * before handing bytes to SLH-DSA. Byte-identical to the prefix the
 * remote signer service applies, so dev and prod produce the same
 * signatures for the same inputs. Any verifier reconstructs the same
 * prefixed input.
 */
const SIGNER_MERKLE_ROOT_PREFIX = Buffer.from('qrauth:merkle-root:v1:', 'utf8');

/**
 * In-process SLH-DSA signer.
 *
 * Loads the private key bytes off the API server's local disk via the
 * existing `SigningService.loadSlhDsaKeyPair` helper. This is the dev
 * fallback — it is NOT air-gapped. Production deployments should set
 * `SLH_DSA_SIGNER=http` and run the standalone signer service on a
 * separate host instead.
 *
 * The reason it stays in the codebase: the protocol test suite, the
 * smoke harness, and any developer running `npm run dev` all need a
 * signer that works without standing up an extra process. LocalSigner
 * gives them one. The downside is purely operational: anyone deploying
 * with the local backend should know it inherits the same blast radius
 * as the API server itself.
 */
export class LocalSlhDsaSigner implements SlhDsaSigner {
  constructor(private signingService: SigningService) {}

  async signRoot(keyId: string, message: Buffer): Promise<Buffer> {
    const pair = await this.signingService.loadSlhDsaKeyPair(keyId);
    if (!pair) {
      throw new Error(
        `LocalSlhDsaSigner: signing key "${keyId}" has no SLH-DSA material on disk`,
      );
    }
    const prefixed = Buffer.concat([SIGNER_MERKLE_ROOT_PREFIX, message]);
    return slhDsaSign(pair.privateKey, prefixed);
  }

  async getPublicKey(keyId: string): Promise<Buffer> {
    const pair = await this.signingService.loadSlhDsaKeyPair(keyId);
    if (!pair) {
      throw new Error(
        `LocalSlhDsaSigner: signing key "${keyId}" has no SLH-DSA material on disk`,
      );
    }
    return pair.publicKey;
  }
}
