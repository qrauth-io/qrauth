/**
 * Guard for operator scripts that decrypt key envelopes on this host.
 *
 * They need a host that generates or signs locally (config.keygen.needsMasterKey),
 * SIGNER_MASTER_KEY, and envelope files in the configured keys directory. Returns a
 * reason string when the host does not qualify, or null when it does.
 */
import { readdirSync } from 'node:fs';
import { config } from '../src/lib/config.js';

export function localKeyMaterialProblem(): string | null {
  if (!config.keygen.needsMasterKey) return 'this host uses signer-side key generation and remote signers';
  if (!process.env.SIGNER_MASTER_KEY) return 'SIGNER_MASTER_KEY is not set';
  let names: string[];
  try {
    names = readdirSync(config.kms.ecdsaPrivateKeyPath);
  } catch {
    return `keys directory ${config.kms.ecdsaPrivateKeyPath} is not readable`;
  }
  if (!names.some((n) => n.endsWith('.enc'))) {
    return `keys directory ${config.kms.ecdsaPrivateKeyPath} holds no envelope files`;
  }
  return null;
}

/** Print a refusal and set exit code 2 when the host does not qualify. Returns true to proceed. */
export function requireLocalKeyMaterial(script: string): boolean {
  const problem = localKeyMaterialProblem();
  if (problem === null) return true;
  console.error(`[${script}] refusing to run: this script decrypts key envelopes locally (${problem}).`);
  process.exitCode = 2;
  return false;
}
