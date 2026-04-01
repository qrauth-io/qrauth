import {
  createHash,
  createSign,
  createVerify,
  generateKeyPairSync,
  randomBytes,
  randomUUID,
} from 'node:crypto';

const CURVE = 'prime256v1'; // P-256 / secp256r1
const SIGN_ALGO = 'SHA256';

export interface KeyPair {
  publicKey: string;
  privateKey: string;
  keyId: string;
}

export interface ApiKeyResult {
  /** The full secret key shown once to the user, e.g. "vqr_<32 hex chars>" */
  fullKey: string;
  /** First 8 characters of the random part – safe to store in plain text for lookup */
  prefix: string;
  /** SHA-256 hex digest of fullKey – stored in the database */
  hash: string;
}

/**
 * Generate a fresh ECDSA P-256 key pair.
 * Both keys are returned in PEM format.
 * The keyId is a random UUID v4 that serves as a stable public identifier
 * for this key pair within the system.
 */
export async function generateKeyPair(): Promise<KeyPair> {
  const { privateKey, publicKey } = generateKeyPairSync('ec', {
    namedCurve: CURVE,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem',
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem',
    },
  });

  return {
    publicKey,
    privateKey,
    keyId: randomUUID(),
  };
}

/**
 * Sign an arbitrary string payload with an ECDSA P-256 private key (PEM).
 * Returns the DER-encoded signature as a base64 string.
 */
export function signPayload(privateKey: string, payload: string): string {
  const signer = createSign(SIGN_ALGO);
  signer.update(payload, 'utf8');
  signer.end();

  return signer.sign(privateKey, 'base64');
}

/**
 * Verify a base64-encoded ECDSA signature against a payload using the
 * supplied PEM public key.
 * Returns true when the signature is valid, false otherwise (never throws).
 */
export function verifySignature(
  publicKey: string,
  signature: string,
  payload: string,
): boolean {
  try {
    const verifier = createVerify(SIGN_ALGO);
    verifier.update(payload, 'utf8');
    verifier.end();

    return verifier.verify(publicKey, signature, 'base64');
  } catch {
    return false;
  }
}

/**
 * Generate a new API key.
 *
 * Format: `vqr_<64 hex chars>`  (32 random bytes → 64 hex characters)
 *
 * - fullKey  – the complete secret, shown to the user exactly once
 * - prefix   – first 8 hex chars of the random part, stored in plain text
 *              so support staff can identify a key without exposing the secret
 * - hash     – SHA-256 hex digest of fullKey, stored in the database for
 *              constant-time comparison on every inbound request
 */
export function generateApiKey(): ApiKeyResult {
  const randomPart = randomBytes(32).toString('hex'); // 64 hex chars
  const fullKey = `vqr_${randomPart}`;
  const prefix = randomPart.slice(0, 8);
  const hash = hashString(fullKey);

  return { fullKey, prefix, hash };
}

/**
 * Compute the SHA-256 hex digest of any string.
 * Used for hashing API keys, tokens, and transparency-log entries.
 */
export function hashString(input: string): string {
  return createHash('sha256').update(input, 'utf8').digest('hex');
}
