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
  /** The full secret key shown once to the user, e.g. "qrauth_<32 hex chars>" */
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
 *
 * @internal — NOT for production use. Exposed only via test-utils.
 * @see SigningService.signCanonical() for the domain-separated production path.
 */
function signPayload(privateKey: string, payload: string): string {
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
  } catch (err) {
    // Log verification failures for monitoring (not an error — just info)
    if (process.env.NODE_ENV === 'development') {
      console.debug('[crypto] Signature verification failed:', (err as Error).message);
    }
    return false;
  }
}

/**
 * Generate a new API key.
 *
 * Format: `qrauth_<64 hex chars>`  (32 random bytes → 64 hex characters)
 *
 * - fullKey  – the complete secret, shown to the user exactly once
 * - prefix   – first 8 hex chars of the random part, stored in plain text
 *              so support staff can identify a key without exposing the secret
 * - hash     – SHA-256 hex digest of fullKey, stored in the database for
 *              constant-time comparison on every inbound request
 */
export function generateApiKey(): ApiKeyResult {
  const randomPart = randomBytes(32).toString('hex'); // 64 hex chars
  const fullKey = `qrauth_${randomPart}`;
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

/**
 * Deterministic JSON serialization with sorted keys at all nesting levels.
 * Required because PostgreSQL JSONB reorders object keys alphabetically,
 * so the hash of the content must be order-independent.
 *
 * Audit-3 M-1: explicit handling for Date, BigInt, NaN, Infinity, and
 * undefined-in-arrays. These edge cases never appear in production payloads
 * today, but this function is the single canonicalization primitive for all
 * signed content — defensive handling prevents silent hash divergence if
 * a future caller passes unsanitized data.
 */
export function stableStringify(value: unknown): string {
  if (value === null || value === undefined) return 'null';

  if (typeof value === 'bigint') {
    return `"${value.toString()}"`;
  }

  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      throw new Error(
        `stableStringify: non-finite number (${value}) cannot be deterministically serialized`,
      );
    }
    return JSON.stringify(value);
  }

  if (typeof value !== 'object') return JSON.stringify(value);

  if (value instanceof Date) {
    if (!Number.isFinite(value.getTime())) {
      throw new Error('stableStringify: invalid Date cannot be deterministically serialized');
    }
    return `"${value.toISOString()}"`;
  }

  if (Array.isArray(value)) {
    return '[' + value.map((item) => stableStringify(item === undefined ? null : item)).join(',') + ']';
  }

  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  const pairs = keys
    .filter((k) => obj[k] !== undefined)
    .map((k) => JSON.stringify(k) + ':' + stableStringify(obj[k]));
  return '{' + pairs.join(',') + '}';
}

// ---------------------------------------------------------------------------
// Test-only exports (Audit-4 A4-L1)
// These are intentionally NOT part of the public module surface. Import from
// this path only in tests, benchmarks, and seed scripts.
// ---------------------------------------------------------------------------
export { signPayload as __test_signPayload };
