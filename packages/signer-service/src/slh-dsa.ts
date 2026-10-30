import {
  createPrivateKey,
  createPublicKey,
  sign as cryptoSign,
  verify as cryptoVerify,
  type KeyObject,
} from 'node:crypto';
import { slh_dsa_sha2_128s } from '@noble/post-quantum/slh-dsa.js';
import {
  SELF_TEST_MESSAGE,
  SELF_TEST_NOBLE_SIGNATURE,
  SELF_TEST_PUBLIC_KEY,
  SELF_TEST_SECRET_KEY,
} from './slh-dsa-self-test-vector.js';

/**
 * SLH-DSA-SHA2-128s signing: Node's built-in implementation (OpenSSL 3.5,
 * exposed by Node 24) when it is available and passes the startup
 * self-test; @noble/post-quantum (pure JavaScript) otherwise.
 *
 * Both produce FIPS 205 signatures (pure mode, empty context) that the
 * other verifies, so the choice changes speed only: no wire format, key
 * file or verifier changes. Key files keep the raw 64-byte secret key; the
 * built-in path wraps it in a PKCS#8 header in memory on each use.
 */

export type SlhDsaImplementationName = 'native' | 'noble';

export interface SlhDsaImplementation {
  readonly name: SlhDsaImplementationName;
  sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array;
  verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean;
}

export const SECRET_KEY_BYTES = 64;
export const PUBLIC_KEY_BYTES = 32;
export const SIGNATURE_BYTES = 7856;

// DER headers for id-slh-dsa-sha2-128s (OID 2.16.840.1.101.3.4.3.20) as
// emitted by Node 24 / OpenSSL 3.5: PKCS#8 wraps the raw 64-byte secret
// key in an OCTET STRING, SPKI the raw 32-byte public key in a BIT STRING.
const PKCS8_PREFIX = Buffer.from('3052020100300b06096086480165030403140440', 'hex');
const SPKI_PREFIX = Buffer.from('3030300b0609608648016503040314032100', 'hex');

function expectLength(bytes: Uint8Array, length: number, what: string): void {
  if (bytes.length !== length) {
    throw new Error(`SLH-DSA ${what} must be ${length} bytes, got ${bytes.length}`);
  }
}

/** Raw 64-byte secret key → node:crypto KeyObject. In memory only. */
export function nativePrivateKey(secretKey: Uint8Array): KeyObject {
  expectLength(secretKey, SECRET_KEY_BYTES, 'secret key');
  return createPrivateKey({
    key: Buffer.concat([PKCS8_PREFIX, secretKey]),
    format: 'der',
    type: 'pkcs8',
  });
}

/** Raw 32-byte public key → node:crypto KeyObject. */
export function nativePublicKey(publicKey: Uint8Array): KeyObject {
  expectLength(publicKey, PUBLIC_KEY_BYTES, 'public key');
  return createPublicKey({
    key: Buffer.concat([SPKI_PREFIX, publicKey]),
    format: 'der',
    type: 'spki',
  });
}

export const nobleImplementation: SlhDsaImplementation = {
  name: 'noble',
  sign: (message, secretKey) => slh_dsa_sha2_128s.sign(message, secretKey),
  verify: (signature, message, publicKey) => slh_dsa_sha2_128s.verify(signature, message, publicKey),
};

export const nativeImplementation: SlhDsaImplementation = {
  name: 'native',
  sign: (message, secretKey) => new Uint8Array(cryptoSign(null, message, nativePrivateKey(secretKey))),
  verify: (signature, message, publicKey) =>
    cryptoVerify(null, message, nativePublicKey(publicKey), signature),
};

export const NATIVE_KEY_TYPE = 'slh-dsa-sha2-128s';

/**
 * True when this Node build recognises SLH-DSA-SHA2-128s keys. Node 22
 * linked against OpenSSL 3.5 still parses the PKCS#8 bytes but returns an
 * untyped key that cannot sign, so the key type is the test, not the parse.
 * The startup self-test then checks that signing actually works.
 */
export function isNativeSlhDsaAvailable(): boolean {
  try {
    // @types/node 22 does not list the SLH-DSA key types yet.
    const keyType: string | undefined = nativePrivateKey(SELF_TEST_SECRET_KEY).asymmetricKeyType;
    return keyType === NATIVE_KEY_TYPE;
  } catch {
    return false;
  }
}

export interface SelfTestResult {
  ok: boolean;
  error?: string;
}

/**
 * Sign the fixed self-test message with `impl` and check the signature with
 * the reference (pure-JS) verifier; then check that `impl` accepts the
 * fixed reference signature. Uses only the public self-test key.
 */
export function runSelfTest(
  impl: SlhDsaImplementation,
  reference: SlhDsaImplementation = nobleImplementation,
): SelfTestResult {
  try {
    const signature = impl.sign(SELF_TEST_MESSAGE, SELF_TEST_SECRET_KEY);
    if (signature.length !== SIGNATURE_BYTES) {
      return { ok: false, error: `signature is ${signature.length} bytes, expected ${SIGNATURE_BYTES}` };
    }
    if (!reference.verify(signature, SELF_TEST_MESSAGE, SELF_TEST_PUBLIC_KEY)) {
      return { ok: false, error: `${reference.name} verifier rejected the ${impl.name} signature` };
    }
    if (!impl.verify(SELF_TEST_NOBLE_SIGNATURE, SELF_TEST_MESSAGE, SELF_TEST_PUBLIC_KEY)) {
      return { ok: false, error: `${impl.name} verifier rejected the reference signature` };
    }
    return { ok: true };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) };
  }
}

export interface SlhDsaSelection {
  implementation: SlhDsaImplementation;
  nativeAvailable: boolean;
  /** Set when the built-in implementation was available but not used. */
  fallbackReason?: string;
}

interface SelectionLogger {
  info(obj: object, msg: string): void;
  error(obj: object, msg: string): void;
}

export interface SelectOptions {
  logger: SelectionLogger;
  /** `noble` forces the pure-JS implementation; anything else is `auto`. */
  mode?: string;
  /** Test seams. `native: null` means "not available on this Node". */
  native?: SlhDsaImplementation | null;
  noble?: SlhDsaImplementation;
}

/**
 * Pick the signing implementation once, at startup, and log the choice.
 * Falls back to the pure-JS library when the built-in one is unavailable,
 * disabled or fails its self-test. Throws only if the fallback fails too.
 */
export function selectSlhDsaImplementation(opts: SelectOptions): SlhDsaSelection {
  const { logger } = opts;
  const noble = opts.noble ?? nobleImplementation;
  const native =
    opts.native !== undefined ? opts.native : isNativeSlhDsaAvailable() ? nativeImplementation : null;
  const nativeAvailable = native !== null;
  const node = process.versions.node;
  const openssl = process.versions.openssl;

  let fallbackReason: string | undefined;
  if (native && opts.mode === 'noble') {
    fallbackReason = 'disabled by SIGNER_SLH_DSA_IMPL=noble';
  } else if (native) {
    const result = runSelfTest(native, noble);
    if (result.ok) {
      logger.info({ implementation: native.name, node, openssl }, 'slh-dsa implementation selected');
      return { implementation: native, nativeAvailable };
    }
    fallbackReason = `self-test failed: ${result.error}`;
    logger.error(
      { implementation: native.name, error: result.error },
      'slh-dsa built-in self-test failed; falling back to pure-JS',
    );
  }

  const result = runSelfTest(noble, noble);
  if (!result.ok) {
    logger.error({ implementation: noble.name, error: result.error }, 'slh-dsa pure-JS self-test failed');
    throw new Error(`No working SLH-DSA implementation (pure-JS self-test: ${result.error})`);
  }
  logger.info(
    { implementation: noble.name, nativeAvailable, fallbackReason, node, openssl },
    'slh-dsa implementation selected',
  );
  return { implementation: noble, nativeAvailable, fallbackReason };
}

/** Time `count` signatures of the self-test message (public test key only). */
export function benchmarkSignatures(impl: SlhDsaImplementation, count: number): number[] {
  const timings: number[] = [];
  for (let i = 0; i < count; i += 1) {
    const start = process.hrtime.bigint();
    impl.sign(SELF_TEST_MESSAGE, SELF_TEST_SECRET_KEY);
    timings.push(Number(process.hrtime.bigint() - start) / 1e6);
  }
  return timings.map((ms) => Math.round(ms * 10) / 10);
}
