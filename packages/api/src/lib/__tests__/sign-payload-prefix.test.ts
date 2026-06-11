import { describe, it, expect, beforeAll } from 'vitest';
import { generateKeyPairSync, createSign } from 'node:crypto';
import {
  ECDSA_CANONICAL_DOMAIN_PREFIX,
  __test_signPayload,
  __test_signPayload_raw,
  verifySignature,
} from '../crypto.js';

// Issue #62 (62b). Pin the test-only signing helpers to the production
// canonical-prefix convention. The seed scripts that consume
// __test_signPayload must produce QR rows the prod verifier accepts —
// which means signatures over PREFIX+canonical, exactly like
// SigningService.signCanonical.
//
// The bench helper __test_signPayload_raw deliberately omits the prefix
// for a small set of legitimate use cases (raw-ECDSA micro-benchmarks,
// cross-version compat vectors). Tests here pin both helpers so a
// future refactor that drops the prefix from the default helper or
// adds it to the raw helper fails CI loudly.

let publicKey: string;
let privateKey: string;

beforeAll(() => {
  const kp = generateKeyPairSync('ec', {
    namedCurve: 'prime256v1',
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  publicKey = kp.publicKey;
  privateKey = kp.privateKey;
});

describe('__test_signPayload (prefixed, default helper)', () => {
  it('produces a signature that verifies against PREFIX + payload', () => {
    const payload = 'hybrid-ecdsa-slhdsa-v1|tok|tnt|dest|none|';
    const sig = __test_signPayload(privateKey, payload);
    expect(verifySignature(publicKey, sig, ECDSA_CANONICAL_DOMAIN_PREFIX + payload)).toBe(true);
  });

  it('does NOT verify against the un-prefixed payload (proves the prefix was applied)', () => {
    const payload = 'hybrid-ecdsa-slhdsa-v1|tok|tnt|dest|none|';
    const sig = __test_signPayload(privateKey, payload);
    expect(verifySignature(publicKey, sig, payload)).toBe(false);
  });

  it('matches what the production signer (LocalEcdsaSigner inline) would produce', () => {
    // Reconstruct the production signing path inline (createSign + prefix)
    // and confirm a verifier accepts both helper-signed and inline-signed
    // bytes against the same canonical input. Different signature bytes
    // (ECDSA is non-deterministic) but the same verify outcome.
    const payload = 'roundtrip-canonical-input|abc|def';

    const helperSig = __test_signPayload(privateKey, payload);

    const prodLike = createSign('SHA256');
    prodLike.update(ECDSA_CANONICAL_DOMAIN_PREFIX + payload, 'utf8');
    prodLike.end();
    const prodSig = prodLike.sign(privateKey, 'base64');

    // Both verify against the same prefixed-canonical the prod verifier
    // would reconstruct. That is the contract the helper must match.
    expect(verifySignature(publicKey, helperSig, ECDSA_CANONICAL_DOMAIN_PREFIX + payload)).toBe(true);
    expect(verifySignature(publicKey, prodSig, ECDSA_CANONICAL_DOMAIN_PREFIX + payload)).toBe(true);
  });
});

describe('__test_signPayload_raw (no prefix, escape hatch)', () => {
  it('produces a signature that verifies against the un-prefixed payload', () => {
    const payload = 'raw-input-no-prefix';
    const sig = __test_signPayload_raw(privateKey, payload);
    expect(verifySignature(publicKey, sig, payload)).toBe(true);
  });

  it('does NOT verify against PREFIX + payload (proves no prefix was applied)', () => {
    const payload = 'raw-input-no-prefix';
    const sig = __test_signPayload_raw(privateKey, payload);
    expect(verifySignature(publicKey, sig, ECDSA_CANONICAL_DOMAIN_PREFIX + payload)).toBe(false);
  });
});
