/**
 * Fixed SLH-DSA-SHA2-128s self-test vector (used by ./slh-dsa.ts).
 *
 * NOT A SECRET. The key pair is derived by @noble/post-quantum 0.6.1
 * `slh_dsa_sha2_128s.keygen()` from the public seed 0x00, 0x01, … 0x2f and
 * signs nothing but SELF_TEST_MESSAGE, which is outside every production
 * domain (see ./domain-separation.ts). SELF_TEST_NOBLE_SIGNATURE is a
 * signature over SELF_TEST_MESSAGE made by that library, so the startup
 * self-test can check that the built-in implementation accepts library
 * signatures without signing with the slow library at every boot.
 */

export const SELF_TEST_MESSAGE = Buffer.from('qrauth:signer:slh-dsa-self-test:v1', 'utf8');

/** 64 bytes: SK.seed || SK.prf || PK.seed || PK.root (FIPS 205 §9.1). */
export const SELF_TEST_SECRET_KEY = Buffer.from(
  '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f990ce6298792b128846a8e4a3a68954c',
  'hex',
);

/** 32 bytes: PK.seed || PK.root; equals SELF_TEST_SECRET_KEY.subarray(32). */
export const SELF_TEST_PUBLIC_KEY = Buffer.from('202122232425262728292a2b2c2d2e2f990ce6298792b128846a8e4a3a68954c', 'hex');

export const SELF_TEST_NOBLE_SIGNATURE = Buffer.from(
  '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' +
  '2RAFeJj/i6c=',
  'base64',
);
