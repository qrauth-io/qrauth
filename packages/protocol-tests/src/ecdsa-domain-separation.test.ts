import "./test-setup.js";
import { describe, it, expect, beforeAll } from "vitest";
import { createSign, createVerify } from "node:crypto";

import { generateKeyPair, verifySignature } from "../../api/src/lib/crypto.js";
import { SigningService } from "../../api/src/services/signing.js";

/**
 * AUDIT-2 N-2: ECDSA canonical signing path carries a fixed
 * domain-separation prefix so a compromised signer-service bearer token
 * can only mint signatures for one logical use, not arbitrary forged
 * auth-session / proximity / QR-core payloads.
 *
 * The acceptance criteria in `docs/security/audit2-remediation-plan.md`
 * call for two unit tests:
 *
 *   1. A signature produced over the prefixed bytes verifies under the
 *      new `SigningService.verifyCanonical`, and the equivalent signature
 *      over the unprefixed bytes (what an attacker with a stolen
 *      bearer token would have minted pre-fix) does NOT verify under the
 *      new path.
 *   2. A signature produced over the raw canonical bytes (pre-N-2 code
 *      path) does not verify under the new path — the positive proof
 *      that the prefix is actually inside the signed bytes.
 *
 * These tests touch the verifier only; the signer is stubbed in-process
 * via Node's built-in `createSign` so the tests don't need to stand up
 * the encrypted-envelope on-disk format the LocalEcdsaSigner expects.
 */

const ECDSA_CANONICAL_DOMAIN_PREFIX = "qrauth:ecdsa-canonical:v1:";
const CANONICAL = "hybrid-ecdsa-slhdsa-v1|test-token|tnt_test|dest|none|";

let publicKey: string;
let privateKey: string;
let svc: SigningService;

function rawEcdsaSign(pem: string, message: string): string {
  const signer = createSign("SHA256");
  signer.update(message, "utf8");
  signer.end();
  return signer.sign(pem, "base64");
}

beforeAll(async () => {
  const pair = await generateKeyPair();
  publicKey = pair.publicKey;
  privateKey = pair.privateKey;
  // SigningService's verifyCanonical is pure-function w.r.t. the
  // arguments the test supplies — the constructor's PrismaClient
  // dependency is only hit on disk/database code paths we don't
  // exercise here.
  svc = new SigningService({} as never);
});

describe("ECDSA canonical domain separation (AUDIT-2 N-2)", () => {
  it("verifies a signature produced over the prefixed bytes", () => {
    const sig = rawEcdsaSign(privateKey, ECDSA_CANONICAL_DOMAIN_PREFIX + CANONICAL);
    expect(svc.verifyCanonical(publicKey, sig, CANONICAL)).toBe(true);
  });

  it("rejects a signature produced over the raw unprefixed canonical", () => {
    // This is the pre-fix shape: a legitimate signer that forgot to
    // apply the prefix, or a compromised bearer token signing an
    // arbitrary canonical directly. Post-N-2 the verifier requires the
    // prefix inside the signed bytes.
    const sig = rawEcdsaSign(privateKey, CANONICAL);
    expect(svc.verifyCanonical(publicKey, sig, CANONICAL)).toBe(false);
  });

  it("rejects a prefixed signature when the verifier omits the prefix", () => {
    // Mirror image of the above: a signature produced over the prefixed
    // bytes should fail under a verifier that feeds only the raw
    // canonical. This is the guarantee that `verifySignature` is
    // actually sensitive to the prefix bytes, not silently accepting.
    const sig = rawEcdsaSign(privateKey, ECDSA_CANONICAL_DOMAIN_PREFIX + CANONICAL);
    expect(verifySignature(publicKey, sig, CANONICAL)).toBe(false);
  });

  it("fails when the verify path reconstructs a different prefix", () => {
    // A drift in the domain literal on one side invalidates every
    // signature — this is the whole point of the protocol-version lock
    // in ALGORITHM.md §12. The test pins the literal so a stealth
    // change to either side breaks the suite.
    const sig = rawEcdsaSign(privateKey, "qrauth:ecdsa-canonical:v2:" + CANONICAL);
    expect(svc.verifyCanonical(publicKey, sig, CANONICAL)).toBe(false);
  });

  it("createVerify with the right prefix accepts the signature end-to-end", () => {
    // Sanity: the canonical bytes + prefix + ES256 compose the way the
    // signer-service `/v1/sign-ecdsa` handler and the LocalEcdsaSigner
    // both compose them.
    const sig = rawEcdsaSign(privateKey, ECDSA_CANONICAL_DOMAIN_PREFIX + CANONICAL);
    const verifier = createVerify("SHA256");
    verifier.update(ECDSA_CANONICAL_DOMAIN_PREFIX + CANONICAL, "utf8");
    verifier.end();
    expect(verifier.verify(publicKey, sig, "base64")).toBe(true);
  });
});
