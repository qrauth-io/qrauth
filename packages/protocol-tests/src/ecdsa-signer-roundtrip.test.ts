import "./test-setup.js";
import { describe, it, expect, beforeAll } from "vitest";
import { createSign, createVerify } from "node:crypto";

import { SIGNER_ECDSA_CANONICAL_PREFIX } from "../../signer-service/src/domain-separation.js";
import { generateKeyPair, verifySignature } from "../../api/src/lib/crypto.js";
import { SigningService } from "../../api/src/services/signing.js";

/**
 * AUDIT-2 N-7 (second amendment): signer-service ↔ API ECDSA round-trip.
 *
 * The N-2 ECDSA canonical domain-separation prefix is pinned on two
 * sides of the wire. The signer-service prepends
 * `qrauth:ecdsa-canonical:v1:` before every `/v1/sign-ecdsa` call, and
 * the API server's `SigningService.verifyCanonical` reconstructs the
 * same prefix before handing the bytes to `verifySignature`. If either
 * literal drifts by so much as a byte, N-2's threat-model invariant
 * (a compromised signer bearer token cannot mint signatures the API
 * will accept outside the ECDSA-canonical logical domain) silently
 * breaks — previously-issued signatures still validate but new ones
 * from the drifted side no longer do.
 *
 * This test imports the signer-service's module-exported prefix
 * constant directly (byte-equality anchor on the signer side) and
 * signs with Node's built-in `createSign("SHA256")` — the exact call
 * shape `packages/signer-service/src/server.ts::/v1/sign-ecdsa` uses
 * once it has the private PEM in memory. It then feeds the resulting
 * base64 signature through `SigningService.verifyCanonical` which
 * reconstructs the API-side prefix on the verify side. A positive
 * round-trip PLUS three negative controls (wrong prefix literal on
 * the sign side, no prefix at all, wrong canonical body) make any
 * drift on either side of the wire a CI failure.
 *
 * Matches the plan's option (b): import the signer-service's exported
 * prefix constant and round-trip through `createSign`/`createVerify`.
 * Avoids spinning up the Fastify signer app (which would require a
 * real on-disk encrypted envelope to exercise `/v1/sign-ecdsa` and
 * starts an HTTP server on import).
 */

const CANONICAL =
  "hybrid-ecdsa-slhdsa-v1|tok_roundtrip|tnt_roundtrip|dest|none|";

let publicKey: string;
let privateKey: string;
let svc: SigningService;

function signerServiceSide(pem: string, canonical: string): string {
  // Byte-identical to packages/signer-service/src/server.ts::/v1/sign-ecdsa:
  //   const prefixed = SIGNER_ECDSA_CANONICAL_PREFIX + message;
  //   const signer = createSign('SHA256');
  //   signer.update(prefixed, 'utf8');
  //   signer.end();
  //   return signer.sign(pem, 'base64');
  const signer = createSign("SHA256");
  signer.update(SIGNER_ECDSA_CANONICAL_PREFIX + canonical, "utf8");
  signer.end();
  return signer.sign(pem, "base64");
}

beforeAll(async () => {
  const pair = await generateKeyPair();
  publicKey = pair.publicKey;
  privateKey = pair.privateKey;
  // `verifyCanonical` is a pure function over the arguments this test
  // supplies; the constructor's PrismaClient dependency is only hit on
  // code paths we never exercise.
  svc = new SigningService({} as never);
});

describe("ECDSA signer-service ↔ API round-trip (AUDIT-2 N-7)", () => {
  it("pins the signer-service prefix literal byte-for-byte", () => {
    // Any drift in the signer-service constant is a protocol-version
    // bump per ALGORITHM.md §12. Test it here so the drift shows up as
    // a named assertion in the suite, not a mysterious round-trip fail.
    expect(SIGNER_ECDSA_CANONICAL_PREFIX).toBe("qrauth:ecdsa-canonical:v1:");
  });

  it("a signature produced on the signer side verifies on the API side", () => {
    const sig = signerServiceSide(privateKey, CANONICAL);
    expect(svc.verifyCanonical(publicKey, sig, CANONICAL)).toBe(true);
  });

  it("rejects a signature produced with the wrong prefix literal (v2 drift)", () => {
    // Mirrors ecdsa-domain-separation.test.ts's v2 drift case but
    // anchored against the byte-exact signer-service prefix, so a
    // stealth bump to v2 on either side breaks CI.
    const signer = createSign("SHA256");
    signer.update("qrauth:ecdsa-canonical:v2:" + CANONICAL, "utf8");
    signer.end();
    const sig = signer.sign(privateKey, "base64");
    expect(svc.verifyCanonical(publicKey, sig, CANONICAL)).toBe(false);
  });

  it("rejects a signature produced over the raw unprefixed canonical", () => {
    // Pre-N-2 shape — a legitimate signer that forgot the prefix or a
    // compromised bearer token signing a raw canonical. The verifier
    // must reject this path because the prefix is part of the signed
    // bytes.
    const signer = createSign("SHA256");
    signer.update(CANONICAL, "utf8");
    signer.end();
    const sig = signer.sign(privateKey, "base64");
    expect(svc.verifyCanonical(publicKey, sig, CANONICAL)).toBe(false);
  });

  it("rejects a signer-side signature when the canonical body is mutated", () => {
    // Sanity: if the verifier happens to accept the prefix but drops
    // the canonical body, this test fails loudly. Without this case a
    // verifier that only checked the prefix would silently pass.
    const sig = signerServiceSide(privateKey, CANONICAL);
    expect(svc.verifyCanonical(publicKey, sig, CANONICAL + "X")).toBe(false);
  });

  it("direct createVerify with the signer prefix confirms the wire format", () => {
    // Independent cross-check: reconstruct the exact bytes the signer
    // service signs and run them through Node's `createVerify` without
    // going through the SigningService abstraction. If this fails but
    // `verifyCanonical` still passes, the abstraction is covering a
    // regression instead of exposing it.
    const sig = signerServiceSide(privateKey, CANONICAL);
    const verifier = createVerify("SHA256");
    verifier.update(SIGNER_ECDSA_CANONICAL_PREFIX + CANONICAL, "utf8");
    verifier.end();
    expect(verifier.verify(publicKey, sig, "base64")).toBe(true);

    // And the same bytes under `lib/crypto.verifySignature` (the
    // lower-level primitive SigningService.verifyCanonical delegates
    // to) must also validate.
    expect(
      verifySignature(
        publicKey,
        sig,
        SIGNER_ECDSA_CANONICAL_PREFIX + CANONICAL,
      ),
    ).toBe(true);
  });
});
