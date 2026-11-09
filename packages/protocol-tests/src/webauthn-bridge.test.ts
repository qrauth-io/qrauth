import "./test-setup.js";
import { describe, it, expect } from "vitest";
import { randomBytes } from "node:crypto";
import {
  mlDsaKeyPairFromSeed,
  mlDsaSign,
  mlDsaVerify,
  MLDSA_LENGTHS,
  type MlDsaKeyPair,
} from "../../api/src/services/ml-dsa-adapter.js";
import { WEBAUTHN_BRIDGE_TAG } from "../../api/src/services/webauthn.js";

/**
 * AUDIT-1 Finding-003 moved ML-DSA keygen into the browser. The bridge
 * test still needs fresh random keypairs to round-trip sign/verify, so
 * it mints a 32-byte seed locally and calls the adapter's
 * `mlDsaKeyPairFromSeed` helper — the same shape the browser uses.
 */
function freshKeyPair(): MlDsaKeyPair {
  return mlDsaKeyPairFromSeed(randomBytes(MLDSA_LENGTHS.seed));
}

/**
 * Simulates the client-side bridge sign + server-side verify round trip.
 *
 * In production the private key lives in browser IndexedDB; here we hold
 * it in a Buffer for the duration of the test. The wire format and the
 * domain-separation tag are the parts under test — if either drifts
 * between client and server, the bridge silently breaks.
 */
async function clientSign(privateKey: Buffer, challengeBase64Url: string): Promise<string> {
  const message = Buffer.concat([
    Buffer.from(WEBAUTHN_BRIDGE_TAG),
    Buffer.from(challengeBase64Url, "base64url"),
  ]);
  const sig = await mlDsaSign(privateKey, message);
  return sig.toString("base64");
}

async function serverVerify(
  publicKey: Buffer,
  challengeBase64Url: string,
  signatureBase64: string,
): Promise<boolean> {
  const message = Buffer.concat([
    Buffer.from(WEBAUTHN_BRIDGE_TAG),
    Buffer.from(challengeBase64Url, "base64url"),
  ]);
  return mlDsaVerify(publicKey, message, Buffer.from(signatureBase64, "base64"));
}

describe("WebAuthn bridge round trip", () => {
  it("uses the v1 domain tag", () => {
    expect(WEBAUTHN_BRIDGE_TAG).toBe("qrauth:webauthn:bridge:v1");
  });

  it("client-signed challenge verifies server-side", async () => {
    const kp = freshKeyPair();
    const challenge = Buffer.from("challenge-bytes-12345").toString("base64url");
    const sig = await clientSign(kp.privateKey, challenge);
    expect(await serverVerify(kp.publicKey, challenge, sig)).toBe(true);
  });

  it("rejects a signature for a different challenge", async () => {
    const kp = freshKeyPair();
    const sig = await clientSign(kp.privateKey, Buffer.from("real").toString("base64url"));
    const wrongChallenge = Buffer.from("forged").toString("base64url");
    expect(await serverVerify(kp.publicKey, wrongChallenge, sig)).toBe(false);
  });

  it("rejects a signature from a different key", async () => {
    const a = freshKeyPair();
    const b = freshKeyPair();
    const challenge = Buffer.from("c").toString("base64url");
    const sig = await clientSign(a.privateKey, challenge);
    expect(await serverVerify(b.publicKey, challenge, sig)).toBe(false);
  });

  it("rejects a signature created without the domain tag", async () => {
    // An attacker who repurposed the bridge key for a non-tagged payload
    // must not be able to pass the verifier — the domain tag isolates
    // this key from any other ML-DSA-signed payload in the codebase.
    const kp = freshKeyPair();
    const challenge = Buffer.from("c").toString("base64url");
    const untagged = await mlDsaSign(kp.privateKey, Buffer.from(challenge, "base64url"));
    expect(await serverVerify(kp.publicKey, challenge, untagged.toString("base64"))).toBe(false);
  });

  it("rejects a malformed base64 signature without throwing", async () => {
    const kp = freshKeyPair();
    const challenge = Buffer.from("c").toString("base64url");
    expect(await serverVerify(kp.publicKey, challenge, "not-base64-bytes")).toBe(false);
  });
});
