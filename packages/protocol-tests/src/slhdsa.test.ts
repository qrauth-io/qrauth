import { describe, it, expect } from "vitest";
import {
  SLHDSA_LENGTHS,
  SLHDSA_PARAM_SET,
  slhDsaGenerateKeyPair,
  slhDsaKeyPairFromSeed,
  slhDsaSign,
  slhDsaVerify,
} from "../../api/src/services/slhdsa-adapter.js";

describe("SLH-DSA adapter", () => {
  it("uses the SHA2-128s parameter set with the documented sizes", () => {
    expect(SLHDSA_PARAM_SET).toBe("slh-dsa-sha2-128s");
    expect(SLHDSA_LENGTHS).toEqual({
      publicKey: 32,
      secretKey: 64,
      signature: 7856,
      seed: 48,
    });
  });

  it("generates keypairs of the documented length", async () => {
    const kp = await slhDsaGenerateKeyPair();
    expect(kp.publicKey.length).toBe(SLHDSA_LENGTHS.publicKey);
    expect(kp.privateKey.length).toBe(SLHDSA_LENGTHS.secretKey);
  });

  it("produces deterministic keypairs from a fixed seed", () => {
    const seed = Buffer.alloc(48, 1);
    const a = slhDsaKeyPairFromSeed(seed);
    const b = slhDsaKeyPairFromSeed(seed);
    expect(a.publicKey.equals(b.publicKey)).toBe(true);
    expect(a.privateKey.equals(b.privateKey)).toBe(true);
  });

  it("rejects malformed seeds", () => {
    expect(() => slhDsaKeyPairFromSeed(Buffer.alloc(32))).toThrow();
    expect(() => slhDsaKeyPairFromSeed(Buffer.alloc(64))).toThrow();
  });

  it("signs a message and verifies the signature", async () => {
    const kp = slhDsaKeyPairFromSeed(Buffer.alloc(48, 2));
    const msg = Buffer.from("qrauth:test:slhdsa:v1");
    const sig = await slhDsaSign(kp.privateKey, msg);
    expect(sig.length).toBe(SLHDSA_LENGTHS.signature);
    expect(await slhDsaVerify(kp.publicKey, msg, sig)).toBe(true);
  });

  it("rejects a signature with the wrong message", async () => {
    const kp = slhDsaKeyPairFromSeed(Buffer.alloc(48, 3));
    const sig = await slhDsaSign(kp.privateKey, Buffer.from("real"));
    expect(await slhDsaVerify(kp.publicKey, Buffer.from("forged"), sig)).toBe(false);
  });

  it("rejects a signature under the wrong public key", async () => {
    const a = slhDsaKeyPairFromSeed(Buffer.alloc(48, 4));
    const b = slhDsaKeyPairFromSeed(Buffer.alloc(48, 5));
    const sig = await slhDsaSign(a.privateKey, Buffer.from("msg"));
    expect(await slhDsaVerify(b.publicKey, Buffer.from("msg"), sig)).toBe(false);
  });

  it("rejects malformed public key / signature inputs", async () => {
    const kp = slhDsaKeyPairFromSeed(Buffer.alloc(48, 6));
    const sig = await slhDsaSign(kp.privateKey, Buffer.from("msg"));
    expect(await slhDsaVerify(Buffer.alloc(10), Buffer.from("msg"), sig)).toBe(false);
    expect(await slhDsaVerify(kp.publicKey, Buffer.from("msg"), Buffer.alloc(10))).toBe(false);
  });

  it("rejects signing with malformed private key", async () => {
    await expect(slhDsaSign(Buffer.alloc(10), Buffer.from("msg"))).rejects.toThrow();
  });
});
