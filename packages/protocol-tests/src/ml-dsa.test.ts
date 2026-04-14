import { describe, it, expect } from "vitest";
import {
  MLDSA_LENGTHS,
  MLDSA_PARAM_SET,
  mlDsaGenerateKeyPair,
  mlDsaKeyPairFromSeed,
  mlDsaSign,
  mlDsaVerify,
} from "../../api/src/services/ml-dsa-adapter.js";

describe("ML-DSA-44 adapter", () => {
  it("uses the FIPS 204 ml-dsa-44 parameter set with the documented sizes", () => {
    expect(MLDSA_PARAM_SET).toBe("ml-dsa-44");
    expect(MLDSA_LENGTHS).toEqual({
      publicKey: 1312,
      secretKey: 2560,
      signature: 2420,
      seed: 32,
    });
  });

  it("generates keypairs of the documented length", async () => {
    const kp = await mlDsaGenerateKeyPair();
    expect(kp.publicKey.length).toBe(MLDSA_LENGTHS.publicKey);
    expect(kp.privateKey.length).toBe(MLDSA_LENGTHS.secretKey);
  });

  it("produces deterministic keypairs from a fixed seed", () => {
    const seed = Buffer.alloc(32, 1);
    const a = mlDsaKeyPairFromSeed(seed);
    const b = mlDsaKeyPairFromSeed(seed);
    expect(a.publicKey.equals(b.publicKey)).toBe(true);
    expect(a.privateKey.equals(b.privateKey)).toBe(true);
  });

  it("rejects malformed seeds", () => {
    expect(() => mlDsaKeyPairFromSeed(Buffer.alloc(16))).toThrow();
    expect(() => mlDsaKeyPairFromSeed(Buffer.alloc(64))).toThrow();
  });

  it("signs a message and verifies the signature", async () => {
    const kp = mlDsaKeyPairFromSeed(Buffer.alloc(32, 2));
    const msg = Buffer.from("qrauth:test:ml-dsa:v1");
    const sig = await mlDsaSign(kp.privateKey, msg);
    expect(sig.length).toBe(MLDSA_LENGTHS.signature);
    expect(await mlDsaVerify(kp.publicKey, msg, sig)).toBe(true);
  });

  it("rejects a signature with the wrong message", async () => {
    const kp = mlDsaKeyPairFromSeed(Buffer.alloc(32, 3));
    const sig = await mlDsaSign(kp.privateKey, Buffer.from("real"));
    expect(await mlDsaVerify(kp.publicKey, Buffer.from("forged"), sig)).toBe(false);
  });

  it("rejects a signature under the wrong public key", async () => {
    const a = mlDsaKeyPairFromSeed(Buffer.alloc(32, 4));
    const b = mlDsaKeyPairFromSeed(Buffer.alloc(32, 5));
    const sig = await mlDsaSign(a.privateKey, Buffer.from("msg"));
    expect(await mlDsaVerify(b.publicKey, Buffer.from("msg"), sig)).toBe(false);
  });

  it("rejects malformed inputs without throwing", async () => {
    const kp = mlDsaKeyPairFromSeed(Buffer.alloc(32, 6));
    const sig = await mlDsaSign(kp.privateKey, Buffer.from("msg"));
    expect(await mlDsaVerify(Buffer.alloc(10), Buffer.from("msg"), sig)).toBe(false);
    expect(await mlDsaVerify(kp.publicKey, Buffer.from("msg"), Buffer.alloc(10))).toBe(false);
  });

  it("rejects signing with malformed private key", async () => {
    await expect(mlDsaSign(Buffer.alloc(10), Buffer.from("msg"))).rejects.toThrow();
  });

  it("verify is fast (target: <50ms)", async () => {
    const kp = mlDsaKeyPairFromSeed(Buffer.alloc(32, 7));
    const sig = await mlDsaSign(kp.privateKey, Buffer.from("benchmark"));
    const t0 = Date.now();
    await mlDsaVerify(kp.publicKey, Buffer.from("benchmark"), sig);
    const elapsed = Date.now() - t0;
    expect(elapsed).toBeLessThan(50);
  });
});
