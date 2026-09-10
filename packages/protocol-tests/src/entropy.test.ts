import { describe, it, expect } from "vitest";
import { generateSecureEntropy } from "../../api/src/lib/entropy.js";

describe("generateSecureEntropy", () => {
  it("returns the requested number of bytes", async () => {
    for (const n of [1, 16, 32, 48, 64, 128]) {
      const buf = await generateSecureEntropy(n);
      expect(buf.length).toBe(n);
    }
  });

  it("rejects non-positive sizes", async () => {
    await expect(generateSecureEntropy(0)).rejects.toThrow();
    await expect(generateSecureEntropy(-1)).rejects.toThrow();
    await expect(generateSecureEntropy(1.5)).rejects.toThrow();
  });

  it("produces high-entropy output (no all-zero / all-one buffers)", async () => {
    for (let i = 0; i < 16; i++) {
      const buf = await generateSecureEntropy(32);
      expect(buf.every((b) => b === 0)).toBe(false);
      expect(buf.every((b) => b === 0xff)).toBe(false);
    }
  });

  it("never returns identical buffers across calls", async () => {
    const samples = await Promise.all(
      Array.from({ length: 64 }, () => generateSecureEntropy(32)),
    );
    const hexes = new Set(samples.map((b) => b.toString("hex")));
    expect(hexes.size).toBe(samples.length);
  });
});
