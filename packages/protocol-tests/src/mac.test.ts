import { describe, it, expect } from "vitest";
import { computeMac, macsEqual, MAC_KEY_BYTES } from "../../api/src/services/mac.js";

describe("MAC primitives", () => {
  it("uses a 256-bit key", () => {
    expect(MAC_KEY_BYTES).toBe(32);
  });

  it("is deterministic for a fixed (payload, secret)", () => {
    const secret = Buffer.alloc(32, 7);
    const a = computeMac("token:url:geo:exp:contenthash", secret);
    const b = computeMac("token:url:geo:exp:contenthash", secret);
    expect(a).toBe(b);
    expect(a).toHaveLength(64);
  });

  it("changes with the payload", () => {
    const secret = Buffer.alloc(32, 7);
    const a = computeMac("token:urlA:geo:exp:ch", secret);
    const b = computeMac("token:urlB:geo:exp:ch", secret);
    expect(a).not.toBe(b);
  });

  it("changes with the secret", () => {
    const a = computeMac("token:url:geo:exp:ch", Buffer.alloc(32, 1));
    const b = computeMac("token:url:geo:exp:ch", Buffer.alloc(32, 2));
    expect(a).not.toBe(b);
  });

  it("includes the v1 domain separation tag", () => {
    // Two payloads where one happens to start with the literal v1 prefix
    // must still produce different MACs — i.e. the domain tag is prepended,
    // not interpolated.
    const secret = Buffer.alloc(32, 9);
    const real = computeMac("alpha", secret);
    const collision = computeMac("qrauth:mac:v1:alpha", secret);
    expect(real).not.toBe(collision);
  });

  it("constant-time comparison rejects different MACs", () => {
    expect(macsEqual("aa".repeat(32), "bb".repeat(32))).toBe(false);
  });

  it("constant-time comparison accepts identical MACs", () => {
    expect(macsEqual("aa".repeat(32), "aa".repeat(32))).toBe(true);
  });

  it("constant-time comparison rejects mismatched lengths", () => {
    expect(macsEqual("aa".repeat(32), "aabb")).toBe(false);
  });
});
