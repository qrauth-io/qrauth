import { describe, it, expect } from "vitest";
import { createHash } from "crypto";
import {
  canonicalGeoHash,
  canonicalizeCore,
  canonicalizeMerkleLeaf,
  computeDestHash,
  sha3_256Hex,
  CANONICAL_FIELD_SEPARATOR,
} from "@qrauth/shared";

const sha3 = (input: string) => createHash("sha3-256").update(input).digest("hex");

describe("canonical payload serialization (AUDIT-FINDING-011 unified form)", () => {
  it("hashes destination URL with SHA3-256 via computeDestHash", async () => {
    const out = await computeDestHash("url", "https://example.com/landing", "");
    // Domain-separated: SHA3-256("qrauth:dest:v1:url:https://example.com/landing")
    expect(out).toBe(sha3("qrauth:dest:v1:url:https://example.com/landing"));
    expect(out).toHaveLength(64);
  });

  it("content QRs commit to the content hash instead of the URL", async () => {
    const urlHash = await computeDestHash("url", "https://example.com/r/token-1", "");
    const contentHash = await computeDestHash("vcard", "https://example.com/r/token-1", "abc123def");
    expect(urlHash).not.toBe(contentHash);
    expect(contentHash).toBe(sha3("qrauth:dest:v1:vcard:abc123def"));
  });

  it("uses the literal 'none' geo hash when location is unset", async () => {
    expect(await canonicalGeoHash(null, null, null)).toBe("none");
  });

  it("rejects lat+lng set without a radius", async () => {
    await expect(canonicalGeoHash(41.4, 23.7, null)).rejects.toThrow();
  });

  it("treats any row with a null lat or lng as unbound, returning 'none'", async () => {
    // The schema default on `radiusM` is 50, which would otherwise trip a
    // partial-set check on legitimately-unbound rows.
    expect(await canonicalGeoHash(41.4, null, 50)).toBe("none");
    expect(await canonicalGeoHash(null, 23.7, 50)).toBe("none");
    expect(await canonicalGeoHash(null, null, 50)).toBe("none");
  });

  it("normalizes lat/lng to 7 decimal places before hashing", async () => {
    const a = await canonicalGeoHash(41.4, 23.7, 50);
    const b = await canonicalGeoHash(41.4000000, 23.7000000, 50);
    expect(a).toBe(b);
  });

  it("treats different precisions as distinct geohashes when they differ at 7dp", async () => {
    const a = await canonicalGeoHash(41.4000001, 23.7, 50);
    const b = await canonicalGeoHash(41.4000002, 23.7, 50);
    expect(a).not.toBe(b);
  });

  it("canonicalizeCore is deterministic", () => {
    const parts = {
      algVersion: "hybrid-ecdsa-slhdsa-v1",
      token: "abc123",
      tenantId: "tnt_1",
      destHash: "d".repeat(64),
      geoHash: "g".repeat(64),
      expiresAt: "2027-01-01T00:00:00.000Z",
    };
    expect(canonicalizeCore(parts)).toBe(canonicalizeCore(parts));
  });

  it("produces different canonical strings for differing fields", () => {
    const base = {
      algVersion: "hybrid-ecdsa-slhdsa-v1",
      token: "abc123",
      tenantId: "tnt_1",
      destHash: "d".repeat(64),
      geoHash: "g".repeat(64),
      expiresAt: "2027-01-01T00:00:00.000Z",
    };
    const a = canonicalizeCore(base);
    const b = canonicalizeCore({ ...base, token: "abc124" });
    const c = canonicalizeCore({ ...base, destHash: "e".repeat(64) });
    const d = canonicalizeCore({ ...base, algVersion: "slhdsa-sha2-128s-v1" });
    expect(new Set([a, b, c, d]).size).toBe(4);
  });

  it("canonicalizeCore matches the documented field order", () => {
    const out = canonicalizeCore({
      algVersion: "A",
      token: "T",
      tenantId: "TID",
      destHash: "DH",
      geoHash: "GH",
      expiresAt: "EXP",
    });
    expect(out).toBe(["A", "T", "TID", "DH", "GH", "EXP"].join(CANONICAL_FIELD_SEPARATOR));
  });

  it("canonicalizeMerkleLeaf appends a per-leaf nonce to the core form", () => {
    const core = {
      algVersion: "A",
      token: "T",
      tenantId: "TID",
      destHash: "DH",
      geoHash: "GH",
      expiresAt: "EXP",
    };
    const leaf = canonicalizeMerkleLeaf({ ...core, nonce: "N" });
    expect(leaf).toBe(["A", "T", "TID", "DH", "GH", "EXP", "N"].join(CANONICAL_FIELD_SEPARATOR));
    // Core form is a strict prefix — the Merkle leaf hash commits to the
    // same inputs as the ECDSA + MAC legs, plus the nonce.
    expect(leaf.startsWith(canonicalizeCore(core) + CANONICAL_FIELD_SEPARATOR)).toBe(true);
  });

  it("rejects separator, newline, and NUL in core fields", () => {
    const base = {
      algVersion: "hybrid-ecdsa-slhdsa-v1",
      token: "abc",
      tenantId: "t",
      destHash: "d",
      geoHash: "g",
      expiresAt: "",
    };
    expect(() => canonicalizeCore({ ...base, token: "a|b" })).toThrow();
    expect(() => canonicalizeCore({ ...base, token: "a\nb" })).toThrow();
    expect(() => canonicalizeCore({ ...base, token: "a\0b" })).toThrow();
  });

  // Cross-language test vector. Any SDK (Python, Go, Rust) MUST reproduce
  // these exact bytes when fed the same input. If you change this, you have
  // changed the on-the-wire protocol — bump qrva-v2 → qrva-v3.
  it("matches the pinned cross-language test vector", async () => {
    const destHash = await computeDestHash("url", "https://acme.example/promo", "");
    const geoHash = await canonicalGeoHash(40.7128, -74.006, 100);
    const canonical = canonicalizeCore({
      algVersion: "hybrid-ecdsa-slhdsa-v1",
      token: "xK9m2pQ7",
      tenantId: "tnt_acme",
      destHash,
      geoHash,
      expiresAt: "2027-01-01T00:00:00.000Z",
    });
    const expectedDestHash = sha3("qrauth:dest:v1:url:https://acme.example/promo");
    const expectedGeoHash = sha3("40.7128000:-74.0060000:100");
    const expected = [
      "hybrid-ecdsa-slhdsa-v1",
      "xK9m2pQ7",
      "tnt_acme",
      expectedDestHash,
      expectedGeoHash,
      "2027-01-01T00:00:00.000Z",
    ].join("|");
    expect(canonical).toBe(expected);
  });
});
