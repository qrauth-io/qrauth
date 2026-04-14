import { describe, it, expect } from "vitest";
import { createHash } from "crypto";
import {
  canonicalGeoHash,
  canonicalizePayload,
  canonicalizePayloadSync,
  sha3_256Hex,
  CANONICAL_FIELD_SEPARATOR,
} from "@qrauth/shared";

const sha3 = (input: string) => createHash("sha3-256").update(input).digest("hex");

describe("canonical payload serialization", () => {
  it("hashes destination URL with SHA3-256", async () => {
    const out = await sha3_256Hex("https://example.com/landing");
    expect(out).toBe(sha3("https://example.com/landing"));
    expect(out).toHaveLength(64);
  });

  it("uses the literal 'none' geo hash when location is unset", async () => {
    expect(await canonicalGeoHash(null, null, null)).toBe("none");
  });

  it("rejects partially-set location", async () => {
    await expect(canonicalGeoHash(41.4, null, null)).rejects.toThrow();
    await expect(canonicalGeoHash(null, 23.7, null)).rejects.toThrow();
    await expect(canonicalGeoHash(41.4, 23.7, null)).rejects.toThrow();
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

  it("produces a deterministic canonical payload string", async () => {
    const a = await canonicalizePayload({
      token: "abc123",
      tenantId: "tnt_1",
      destinationUrl: "https://example.com/x",
      lat: 41.4,
      lng: 23.7,
      radiusM: 50,
      expiresAt: "2027-01-01T00:00:00.000Z",
      nonce: "deadbeef",
    });
    const b = await canonicalizePayload({
      token: "abc123",
      tenantId: "tnt_1",
      destinationUrl: "https://example.com/x",
      lat: 41.4,
      lng: 23.7,
      radiusM: 50,
      expiresAt: "2027-01-01T00:00:00.000Z",
      nonce: "deadbeef",
    });
    expect(a).toBe(b);
  });

  it("produces different canonical strings for differing fields", async () => {
    const base = {
      token: "abc123",
      tenantId: "tnt_1",
      destinationUrl: "https://example.com/x",
      lat: 41.4,
      lng: 23.7,
      radiusM: 50,
      expiresAt: "2027-01-01T00:00:00.000Z",
      nonce: "deadbeef",
    };
    const a = await canonicalizePayload(base);
    const b = await canonicalizePayload({ ...base, token: "abc124" });
    const c = await canonicalizePayload({ ...base, destinationUrl: "https://example.com/y" });
    const d = await canonicalizePayload({ ...base, nonce: "deadbeee" });
    expect(new Set([a, b, c, d]).size).toBe(4);
  });

  it("matches the documented field order", async () => {
    const out = canonicalizePayloadSync({
      token: "T",
      tenantId: "TID",
      destinationHash: "DH",
      geoHash: "GH",
      expiresAt: "EXP",
      nonce: "N",
    });
    expect(out).toBe(["T", "TID", "DH", "GH", "EXP", "N"].join(CANONICAL_FIELD_SEPARATOR));
  });

  // Cross-language test vector. Any SDK (Python, Go, Rust) MUST reproduce
  // these exact bytes when fed the same input. If you change this, you have
  // changed the on-the-wire protocol — bump qrva-v2 → qrva-v3.
  it("matches the pinned cross-language test vector", async () => {
    const canonical = await canonicalizePayload({
      token: "xK9m2pQ7",
      tenantId: "tnt_acme",
      destinationUrl: "https://acme.example/promo",
      lat: 40.7128,
      lng: -74.006,
      radiusM: 100,
      expiresAt: "2027-01-01T00:00:00.000Z",
      nonce: "0000000000000000000000000000000000000000000000000000000000000001",
    });
    const expectedDestHash = sha3("https://acme.example/promo");
    const expectedGeoHash = sha3("40.7128000:-74.0060000:100");
    const expected = [
      "xK9m2pQ7",
      "tnt_acme",
      expectedDestHash,
      expectedGeoHash,
      "2027-01-01T00:00:00.000Z",
      "0000000000000000000000000000000000000000000000000000000000000001",
    ].join("|");
    expect(canonical).toBe(expected);
  });
});
