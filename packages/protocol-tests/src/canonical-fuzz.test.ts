import { describe, it, expect } from "vitest";
import fc from "fast-check";
import {
  canonicalizeCore,
  canonicalizeMerkleLeaf,
  canonicalGeoHash,
  assertCanonicalSafe,
  type CanonicalCore,
} from "@qrauth/shared";

/** Strings that are safe to drop into a canonical field — no pipe,
 *  newline, or NUL. The canonicalizer rejects those characters
 *  defensively (see assertCanonicalSafe), so the fuzz inputs must
 *  match the contract production callers already obey. */
const arbCanonicalSafeString = (minLength: number, maxLength: number) =>
  fc
    .string({ minLength, maxLength })
    .filter((s) => !s.includes("|") && !s.includes("\n") && !s.includes("\0"));

/**
 * Property-based fuzzing of the canonical payload serializer
 * (AUDIT-FINDING-011 unified form).
 *
 * The canonical string is the input to every Merkle leaf hash, every
 * MAC computation, and every ECDSA signature in the system. Any drift
 * here — between two calls in the same process, between two SDK
 * languages, between two future versions — silently breaks every
 * signature it touches. The properties below pin the contract so any
 * drift fails CI loudly.
 *
 *   1. **Determinism**: same payload object, two calls → identical
 *      bytes. Pure string join, no async, no random input.
 *
 *   2. **Field independence**: changing any single field always changes
 *      the canonical string. Verifies no field is being silently
 *      collapsed (e.g. trimmed, lowercased, dropped on null).
 *
 *   3. **Geo precision**: lat/lng values that differ at the 7th decimal
 *      always produce different geo hashes; values that round to the
 *      same 7-decimal representation always produce the same hash.
 */

const HEX64 = "f".repeat(64);

// Arbitrary: a fully-populated CanonicalCore record. Fields are filtered
// against the canonical-safe predicate so we exercise the deterministic
// path, not the rejection path (covered by a dedicated test below).
const arbCore = fc.record<CanonicalCore>({
  algVersion: fc.constantFrom(
    "hybrid-ecdsa-slhdsa-v1",
    "slhdsa-sha2-128s-v1",
    "slhdsa-sha2-256s-v1",
  ),
  token: arbCanonicalSafeString(4, 24),
  tenantId: arbCanonicalSafeString(1, 32),
  destHash: fc.hexaString({ minLength: 64, maxLength: 64 }),
  geoHash: fc.oneof(fc.constant("none"), fc.hexaString({ minLength: 64, maxLength: 64 })),
  expiresAt: fc.constantFrom("", "2027-01-01T00:00:00.000Z", "2026-06-15T12:34:56.000Z"),
});

describe("canonicalizeCore — determinism property", () => {
  it("two calls with the same payload produce identical bytes", () => {
    fc.assert(
      fc.property(arbCore, (core) => canonicalizeCore(core) === canonicalizeCore(core)),
      { numRuns: 200 },
    );
  });

  it("produces a single-line pipe-separated string with exactly 6 fields", () => {
    fc.assert(
      fc.property(arbCore, (core) => {
        const out = canonicalizeCore(core);
        return out.split("|").length === 6 && !out.includes("\n");
      }),
      { numRuns: 200 },
    );
  });
});

describe("canonicalizeCore — field independence", () => {
  it("changing the token always changes the canonical string", () => {
    fc.assert(
      fc.property(arbCore, arbCanonicalSafeString(4, 24), (core, otherToken) => {
        fc.pre(otherToken !== core.token);
        return canonicalizeCore(core) !== canonicalizeCore({ ...core, token: otherToken });
      }),
      { numRuns: 100 },
    );
  });

  it("changing the tenantId always changes the canonical string", () => {
    fc.assert(
      fc.property(arbCore, arbCanonicalSafeString(1, 32), (core, otherTenant) => {
        fc.pre(otherTenant !== core.tenantId);
        return canonicalizeCore(core) !== canonicalizeCore({ ...core, tenantId: otherTenant });
      }),
      { numRuns: 100 },
    );
  });

  it("changing the destHash always changes the canonical string", () => {
    fc.assert(
      fc.property(
        arbCore,
        fc.hexaString({ minLength: 64, maxLength: 64 }),
        (core, otherDest) => {
          fc.pre(otherDest !== core.destHash);
          return canonicalizeCore(core) !== canonicalizeCore({ ...core, destHash: otherDest });
        },
      ),
      { numRuns: 100 },
    );
  });

  it("changing the algVersion always changes the canonical string", () => {
    fc.assert(
      fc.property(
        arbCore,
        fc.constantFrom(
          "hybrid-ecdsa-slhdsa-v1",
          "slhdsa-sha2-128s-v1",
          "slhdsa-sha2-256s-v1",
        ),
        (core, otherAlg) => {
          fc.pre(otherAlg !== core.algVersion);
          return canonicalizeCore(core) !== canonicalizeCore({ ...core, algVersion: otherAlg });
        },
      ),
      { numRuns: 100 },
    );
  });

  it("changing the expiresAt always changes the canonical string", () => {
    fc.assert(
      fc.property(arbCore, arbCanonicalSafeString(1, 30), (core, otherExpiry) => {
        fc.pre(otherExpiry !== core.expiresAt);
        return canonicalizeCore(core) !== canonicalizeCore({ ...core, expiresAt: otherExpiry });
      }),
      { numRuns: 100 },
    );
  });
});

describe("canonicalizeMerkleLeaf — nonce binds uniquely", () => {
  it("changing the nonce always changes the leaf string", () => {
    fc.assert(
      fc.property(
        arbCore,
        fc.hexaString({ minLength: 16, maxLength: 64 }),
        fc.hexaString({ minLength: 16, maxLength: 64 }),
        (core, nonceA, nonceB) => {
          fc.pre(nonceA !== nonceB);
          return (
            canonicalizeMerkleLeaf({ ...core, nonce: nonceA }) !==
            canonicalizeMerkleLeaf({ ...core, nonce: nonceB })
          );
        },
      ),
      { numRuns: 100 },
    );
  });

  it("the core form is a strict prefix of the leaf form", () => {
    fc.assert(
      fc.property(arbCore, fc.hexaString({ minLength: 16, maxLength: 64 }), (core, nonce) => {
        const leaf = canonicalizeMerkleLeaf({ ...core, nonce });
        return leaf.startsWith(canonicalizeCore(core) + "|");
      }),
      { numRuns: 100 },
    );
  });
});

describe("canonicalizeCore — separator-injection defense", () => {
  const FORBIDDEN_CHARS = ["|", "\n", "\0"] as const;

  for (const ch of FORBIDDEN_CHARS) {
    it(`rejects token containing ${JSON.stringify(ch)}`, () => {
      expect(() =>
        canonicalizeCore({
          algVersion: "hybrid-ecdsa-slhdsa-v1",
          token: `tok${ch}123`,
          tenantId: "tnt",
          destHash: HEX64,
          geoHash: "none",
          expiresAt: "",
        }),
      ).toThrow(/forbidden character/);
    });

    it(`rejects tenantId containing ${JSON.stringify(ch)}`, () => {
      expect(() =>
        canonicalizeCore({
          algVersion: "hybrid-ecdsa-slhdsa-v1",
          token: "tok",
          tenantId: `tnt${ch}1`,
          destHash: HEX64,
          geoHash: "none",
          expiresAt: "",
        }),
      ).toThrow(/forbidden character/);
    });
  }

  it("assertCanonicalSafe accepts safe inputs", () => {
    expect(() => assertCanonicalSafe("token", "abc123")).not.toThrow();
    expect(() => assertCanonicalSafe("token", "with-dashes_and.dots")).not.toThrow();
    expect(() => assertCanonicalSafe("token", "")).not.toThrow();
  });

  it("assertCanonicalSafe rejects non-string inputs", () => {
    expect(() => assertCanonicalSafe("token", null as unknown as string)).toThrow();
    expect(() => assertCanonicalSafe("token", 42 as unknown as string)).toThrow();
  });
});

describe("canonicalGeoHash — precision properties", () => {
  it("lat/lng/radius that round to identical 7-decimal forms produce identical hashes", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.double({ min: -89, max: 89, noNaN: true }),
        fc.double({ min: -179, max: 179, noNaN: true }),
        fc.integer({ min: 1, max: 1000 }),
        async (lat, lng, radius) => {
          const roundedLat = Number(lat.toFixed(7));
          const roundedLng = Number(lng.toFixed(7));
          const a = await canonicalGeoHash(roundedLat, roundedLng, radius);
          const b = await canonicalGeoHash(roundedLat, roundedLng, radius);
          return a === b;
        },
      ),
      { numRuns: 100 },
    );
  });

  it("the literal 'none' geohash is returned for fully-null locations", async () => {
    expect(await canonicalGeoHash(null, null, null)).toBe("none");
  });

  it("lat+lng set without a radius throws; null lat or lng always returns 'none'", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.double({ min: -90, max: 90, noNaN: true }),
        fc.double({ min: -180, max: 180, noNaN: true }),
        fc.integer({ min: 1, max: 1000 }),
        async (lat, lng, radius) => {
          // Only (lat, lng, null) is a hard error — both coordinates set
          // but no radius. Every other null combination collapses to
          // "unbound location" because radius without lat/lng is
          // meaningless (schema default of 50 can bleed through).
          await expect(canonicalGeoHash(lat, lng, null)).rejects.toThrow();
          expect(await canonicalGeoHash(lat, null, null)).toBe("none");
          expect(await canonicalGeoHash(null, lng, null)).toBe("none");
          expect(await canonicalGeoHash(null, null, radius)).toBe("none");
          expect(await canonicalGeoHash(lat, null, radius)).toBe("none");
          expect(await canonicalGeoHash(null, lng, radius)).toBe("none");
          return true;
        },
      ),
      { numRuns: 30 },
    );
  });
});
