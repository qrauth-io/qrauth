import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";

import {
  canonicalizeCore,
  canonicalizeMerkleLeaf,
  canonicalGeoHash,
  computeDestHash,
} from "@qrauth/shared";
import {
  computeLeafHash,
  computeLeafHashFromCore,
  leafHashesEqual,
  type QRPayloadInput,
} from "../../api/src/services/merkle-signing.js";
import { buildQrCanonicalCore } from "../../api/src/lib/qr-canonical.js";

/**
 * Cross-language test vector consumer for the Node side.
 *
 * Reads `fixtures/canonical-vectors.json` and asserts that the Node
 * implementation reproduces every recorded value exactly. The same
 * file is consumed by the Python tests in
 * `packages/python-sdk/tests/test_canonical.py` — if either side
 * drifts, the corresponding suite fails and CI blocks the merge.
 *
 * To regenerate:
 *   npx tsx packages/protocol-tests/scripts/generate-vectors.ts
 */

interface VectorPayload {
  algVersion: string;
  token: string;
  tenantId: string;
  contentType: string;
  destinationUrl: string;
  contentHashHex: string;
  lat: number | null;
  lng: number | null;
  radiusM: number | null;
  expiresAt: string;
  nonce: string;
}

interface VectorFile {
  protocolVersion: string;
  generatedAt: string;
  notes: string[];
  vectors: Array<{
    name: string;
    description: string;
    payload: VectorPayload;
    expected: {
      destHash: string;
      geoHash: string;
      canonicalCore: string;
      canonicalCoreSha3: string;
      merkleLeaf: string;
      leafHash: string;
    };
  }>;
  leafBinding: Array<{
    name: string;
    base: string;
    storedLeafHash: string;
    payload: VectorPayload;
    recomputedLeafHash: string;
    expect: "accept" | "reject";
  }>;
}

const __filename = fileURLToPath(import.meta.url);
const here = dirname(__filename);
const fixturesPath = resolve(here, "../fixtures/canonical-vectors.json");
const fixtures = JSON.parse(readFileSync(fixturesPath, "utf8")) as VectorFile;

describe("cross-language canonical vectors (Node side)", () => {
  it("the fixtures file pins protocol qrva-v2", () => {
    expect(fixtures.protocolVersion).toBe("qrva-v2");
  });

  it("the fixtures file is non-empty", () => {
    expect(fixtures.vectors.length).toBeGreaterThan(0);
  });

  for (const vector of fixtures.vectors) {
    describe(`vector: ${vector.name}`, () => {
      it("destHash matches", async () => {
        const out = await computeDestHash(
          vector.payload.contentType,
          vector.payload.destinationUrl,
          vector.payload.contentHashHex,
        );
        expect(out).toBe(vector.expected.destHash);
      });

      it("geoHash matches", async () => {
        const out = await canonicalGeoHash(
          vector.payload.lat,
          vector.payload.lng,
          vector.payload.radiusM,
        );
        expect(out).toBe(vector.expected.geoHash);
      });

      it("canonicalCore matches byte-for-byte", async () => {
        const destHash = await computeDestHash(
          vector.payload.contentType,
          vector.payload.destinationUrl,
          vector.payload.contentHashHex,
        );
        const geoHash = await canonicalGeoHash(
          vector.payload.lat,
          vector.payload.lng,
          vector.payload.radiusM,
        );
        const out = canonicalizeCore({
          algVersion: vector.payload.algVersion,
          token: vector.payload.token,
          tenantId: vector.payload.tenantId,
          destHash,
          geoHash,
          expiresAt: vector.payload.expiresAt,
        });
        expect(out).toBe(vector.expected.canonicalCore);
      });

      it("canonicalCoreSha3 matches", () => {
        const sha3 = createHash("sha3-256")
          .update(vector.expected.canonicalCore, "utf8")
          .digest("hex");
        expect(sha3).toBe(vector.expected.canonicalCoreSha3);
      });

      it("merkleLeaf matches", async () => {
        const destHash = await computeDestHash(
          vector.payload.contentType,
          vector.payload.destinationUrl,
          vector.payload.contentHashHex,
        );
        const geoHash = await canonicalGeoHash(
          vector.payload.lat,
          vector.payload.lng,
          vector.payload.radiusM,
        );
        const out = canonicalizeMerkleLeaf({
          algVersion: vector.payload.algVersion,
          token: vector.payload.token,
          tenantId: vector.payload.tenantId,
          destHash,
          geoHash,
          expiresAt: vector.payload.expiresAt,
          nonce: vector.payload.nonce,
        });
        expect(out).toBe(vector.expected.merkleLeaf);
      });

      it("leafHash matches (Merkle leaf with 0x00 prefix)", async () => {
        const merklePayload: QRPayloadInput = {
          algVersion: vector.payload.algVersion,
          token: vector.payload.token,
          tenantId: vector.payload.tenantId,
          contentType: vector.payload.contentType,
          destinationUrl: vector.payload.destinationUrl,
          contentHashHex: vector.payload.contentHashHex,
          lat: vector.payload.lat,
          lng: vector.payload.lng,
          radiusM: vector.payload.radiusM,
          expiresAt: vector.payload.expiresAt,
        };
        const out = await computeLeafHash(merklePayload, vector.payload.nonce);
        expect(out).toBe(vector.expected.leafHash);
      });
    });
  }

  describe("verify route core builder (Date round trip)", () => {
    // The verify route rebuilds the core from a database row, where expiresAt
    // is a Date. Its serialization must match the vector byte for byte under
    // any host time zone (CI runs this file under UTC and Europe/Athens).
    for (const vector of fixtures.vectors) {
      it(`${vector.name}: buildQrCanonicalCore reproduces canonicalCore`, async () => {
        const p = vector.payload;
        const core = await buildQrCanonicalCore({
          token: p.token,
          organizationId: p.tenantId,
          contentType: p.contentType,
          destinationUrl: p.destinationUrl,
          content: null,
          latitude: p.lat,
          longitude: p.lng,
          radiusM: p.radiusM ?? 50,
          expiresAt: p.expiresAt ? new Date(p.expiresAt) : null,
          algVersion: p.algVersion,
        });
        if (p.contentType === "url") {
          expect(core).toBe(vector.expected.canonicalCore);
        } else {
          // Content QRs hash stored content; the vector pins contentHashHex
          // directly, so compare every field except destHash.
          const [a, b] = [core.split("|"), vector.expected.canonicalCore.split("|")];
          expect([a[0], a[1], a[2], a[4], a[5]]).toEqual([b[0], b[1], b[2], b[4], b[5]]);
        }
      });
    }
  });

  describe("leaf binding (verifier recomputes the leaf)", () => {
    it("has leaf-binding cases", () => {
      expect(fixtures.leafBinding.length).toBeGreaterThan(0);
    });

    for (const c of fixtures.leafBinding) {
      it(`${c.name}: recomputed leaf matches and verdict is ${c.expect}`, async () => {
        const core = canonicalizeCore({
          algVersion: c.payload.algVersion,
          token: c.payload.token,
          tenantId: c.payload.tenantId,
          destHash: await computeDestHash(
            c.payload.contentType,
            c.payload.destinationUrl,
            c.payload.contentHashHex,
          ),
          geoHash: await canonicalGeoHash(c.payload.lat, c.payload.lng, c.payload.radiusM),
          expiresAt: c.payload.expiresAt,
        });
        const recomputed = computeLeafHashFromCore(core, c.payload.nonce);
        expect(recomputed).toBe(c.recomputedLeafHash);
        expect(leafHashesEqual(recomputed, c.storedLeafHash) ? "accept" : "reject").toBe(c.expect);
      });
    }

    // Pinned by hand, independent of the generator: an unchanged payload is
    // accepted, and every field the leaf binds for that content type rejects.
    const verdict = (name: string) => fixtures.leafBinding.find((c) => c.name === name)?.expect;
    it("pins the expected verdicts", () => {
      for (const base of ["minimal_no_location", "vcard_content_qr", "expiry_near_midnight_utc"]) {
        expect(verdict(`${base}__unchanged`)).toBe("accept");
        for (const m of ["tenant_changed", "expiry_changed", "location_added", "nonce_changed", "alg_version_changed"]) {
          expect(verdict(`${base}__${m}`)).toBe("reject");
        }
      }
      expect(verdict("minimal_no_location__destination_changed")).toBe("reject");
      expect(verdict("vcard_content_qr__content_hash_changed")).toBe("reject");
    });
  });
});
