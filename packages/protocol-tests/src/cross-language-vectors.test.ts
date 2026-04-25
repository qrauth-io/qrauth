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
import { computeLeafHash, type QRPayloadInput } from "../../api/src/services/merkle-signing.js";

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
});
