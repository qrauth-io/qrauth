import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";

import {
  canonicalizePayload,
  canonicalGeoHash,
  sha3_256Hex,
  type CanonicalQRPayload,
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
 * Why this matters: the canonical string is the input to every
 * Merkle leaf hash and every MAC computation. A single byte of
 * drift between the Node and Python SDKs silently breaks every
 * signature that crosses the language boundary. These vectors are
 * the contract.
 *
 * To regenerate:
 *   npx tsx packages/protocol-tests/scripts/generate-vectors.ts
 *
 * Then re-run both Node and Python suites.
 */

interface VectorFile {
  protocolVersion: string;
  generatedAt: string;
  notes: string[];
  vectors: Array<{
    name: string;
    description: string;
    payload: CanonicalQRPayload;
    expected: {
      destinationHash: string;
      geoHash: string;
      canonical: string;
      canonicalSha3: string;
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
      it("destinationHash matches", async () => {
        const out = await sha3_256Hex(vector.payload.destinationUrl);
        expect(out).toBe(vector.expected.destinationHash);
      });

      it("geoHash matches", async () => {
        const out = await canonicalGeoHash(
          vector.payload.lat,
          vector.payload.lng,
          vector.payload.radiusM,
        );
        expect(out).toBe(vector.expected.geoHash);
      });

      it("canonical string matches byte-for-byte", async () => {
        const out = await canonicalizePayload(vector.payload);
        expect(out).toBe(vector.expected.canonical);
      });

      it("canonicalSha3 matches (sha3 of the canonical string)", async () => {
        const canonical = await canonicalizePayload(vector.payload);
        const sha3 = createHash("sha3-256").update(canonical, "utf8").digest("hex");
        expect(sha3).toBe(vector.expected.canonicalSha3);
      });

      it("leafHash matches (Merkle leaf with 0x00 prefix)", async () => {
        const merklePayload: QRPayloadInput = {
          token: vector.payload.token,
          tenantId: vector.payload.tenantId,
          destinationUrl: vector.payload.destinationUrl,
          lat: vector.payload.lat,
          lng: vector.payload.lng,
          radiusM: vector.payload.radiusM,
          expiresAt:
            vector.payload.expiresAt === ""
              ? new Date(0)
              : new Date(vector.payload.expiresAt),
        };
        const out = await computeLeafHash(merklePayload, vector.payload.nonce);
        expect(out).toBe(vector.expected.leafHash);
      });
    });
  }
});
