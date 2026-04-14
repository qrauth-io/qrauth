/**
 * Generate cross-language test vectors for the QRVA canonical payload.
 *
 * Run with:
 *   npx tsx packages/protocol-tests/scripts/generate-vectors.ts
 *
 * Output:
 *   packages/protocol-tests/fixtures/canonical-vectors.json
 *
 * The JSON is the authoritative wire-format pin between the Node and
 * Python (and future Go / Rust / PHP) SDK implementations of the
 * canonical payload serializer. ALGORITHM.md §14.2:
 *
 *   "If any SDK produces a different canonical payload string,
 *    Merkle leaf hash, or MAC for the same inputs, the CI build
 *    fails."
 *
 * The Node side is the reference implementation. This script enumerates
 * a curated set of payloads (covering the interesting axes — null
 * geo, real geo, edge-case coordinates, all charsets, fixed nonces)
 * and computes the canonical string + leaf hash + per-component
 * hashes for each. Both sides verify byte-for-byte equality at test
 * time.
 *
 * Curated, not random: random vectors would change every run and
 * mask drift between SDKs. Hand-picked vectors are stable across
 * generations and cover the cases that actually exercise the
 * format edges.
 *
 * To add a new vector: edit the FIXTURES array, re-run this script,
 * commit the updated JSON. Both Node and Python tests pick it up
 * automatically.
 */
import { writeFileSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import {
  canonicalizePayload,
  canonicalGeoHash,
  sha3_256Hex,
  type CanonicalQRPayload,
} from "@qrauth/shared";
import {
  computeLeafHash,
  type QRPayloadInput,
} from "../../api/src/services/merkle-signing.js";

interface Fixture {
  name: string;
  description: string;
  payload: CanonicalQRPayload;
}

// Curated fixtures covering the canonicalizer's branching axes.
// Tokens use a mix of charsets, geo coverage spans null/positive/
// negative/extreme, expiry covers ISO 8601 + the epoch sentinel,
// and the nonce is a fixed hex string per fixture so the output is
// deterministic across regenerations.
const FIXTURES: Fixture[] = [
  {
    name: "minimal_no_location",
    description: "Smallest valid payload with no location set",
    payload: {
      token: "abc123",
      tenantId: "tnt_test",
      destinationUrl: "https://example.com/x",
      lat: null,
      lng: null,
      radiusM: null,
      expiresAt: "2027-01-01T00:00:00.000Z",
      nonce: "deadbeef",
    },
  },
  {
    name: "northern_hemisphere_location",
    description: "Real-world location in NYC with 100m radius",
    payload: {
      token: "xK9m2pQ7",
      tenantId: "tnt_acme",
      destinationUrl: "https://acme.example/promo",
      lat: 40.7128,
      lng: -74.006,
      radiusM: 100,
      expiresAt: "2027-01-01T00:00:00.000Z",
      nonce: "0000000000000000000000000000000000000000000000000000000000000001",
    },
  },
  {
    name: "southern_hemisphere_location",
    description: "Real-world location in Sydney",
    payload: {
      token: "tok_AU01",
      tenantId: "tnt_au",
      destinationUrl: "https://example.au/welcome",
      lat: -33.8688,
      lng: 151.2093,
      radiusM: 50,
      expiresAt: "2026-06-15T12:30:00.000Z",
      nonce: "feedface",
    },
  },
  {
    name: "antimeridian_edge",
    description: "Coordinates near the antimeridian (180/-180 boundary)",
    payload: {
      token: "tok_FJI1",
      tenantId: "tnt_pacific",
      destinationUrl: "https://example.fj/",
      lat: -17.7134,
      lng: 178.065,
      radiusM: 200,
      expiresAt: "2027-12-31T23:59:59.999Z",
      nonce: "cafebabe",
    },
  },
  {
    name: "polar_extreme",
    description: "Coordinates very near the north pole, with epoch-sentinel expiry",
    payload: {
      token: "tok_POL",
      tenantId: "tnt_research",
      destinationUrl: "https://research.example/north",
      lat: 89.9999999,
      lng: 0.0,
      radiusM: 1,
      // Epoch sentinel: production code converts null expiry to
      // `new Date(0).toISOString()` before canonicalizing, so the
      // string-based canonicalizer never sees an empty expiresAt
      // for any payload that flows through the Merkle layer. The
      // fixture pins this sentinel explicitly so the canonical
      // string and the Merkle leaf hash agree across SDKs.
      expiresAt: "1970-01-01T00:00:00.000Z",
      nonce: "01",
    },
  },
  {
    name: "no_expiry",
    description: "Non-expiring code (epoch-sentinel expiry)",
    payload: {
      token: "perma01",
      tenantId: "tnt_perma",
      destinationUrl: "https://perma.example/",
      lat: null,
      lng: null,
      radiusM: null,
      expiresAt: "1970-01-01T00:00:00.000Z",
      nonce: "00",
    },
  },
  {
    name: "epoch_expiry_sentinel",
    description: "Epoch sentinel (1970-01-01) used by the Merkle layer for null expiry",
    payload: {
      token: "epochSe",
      tenantId: "tnt_e",
      destinationUrl: "https://example.com/epoch",
      lat: null,
      lng: null,
      radiusM: null,
      expiresAt: "1970-01-01T00:00:00.000Z",
      nonce: "abcdef0123456789",
    },
  },
  {
    name: "url_with_query_and_fragment",
    description: "Destination URL with query string and fragment",
    payload: {
      token: "tok_qry",
      tenantId: "tnt_qry",
      destinationUrl: "https://example.com/path?foo=bar&baz=qux#frag",
      lat: 0.0,
      lng: 0.0,
      radiusM: 10,
      expiresAt: "2030-01-01T00:00:00.000Z",
      nonce: "1234567890abcdef",
    },
  },
  {
    name: "long_token",
    description: "Token at the upper realistic length",
    payload: {
      token: "ABCDEFGHIJKLMNOPQRSTUVWX",
      tenantId: "tnt_long",
      destinationUrl: "https://example.com/long",
      lat: 51.5074,
      lng: -0.1278,
      radiusM: 500,
      expiresAt: "2027-01-01T00:00:00.000Z",
      nonce: "ffffffffffffffff",
    },
  },
  {
    name: "decimal_precision_check",
    description: "Lat/lng with full 7-decimal precision to lock in toFixed formatting",
    payload: {
      token: "precise",
      tenantId: "tnt_pre",
      destinationUrl: "https://example.com/precise",
      lat: 41.4123456,
      lng: 23.7654321,
      radiusM: 25,
      expiresAt: "2027-01-01T00:00:00.000Z",
      nonce: "deadbeefcafebabe",
    },
  },
];

interface VectorOutput {
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
      // sha3 of the canonical string with no leaf prefix — useful
      // for cross-language sanity checks separate from the Merkle
      // 0x00 prefix convention.
      canonicalSha3: string;
      // Full Merkle leaf hash (0x00 prefix + canonical bytes →
      // sha3-256). This is the value that lands in the Merkle tree
      // and is the most important thing to keep byte-identical.
      leafHash: string;
    };
  }>;
}

async function main() {
  const vectors: VectorOutput["vectors"] = [];

  for (const fixture of FIXTURES) {
    const destinationHash = await sha3_256Hex(fixture.payload.destinationUrl);
    const geoHash = await canonicalGeoHash(
      fixture.payload.lat,
      fixture.payload.lng,
      fixture.payload.radiusM,
    );
    const canonical = await canonicalizePayload(fixture.payload);
    const canonicalSha3 = createHash("sha3-256").update(canonical, "utf8").digest("hex");

    // Recompute the Merkle leaf hash via the api-side helper so we
    // also lock in the leaf-prefix convention. The leaf hash takes a
    // QRPayloadInput which has a slightly different shape — convert.
    const merklePayload: QRPayloadInput = {
      token: fixture.payload.token,
      tenantId: fixture.payload.tenantId,
      destinationUrl: fixture.payload.destinationUrl,
      lat: fixture.payload.lat,
      lng: fixture.payload.lng,
      radiusM: fixture.payload.radiusM,
      expiresAt:
        fixture.payload.expiresAt === ""
          ? new Date(0)
          : new Date(fixture.payload.expiresAt),
    };
    const leafHash = await computeLeafHash(merklePayload, fixture.payload.nonce);

    vectors.push({
      name: fixture.name,
      description: fixture.description,
      payload: fixture.payload,
      expected: { destinationHash, geoHash, canonical, canonicalSha3, leafHash },
    });
  }

  const output: VectorOutput = {
    protocolVersion: "qrva-v2",
    generatedAt: new Date().toISOString(),
    notes: [
      "Cross-language test vectors for the QRVA canonical payload (ALGORITHM.md §14.2).",
      "Generated by packages/protocol-tests/scripts/generate-vectors.ts from the Node implementation.",
      "Both packages/protocol-tests (Node) and packages/python-sdk/tests (Python) consume this file.",
      "If you change the canonicalizer, regenerate these vectors AND update both test suites.",
      "Each fixture pins: destinationHash, geoHash, canonical string, sha3 of canonical, Merkle leaf hash.",
    ],
    vectors,
  };

  const __filename = fileURLToPath(import.meta.url);
  const here = dirname(__filename);
  const outputPath = resolve(here, "../fixtures/canonical-vectors.json");
  mkdirSync(dirname(outputPath), { recursive: true });
  writeFileSync(outputPath, JSON.stringify(output, null, 2) + "\n");

  // eslint-disable-next-line no-console
  console.log(`✓ wrote ${vectors.length} vectors to ${outputPath}`);
}

main().catch((err) => {
  // eslint-disable-next-line no-console
  console.error("✗ vector generation failed:", err);
  process.exit(1);
});
