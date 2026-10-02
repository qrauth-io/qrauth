/**
 * Generate cross-language test vectors for the QRVA canonical payload
 * (AUDIT-FINDING-011 unified form).
 *
 * Run with:
 *   npx tsx packages/protocol-tests/scripts/generate-vectors.ts
 *
 * Output:
 *   packages/protocol-tests/fixtures/canonical-vectors.json
 *
 * The JSON is the authoritative wire-format pin between the Node and
 * Python (and future Go / Rust / PHP) SDK implementations of the
 * canonical payload serializer.
 *
 * Format: unified core form from `canonicalizeCore`, plus Merkle leaf
 * form from `canonicalizeMerkleLeaf`. Each fixture captures the raw
 * source inputs (algVersion, token, tenant, contentType, destinationUrl,
 * contentHashHex, lat/lng/radius, expiry, nonce) and the expected
 * outputs computed by the Node implementation. SDKs in other languages
 * reproduce each output from the same inputs and assert byte-for-byte
 * equality.
 */
import { writeFileSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import {
  canonicalizeCore,
  canonicalizeMerkleLeaf,
  canonicalGeoHash,
  computeDestHash,
  ALG_VERSION_POLICY,
} from "@qrauth/shared";
import {
  computeLeafHash,
  type QRPayloadInput,
} from "../../api/src/services/merkle-signing.js";

interface Fixture {
  name: string;
  description: string;
  payload: {
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
  };
}

const FIXTURES: Fixture[] = [
  {
    name: "minimal_no_location",
    description: "Smallest valid payload — URL content, no location, far-future expiry",
    payload: {
      algVersion: ALG_VERSION_POLICY.hybrid,
      token: "abc123",
      tenantId: "tnt_test",
      contentType: "url",
      destinationUrl: "https://example.com/x",
      contentHashHex: "",
      lat: null,
      lng: null,
      radiusM: null,
      expiresAt: "2027-01-01T00:00:00.000Z",
      nonce: "deadbeef",
    },
  },
  {
    name: "url_with_location",
    description: "URL QR in NYC with a 100m radius",
    payload: {
      algVersion: ALG_VERSION_POLICY.hybrid,
      token: "xK9m2pQ7",
      tenantId: "tnt_acme",
      contentType: "url",
      destinationUrl: "https://acme.example/promo",
      contentHashHex: "",
      lat: 40.7128,
      lng: -74.006,
      radiusM: 100,
      expiresAt: "2027-01-01T00:00:00.000Z",
      nonce: "0000000000000000000000000000000000000000000000000000000000000001",
    },
  },
  {
    name: "non_expiring_empty_string_sentinel",
    description: "Non-expiring code — expiresAt uses the empty-string sentinel",
    payload: {
      algVersion: ALG_VERSION_POLICY.hybrid,
      token: "perma01",
      tenantId: "tnt_perma",
      contentType: "url",
      destinationUrl: "https://perma.example/",
      contentHashHex: "",
      lat: null,
      lng: null,
      radiusM: null,
      expiresAt: "",
      nonce: "00",
    },
  },
  {
    name: "vcard_content_qr",
    description: "Content QR (vCard) — destHash commits to the content hash, not the URL",
    payload: {
      algVersion: ALG_VERSION_POLICY.hybrid,
      token: "vcd_001",
      tenantId: "tnt_vcd",
      contentType: "vcard",
      destinationUrl: "https://qrauth.io/v/vcd_001",
      // Pinned pretend content hash — a real contentHash is SHA256(stableStringify(content)).
      contentHashHex: "3b5f2a1c7d9e4f80112233445566778899aabbccddeeff00112233445566aabb",
      lat: null,
      lng: null,
      radiusM: null,
      expiresAt: "",
      nonce: "feedface",
    },
  },
  {
    name: "southern_hemisphere_location",
    description: "Sydney coordinates, short expiry",
    payload: {
      algVersion: ALG_VERSION_POLICY.hybrid,
      token: "tok_AU01",
      tenantId: "tnt_au",
      contentType: "url",
      destinationUrl: "https://example.au/welcome",
      contentHashHex: "",
      lat: -33.8688,
      lng: 151.2093,
      radiusM: 50,
      expiresAt: "2026-06-15T12:30:00.000Z",
      nonce: "cafebabecafebabe",
    },
  },
  {
    name: "decimal_precision_check",
    description: "Lat/lng at 7-decimal precision to lock in toFixed formatting",
    payload: {
      algVersion: ALG_VERSION_POLICY.hybrid,
      token: "precise",
      tenantId: "tnt_pre",
      contentType: "url",
      destinationUrl: "https://example.com/precise",
      contentHashHex: "",
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
    payload: Fixture["payload"];
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

async function main() {
  const vectors: VectorOutput["vectors"] = [];

  for (const fixture of FIXTURES) {
    const destHash = await computeDestHash(
      fixture.payload.contentType,
      fixture.payload.destinationUrl,
      fixture.payload.contentHashHex,
    );
    const geoHash = await canonicalGeoHash(
      fixture.payload.lat,
      fixture.payload.lng,
      fixture.payload.radiusM,
    );
    const canonicalCore = canonicalizeCore({
      algVersion: fixture.payload.algVersion,
      token: fixture.payload.token,
      tenantId: fixture.payload.tenantId,
      destHash,
      geoHash,
      expiresAt: fixture.payload.expiresAt,
    });
    const canonicalCoreSha3 = createHash("sha3-256")
      .update(canonicalCore, "utf8")
      .digest("hex");
    const merkleLeaf = canonicalizeMerkleLeaf({
      algVersion: fixture.payload.algVersion,
      token: fixture.payload.token,
      tenantId: fixture.payload.tenantId,
      destHash,
      geoHash,
      expiresAt: fixture.payload.expiresAt,
      nonce: fixture.payload.nonce,
    });

    const merklePayload: QRPayloadInput = {
      algVersion: fixture.payload.algVersion,
      token: fixture.payload.token,
      tenantId: fixture.payload.tenantId,
      contentType: fixture.payload.contentType,
      destinationUrl: fixture.payload.destinationUrl,
      contentHashHex: fixture.payload.contentHashHex,
      lat: fixture.payload.lat,
      lng: fixture.payload.lng,
      radiusM: fixture.payload.radiusM,
      expiresAt: fixture.payload.expiresAt,
    };
    const leafHash = await computeLeafHash(merklePayload, fixture.payload.nonce);

    vectors.push({
      name: fixture.name,
      description: fixture.description,
      payload: fixture.payload,
      expected: { destHash, geoHash, canonicalCore, canonicalCoreSha3, merkleLeaf, leafHash },
    });
  }

  const output: VectorOutput = {
    protocolVersion: "qrva-v2",
    generatedAt: new Date().toISOString(),
    notes: [
      "Cross-language test vectors for the QRVA unified canonical form (AUDIT-FINDING-011).",
      "Core shape: algVersion|token|tenantId|destHash|geoHash|expiresAt",
      "Merkle leaf: core | nonce",
      "destHash is content-type aware via computeDestHash — URL QRs hash the URL, content QRs hash the contentHashHex.",
      "geoHash is canonicalGeoHash(lat,lng,radius) with 7-decimal precision; unbound locations use the literal 'none'.",
      "Non-expiring codes use the empty string '' for expiresAt.",
      "Regenerate with: npx tsx packages/protocol-tests/scripts/generate-vectors.ts",
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
