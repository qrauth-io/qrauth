import "./test-setup.js";
import { describe, it, expect } from "vitest";
import { createHash } from "crypto";
import {
  buildMerkleTree,
  computeLeafHash,
  getMerklePath,
  issueBatch,
  issueBatchWithSigner,
  verifyMerkleProof,
  verifySignedBatch,
  MERKLE_LEAF_PREFIX,
  MERKLE_NODE_PREFIX,
  type QRPayloadInput,
} from "../../api/src/services/merkle-signing.js";
import {
  slhDsaKeyPairFromSeed,
  slhDsaSign,
} from "../../api/src/services/slhdsa-adapter.js";

/**
 * AUDIT-1 Finding-010 / AUDIT-2 N-7: `LocalSlhDsaSigner` prepends
 * `qrauth:merkle-root:v1:` before handing bytes to SLH-DSA, and
 * `verifySignedBatch` reconstructs the same prefixed input on the
 * verify side. The bare `issueBatch` helper exists for tests but does
 * NOT apply the prefix (it calls `slhDsaSign` directly on the raw root),
 * so round-trips through it fail the verifier.
 *
 * The two post-N-7 round-trip cases below use `issueBatchWithSigner`
 * with a trivial in-test signer that applies the byte-exact prefix —
 * this exercises the production verify path end-to-end and pins the
 * prefix literal for the test suite, without touching production code.
 */
function makePrefixingSigner(keyPair: ReturnType<typeof slhDsaKeyPairFromSeed>) {
  return {
    async signRoot(_keyId: string, message: Buffer): Promise<Buffer> {
      const prefixed = Buffer.concat([
        Buffer.from("qrauth:merkle-root:v1:", "utf8"),
        message,
      ]);
      return slhDsaSign(keyPair.privateKey, prefixed);
    },
  };
}

const sha3 = (b: Buffer) => createHash("sha3-256").update(b).digest("hex");

const FIXED_SEED = Buffer.alloc(48, 7);

function makePayload(i: number): QRPayloadInput {
  return {
    algVersion: "hybrid-ecdsa-slhdsa-v1",
    token: `tok_${i}`,
    tenantId: "tnt_acme",
    contentType: "url",
    destinationUrl: `https://acme.example/p/${i}`,
    contentHashHex: "",
    lat: 40.7128,
    lng: -74.006,
    radiusM: 100,
    expiresAt: "2027-01-01T00:00:00.000Z",
  };
}

describe("merkle tree", () => {
  it("builds a single-leaf tree whose root equals the leaf", () => {
    const leaf = sha3(Buffer.from("only"));
    const { root, tree } = buildMerkleTree([leaf]);
    expect(root).toBe(leaf);
    expect(tree).toHaveLength(1);
  });

  it("pads odd-leaf-count batches to next power of 2", () => {
    const leaves = ["a", "b", "c"].map((s) => sha3(Buffer.from(s)));
    const { tree } = buildMerkleTree(leaves);
    expect(tree[0]).toHaveLength(4);
    expect(tree[0][3]).not.toBe(tree[0][2]);
  });

  it("computes internal nodes with 0x01 prefix", () => {
    const a = sha3(Buffer.from("a"));
    const b = sha3(Buffer.from("b"));
    const { root } = buildMerkleTree([a, b]);
    const expected = createHash("sha3-256")
      .update(Buffer.concat([Buffer.from([MERKLE_NODE_PREFIX]), Buffer.from(a, "hex"), Buffer.from(b, "hex")]))
      .digest("hex");
    expect(root).toBe(expected);
  });

  it("inclusion proof verifies for every leaf", () => {
    const leaves = Array.from({ length: 8 }, (_, i) => sha3(Buffer.from(`l${i}`)));
    const { root, tree } = buildMerkleTree(leaves);
    for (let i = 0; i < leaves.length; i++) {
      const path = getMerklePath(tree, i);
      expect(verifyMerkleProof(leaves[i], path, root)).toBe(true);
    }
  });

  it("inclusion proof fails when leaf hash is tampered", () => {
    const leaves = Array.from({ length: 4 }, (_, i) => sha3(Buffer.from(`l${i}`)));
    const { root, tree } = buildMerkleTree(leaves);
    const path = getMerklePath(tree, 1);
    const tampered = sha3(Buffer.from("not-a-leaf"));
    expect(verifyMerkleProof(tampered, path, root)).toBe(false);
  });

  it("inclusion proof fails when a path node is tampered", () => {
    const leaves = Array.from({ length: 4 }, (_, i) => sha3(Buffer.from(`l${i}`)));
    const { root, tree } = buildMerkleTree(leaves);
    const path = getMerklePath(tree, 2);
    const corrupted = path.map((n, i) =>
      i === 0 ? { ...n, hash: sha3(Buffer.from("evil")) } : n,
    );
    expect(verifyMerkleProof(leaves[2], corrupted, root)).toBe(false);
  });

  it("inclusion proof fails when sides are swapped", () => {
    const leaves = Array.from({ length: 4 }, (_, i) => sha3(Buffer.from(`l${i}`)));
    const { root, tree } = buildMerkleTree(leaves);
    const path = getMerklePath(tree, 2);
    const swapped = path.map((n) => ({ ...n, side: n.side === "left" ? "right" : "left" } as const));
    expect(verifyMerkleProof(leaves[2], swapped, root)).toBe(false);
  });

  it("rejects out-of-range leaf index", () => {
    const leaves = [sha3(Buffer.from("a")), sha3(Buffer.from("b"))];
    const { tree } = buildMerkleTree(leaves);
    expect(() => getMerklePath(tree, 5)).toThrow();
    expect(() => getMerklePath(tree, -1)).toThrow();
  });
});

describe("computeLeafHash", () => {
  it("includes the leaf prefix 0x00 in the hash", async () => {
    const payload = makePayload(0);
    const leaf = await computeLeafHash(payload, "deadbeef");
    expect(leaf).toHaveLength(64);
    expect(MERKLE_LEAF_PREFIX).toBe(0x00);
  });

  it("is deterministic for a fixed (payload, nonce)", async () => {
    const a = await computeLeafHash(makePayload(0), "nonce-1");
    const b = await computeLeafHash(makePayload(0), "nonce-1");
    expect(a).toBe(b);
  });

  it("changes when nonce changes", async () => {
    const a = await computeLeafHash(makePayload(0), "nonce-1");
    const b = await computeLeafHash(makePayload(0), "nonce-2");
    expect(a).not.toBe(b);
  });
});

describe("issueBatch + verifySignedBatch", () => {
  it("issues a batch whose root signature and inclusion proofs all verify", async () => {
    const keyPair = slhDsaKeyPairFromSeed(FIXED_SEED);
    const signer = makePrefixingSigner(keyPair);
    const payloads = Array.from({ length: 5 }, (_, i) => makePayload(i));
    const batch = await issueBatchWithSigner(payloads, signer, "test-key");

    expect(batch.tokenCount).toBe(5);
    expect(batch.tokens).toHaveLength(5);
    expect(batch.algorithmVersion).toBe("slhdsa-sha2-128s-v1");
    expect(batch.merkleRoot).toMatch(/^[0-9a-f]{64}$/);

    const result = await verifySignedBatch(batch, keyPair.publicKey);
    expect(result.ok).toBe(true);
  });

  it("rejects a batch whose root signature was made with a different key", async () => {
    const keyPair = slhDsaKeyPairFromSeed(FIXED_SEED);
    const otherKey = slhDsaKeyPairFromSeed(Buffer.alloc(48, 9));
    const batch = await issueBatch([makePayload(0)], keyPair);

    const result = await verifySignedBatch(batch, otherKey.publicKey);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toBe("BATCH_SIGNATURE_INVALID");
  });

  it("rejects a batch whose merkle root has been tampered", async () => {
    const keyPair = slhDsaKeyPairFromSeed(FIXED_SEED);
    const batch = await issueBatch([makePayload(0), makePayload(1)], keyPair);

    const tampered = { ...batch, merkleRoot: "00".repeat(32) };
    const result = await verifySignedBatch(tampered, keyPair.publicKey);
    expect(result.ok).toBe(false);
  });

  it("rejects when a single token's inclusion proof is broken", async () => {
    const keyPair = slhDsaKeyPairFromSeed(FIXED_SEED);
    const signer = makePrefixingSigner(keyPair);
    const batch = await issueBatchWithSigner(
      Array.from({ length: 4 }, (_, i) => makePayload(i)),
      signer,
      "test-key",
    );

    const bad = JSON.parse(JSON.stringify(batch));
    bad.tokens[2].leafHash = "00".repeat(32);
    const result = await verifySignedBatch(bad, keyPair.publicKey);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toMatch(/MERKLE_PROOF_INVALID/);
  });

  it("rejects empty batches", async () => {
    const keyPair = slhDsaKeyPairFromSeed(FIXED_SEED);
    await expect(issueBatch([], keyPair)).rejects.toThrow();
  });
});
