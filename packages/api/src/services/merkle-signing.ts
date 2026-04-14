import { createHash, timingSafeEqual as nodeTimingSafeEqual } from "crypto";
import {
  CANONICAL_FIELD_SEPARATOR,
  canonicalGeoHash,
  canonicalizePayloadSync,
  type CanonicalQRPayload,
} from "@qrauth/shared";
import { generateSecureEntropy } from "../lib/entropy.js";
import { slhDsaSign, slhDsaVerify, type SlhDsaKeyPair } from "./slhdsa-adapter.js";

/**
 * Merkle-based batch signing service (ALGORITHM.md §6).
 *
 * Per-QR asymmetric signing is gone. Instead:
 *   1. Each QR contributes a SHA3-256 leaf hash over its canonical payload.
 *   2. Leaves are arranged into a binary Merkle tree with domain-separated
 *      hashing (0x00 prefix on leaves, 0x01 on internal nodes).
 *   3. The root is signed once with SLH-DSA, offline / air-gapped in
 *      production — see ALGORITHM.md §13.1 for the signing-machine workflow.
 *   4. Verification at the edge is two cheap hash chains plus one cached
 *      SLH-DSA verify per batch. No per-QR asymmetric work.
 *
 * Nothing in this module touches the existing `signing.ts` ECDSA service. The
 * cutover happens in Phase 1 hybrid mode after the protocol-test suite is
 * green and the air-gapped signing workflow is in place.
 */

export const MERKLE_LEAF_PREFIX = 0x00;
export const MERKLE_NODE_PREFIX = 0x01;
export const ALGORITHM_VERSION_HYBRID = "hybrid-ecdsa-slhdsa-v1" as const;
export const ALGORITHM_VERSION_PQC = "slhdsa-sha2-128s-v1" as const;

export interface QRPayloadInput {
  token: string;
  tenantId: string;
  destinationUrl: string;
  lat: number | null;
  lng: number | null;
  radiusM: number | null;
  expiresAt: Date;
  metadata?: Record<string, unknown>;
}

export interface MerkleNode {
  hash: string;
  side: "left" | "right";
}

export interface SignedToken {
  token: string;
  leafHash: string;
  leafIndex: number;
  nonce: string;
  merklePath: MerkleNode[];
}

export interface SignedBatch {
  batchId: string;
  algorithmVersion: typeof ALGORITHM_VERSION_PQC;
  issuedAt: string;
  merkleRoot: string;
  rootSignature: string;
  tokenCount: number;
  tokens: SignedToken[];
}

/**
 * Build and sign a batch of QR payloads.
 *
 * The order of operations matters for forensic reconstruction: we materialize
 * leaves first, then the tree, then sign the root. If SLH-DSA signing fails
 * the entire batch is discarded — partial state never reaches the database.
 *
 * This variant takes the keypair directly. It's used by the protocol test
 * suite and any path that wants to sign in-process without going through a
 * `SlhDsaSigner`. Production code paths use `issueBatchWithSigner` so the
 * private key never has to be loaded into the API server's address space.
 */
export async function issueBatch(
  payloads: QRPayloadInput[],
  keyPair: SlhDsaKeyPair,
  now: Date = new Date(),
): Promise<SignedBatch> {
  return issueBatchInternal(payloads, async (root) => slhDsaSign(keyPair.privateKey, root), now);
}

/**
 * Build and sign a batch using a `SlhDsaSigner`. The signer is opaque —
 * it may be local-disk, HTTP-to-air-gapped-host, KMS, or HSM. The hot
 * path inside this function only ever sees a Merkle root and a signature
 * coming back from `signer.signRoot(keyId, root)`.
 *
 * This is the production-recommended variant once the standalone signer
 * service is deployed. See ALGORITHM.md §13.1.
 */
export async function issueBatchWithSigner(
  payloads: QRPayloadInput[],
  signer: { signRoot(keyId: string, message: Buffer): Promise<Buffer> },
  keyId: string,
  now: Date = new Date(),
): Promise<SignedBatch> {
  return issueBatchInternal(payloads, (root) => signer.signRoot(keyId, root), now);
}

async function issueBatchInternal(
  payloads: QRPayloadInput[],
  sign: (rootBytes: Buffer) => Promise<Buffer>,
  now: Date,
): Promise<SignedBatch> {
  if (payloads.length === 0) {
    throw new Error("issueBatch: cannot issue an empty batch");
  }

  const batchId = (await generateSecureEntropy(16)).toString("hex");

  const leaves: string[] = new Array(payloads.length);
  const nonces: string[] = new Array(payloads.length);

  for (let i = 0; i < payloads.length; i++) {
    const nonce = (await generateSecureEntropy(32)).toString("hex");
    nonces[i] = nonce;
    leaves[i] = await computeLeafHash(payloads[i], nonce);
  }

  const { root, tree } = buildMerkleTree(leaves);

  const rootSignature = await sign(Buffer.from(root, "hex"));

  const tokens: SignedToken[] = payloads.map((p, i) => ({
    token: p.token,
    leafHash: leaves[i],
    leafIndex: i,
    nonce: nonces[i],
    merklePath: getMerklePath(tree, i),
  }));

  return {
    batchId,
    algorithmVersion: ALGORITHM_VERSION_PQC,
    issuedAt: now.toISOString(),
    merkleRoot: root,
    rootSignature: rootSignature.toString("base64"),
    tokenCount: payloads.length,
    tokens,
  };
}

/**
 * Compute the SHA3-256 leaf hash for a single QR payload + nonce.
 *
 * Two-step process:
 *   1. Build the canonical payload string (pure data — same as Python/Node SDKs).
 *   2. Hash with the leaf prefix `0x00` to domain-separate from internal nodes
 *      (defends against second-preimage attacks where an internal node hash
 *      happens to collide with a leaf hash).
 */
export async function computeLeafHash(
  payload: QRPayloadInput,
  nonce: string,
): Promise<string> {
  const destinationHash = sha3_256Hex(payload.destinationUrl);
  const geoHash = await canonicalGeoHash(payload.lat, payload.lng, payload.radiusM);

  const canonical = canonicalizePayloadSync({
    token: payload.token,
    tenantId: payload.tenantId,
    destinationHash,
    geoHash,
    expiresAt: payload.expiresAt.toISOString(),
    nonce,
  });

  return sha3_256HexPrefixed(MERKLE_LEAF_PREFIX, canonical);
}

/**
 * Build a binary Merkle tree, padding to the next power of 2 with
 * deterministic, distinguishable padding leaves so duplicate-leaf attacks fail.
 *
 * `tree[0]` holds the (padded) leaves; `tree[level]` holds the nodes at depth
 * `level` from the bottom. `tree.at(-1)` is `[root]`.
 */
export function buildMerkleTree(leaves: string[]): { root: string; tree: string[][] } {
  if (leaves.length === 0) throw new Error("buildMerkleTree: empty leaf set");

  const size = nextPowerOf2(leaves.length);
  const padded = leaves.slice();
  while (padded.length < size) {
    // Padding leaves include their index so each one is unique. Without this,
    // two distinct trees with different real-leaf counts could produce
    // colliding roots after padding.
    padded.push(sha3_256HexPrefixed(MERKLE_LEAF_PREFIX, `qrauth-pad:${padded.length}`));
  }

  const tree: string[][] = [padded];
  let current = padded;

  while (current.length > 1) {
    const next: string[] = new Array(current.length / 2);
    for (let i = 0; i < current.length; i += 2) {
      next[i / 2] = hashInternalNode(current[i], current[i + 1]);
    }
    tree.push(next);
    current = next;
  }

  return { root: current[0], tree };
}

/**
 * Build the inclusion proof for the leaf at `leafIndex`.
 *
 * The proof is the sequence of sibling hashes encountered when walking from
 * the leaf up to the root, each tagged with which side it sits on. Verifiers
 * use the side tag to know which order to concatenate at each level.
 */
export function getMerklePath(tree: string[][], leafIndex: number): MerkleNode[] {
  if (leafIndex < 0 || leafIndex >= tree[0].length) {
    throw new Error(`getMerklePath: leafIndex ${leafIndex} out of range`);
  }

  const path: MerkleNode[] = [];
  let index = leafIndex;
  for (let level = 0; level < tree.length - 1; level++) {
    const isLeft = index % 2 === 0;
    const siblingIndex = isLeft ? index + 1 : index - 1;
    path.push({
      hash: tree[level][siblingIndex],
      side: isLeft ? "right" : "left",
    });
    index = Math.floor(index / 2);
  }
  return path;
}

/**
 * Walk an inclusion proof from a leaf hash up to a claimed root. Constant-time
 * comparison at the end. Side tags are required: a path that mixes them up
 * deterministically fails (no fallback to other orderings).
 */
export function verifyMerkleProof(
  leafHash: string,
  merklePath: MerkleNode[],
  claimedRoot: string,
): boolean {
  let current = leafHash;
  for (const node of merklePath) {
    current =
      node.side === "right"
        ? hashInternalNode(current, node.hash)
        : hashInternalNode(node.hash, current);
  }
  return constantTimeHexEqual(current, claimedRoot);
}

/**
 * Verify a complete signed batch end-to-end:
 *   - SLH-DSA root signature against the supplied tenant public key.
 *   - Every token's inclusion proof against the signed root.
 *
 * Returns the first failure reason, or `null` on success.
 */
export async function verifySignedBatch(
  batch: SignedBatch,
  tenantPublicKey: Buffer,
): Promise<{ ok: true } | { ok: false; reason: string }> {
  const rootBuf = Buffer.from(batch.merkleRoot, "hex");
  const sigBuf = Buffer.from(batch.rootSignature, "base64");

  const sigOk = await slhDsaVerify(tenantPublicKey, rootBuf, sigBuf);
  if (!sigOk) return { ok: false, reason: "BATCH_SIGNATURE_INVALID" };

  for (const token of batch.tokens) {
    const ok = verifyMerkleProof(token.leafHash, token.merklePath, batch.merkleRoot);
    if (!ok) return { ok: false, reason: `MERKLE_PROOF_INVALID:${token.token}` };
  }

  return { ok: true };
}

function hashInternalNode(left: string, right: string): string {
  // Domain separation: 0x01 || left || right, all bytes (not hex-string concat).
  const buf = Buffer.concat([
    Buffer.from([MERKLE_NODE_PREFIX]),
    Buffer.from(left, "hex"),
    Buffer.from(right, "hex"),
  ]);
  return createHash("sha3-256").update(buf).digest("hex");
}

function sha3_256Hex(input: string): string {
  return createHash("sha3-256").update(input, "utf8").digest("hex");
}

function sha3_256HexPrefixed(prefix: number, input: string): string {
  return createHash("sha3-256")
    .update(Buffer.concat([Buffer.from([prefix]), Buffer.from(input, "utf8")]))
    .digest("hex");
}

function nextPowerOf2(n: number): number {
  if (n <= 1) return 1;
  return 2 ** Math.ceil(Math.log2(n));
}

function constantTimeHexEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  const ba = Buffer.from(a, "hex");
  const bb = Buffer.from(b, "hex");
  if (ba.length !== bb.length) return false;
  return nodeTimingSafeEqual(ba, bb);
}

// Re-export for protocol-tests so they can build canonical strings without
// reaching across packages for internal helpers.
export { CANONICAL_FIELD_SEPARATOR, type CanonicalQRPayload };
