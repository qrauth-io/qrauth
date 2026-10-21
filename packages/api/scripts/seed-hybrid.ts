/**
 * Seed-only helpers that issue genuinely hybrid QR rows: one Merkle batch per
 * seed run, its root signed in-process with an SLH-DSA key that exists only
 * in memory for the duration of the seed.
 *
 * Verification requires every hybrid row to carry a batch id, leaf hash,
 * nonce and inclusion path (ALGORITHM.md §6.4), so seeded rows must go
 * through the same Merkle construction as live issuance. The batch root is
 * signed over the same domain-separated message the signer uses.
 *
 * Dev and seed tooling only. Never import from server code.
 */
import type { PrismaClient, SigningKey } from '@prisma/client';
import {
  ALGORITHM_VERSION_HYBRID,
  issueBatchWithSigner,
  type MerkleNode,
  type QRPayloadInput,
} from '../src/services/merkle-signing.js';
import {
  SLHDSA_PARAM_SET,
  slhDsaGenerateKeyPair,
  slhDsaSign,
  type SlhDsaKeyPair,
} from '../src/services/slhdsa-adapter.js';

const MERKLE_ROOT_DOMAIN = Buffer.from('qrauth:merkle-root:v1:', 'utf8');

export interface SeedMerkleFields {
  algVersion: typeof ALGORITHM_VERSION_HYBRID;
  merkleBatchId: string;
  merkleLeafIndex: number;
  merkleLeafHash: string;
  merkleLeafNonce: string;
  merklePath: MerkleNode[];
}

/**
 * Attach a fresh in-memory SLH-DSA keypair to a seed signing key and store
 * its public half on the row. Refuses a key that already has SLH-DSA
 * material, because the seed cannot sign with a secret it does not hold.
 */
export async function attachSeedSlhDsaKey(
  prisma: PrismaClient,
  signingKey: SigningKey,
): Promise<SlhDsaKeyPair> {
  if (signingKey.slhdsaPublicKey) {
    throw new Error(
      `seed: signing key ${signingKey.keyId} already has SLH-DSA material the seed ` +
        'cannot sign with. Reset the dev database or issue QRs through the API instead.',
    );
  }
  const pair = await slhDsaGenerateKeyPair();
  await prisma.signingKey.update({
    where: { id: signingKey.id },
    data: {
      slhdsaPublicKey: pair.publicKey.toString('base64'),
      slhdsaAlgorithm: SLHDSA_PARAM_SET,
    },
  });
  return pair;
}

/** Signs a Merkle root for `keyId`; the signer applies the root domain prefix. */
export type SeedRootSigner = (keyId: string, root: Buffer) => Promise<Buffer>;

/**
 * In-process root signer for a seed-held SLH-DSA key. Applies the same
 * `qrauth:merkle-root:v1:` prefix the signer service applies.
 */
export function inMemoryRootSigner(pair: SlhDsaKeyPair): SeedRootSigner {
  return async (_keyId, root) =>
    slhDsaSign(pair.privateKey, Buffer.concat([MERKLE_ROOT_DOMAIN, root]));
}

/**
 * Build one Merkle batch over `payloads`, sign its root with `signRoot`,
 * persist the `SignedBatch` row, and return the per-row Merkle fields in
 * input order.
 */
export async function issueSeedBatch(
  prisma: PrismaClient,
  args: {
    organizationId: string;
    signingKeyDbId: string;
    signingKeyId: string;
    signRoot: SeedRootSigner;
    payloads: QRPayloadInput[];
  },
): Promise<SeedMerkleFields[]> {
  const batch = await issueBatchWithSigner(
    args.payloads,
    { signRoot: args.signRoot },
    args.signingKeyId,
  );

  await prisma.signedBatch.create({
    data: {
      batchId: batch.batchId,
      organizationId: args.organizationId,
      signingKeyId: args.signingKeyDbId,
      algVersion: ALGORITHM_VERSION_HYBRID,
      merkleRoot: batch.merkleRoot,
      rootSignature: batch.rootSignature,
      tokenCount: batch.tokenCount,
      issuedAt: new Date(batch.issuedAt),
    },
  });

  return batch.tokens.map((t) => ({
    algVersion: ALGORITHM_VERSION_HYBRID,
    merkleBatchId: batch.batchId,
    merkleLeafIndex: t.leafIndex,
    merkleLeafHash: t.leafHash,
    merkleLeafNonce: t.nonce,
    merklePath: t.merklePath,
  }));
}
