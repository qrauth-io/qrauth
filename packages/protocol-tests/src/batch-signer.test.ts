import { describe, it, expect, beforeAll } from "vitest";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { BatchSigner } from "../../api/src/services/batch-signer.js";
import { LocalSlhDsaSigner } from "../../api/src/services/slhdsa-signer/index.js";
import { SigningService } from "../../api/src/services/signing.js";
import { slhDsaGenerateKeyPair } from "../../api/src/services/slhdsa-adapter.js";
import { generateKeyPair } from "../../api/src/lib/crypto.js";
import { config } from "../../api/src/lib/config.js";
import {
  verifyMerkleProof,
  type QRPayloadInput,
} from "../../api/src/services/merkle-signing.js";
import { slhDsaVerify } from "../../api/src/services/slhdsa-adapter.js";

interface FakeSignedBatchRow {
  batchId: string;
  organizationId: string;
  signingKeyId: string;
  algVersion: string;
  merkleRoot: string;
  rootSignature: string;
  tokenCount: number;
  issuedAt: Date;
}

class FakePrisma {
  signedBatches = new Map<string, FakeSignedBatchRow>();
  signingKeys = new Map<string, { id: string; keyId: string; slhdsaPublicKey: string | null }>();

  signedBatch = {
    create: async ({ data }: { data: any }) => {
      const row: FakeSignedBatchRow = {
        batchId: data.batchId,
        organizationId: data.organizationId,
        signingKeyId: data.signingKeyId,
        algVersion: data.algVersion,
        merkleRoot: data.merkleRoot,
        rootSignature: data.rootSignature,
        tokenCount: data.tokenCount,
        issuedAt: data.issuedAt,
      };
      this.signedBatches.set(row.batchId, row);
      return row;
    },
  };

  signingKey = {
    findUnique: async ({ where }: any) => {
      for (const sk of this.signingKeys.values()) {
        if (sk.keyId === where.keyId) return sk;
      }
      return null;
    },
  };
}

let prisma: FakePrisma;
let signingService: SigningService;
let signingKeyDbId: string;
let signingKeyId: string;
let slhdsaPublicKeyB64: string;

beforeAll(async () => {
  const tmpKeysDir = mkdtempSync(join(tmpdir(), "qrauth-batch-test-"));
  (config.kms as { ecdsaPrivateKeyPath: string }).ecdsaPrivateKeyPath = tmpKeysDir;

  prisma = new FakePrisma();
  const ecdsa = await generateKeyPair();
  signingKeyId = ecdsa.keyId;
  writeFileSync(join(tmpKeysDir, `${ecdsa.keyId}.pem`), ecdsa.privateKey, { mode: 0o600 });
  const slh = await slhDsaGenerateKeyPair();
  writeFileSync(
    join(tmpKeysDir, `${ecdsa.keyId}.slhdsa.key`),
    slh.privateKey.toString("base64"),
    { mode: 0o600 },
  );

  signingKeyDbId = "sk_batch_test";
  slhdsaPublicKeyB64 = slh.publicKey.toString("base64");
  prisma.signingKeys.set(signingKeyDbId, {
    id: signingKeyDbId,
    keyId: signingKeyId,
    slhdsaPublicKey: slhdsaPublicKeyB64,
  });

  signingService = new SigningService(prisma as unknown as never);
});

function payload(i: number): QRPayloadInput {
  return {
    token: `tok_${i}`,
    tenantId: "org_acme",
    destinationUrl: `https://acme.example/p/${i}`,
    lat: null,
    lng: null,
    radiusM: null,
    expiresAt: new Date(0),
  };
}

describe("BatchSigner concurrency", () => {
  it("groups concurrent enqueues into a single batch when the size trigger fires", async () => {
    const batcher = new BatchSigner(prisma as unknown as never, new LocalSlhDsaSigner(signingService), {
      maxBatchSize: 8,
      maxWaitMs: 10_000, // very long, so only the size trigger flushes
    });

    const N = 8;
    const results = await Promise.all(
      Array.from({ length: N }, (_, i) =>
        batcher.enqueue({
          organizationId: "org_acme",
          signingKeyDbId,
          signingKeyId,
          payload: payload(i),
        }),
      ),
    );

    // Every result must share the same batchId / merkleRoot / rootSignature.
    const batchIds = new Set(results.map((r) => r.batchId));
    expect(batchIds.size).toBe(1);

    const merkleRoots = new Set(results.map((r) => r.merkleRoot));
    expect(merkleRoots.size).toBe(1);

    // Leaf indices 0..N-1, no duplicates.
    const leafIndices = results.map((r) => r.leafIndex).sort((a, b) => a - b);
    expect(leafIndices).toEqual([0, 1, 2, 3, 4, 5, 6, 7]);

    // Inclusion proof for every leaf must verify against the shared root.
    for (const r of results) {
      expect(verifyMerkleProof(r.leafHash, r.merklePath, r.merkleRoot)).toBe(true);
    }

    // Only one SignedBatch row was inserted.
    expect(prisma.signedBatches.size).toBe(1);
  });

  it("flushes via the time trigger when the queue stays below maxBatchSize", async () => {
    const batcher = new BatchSigner(prisma as unknown as never, new LocalSlhDsaSigner(signingService), {
      maxBatchSize: 1024,
      maxWaitMs: 50,
    });

    const before = prisma.signedBatches.size;
    const t0 = Date.now();
    const result = await batcher.enqueue({
      organizationId: "org_acme",
      signingKeyDbId,
      signingKeyId,
      payload: payload(100),
    });
    const elapsed = Date.now() - t0;

    expect(result.batchId).toBeDefined();
    // Wait window enforced — don't be too tight, SLH-DSA signing dominates.
    expect(elapsed).toBeGreaterThanOrEqual(45);
    expect(prisma.signedBatches.size).toBe(before + 1);
  });

  it("the resulting batch root signature verifies against the SLH-DSA pubkey", async () => {
    const batcher = new BatchSigner(prisma as unknown as never, new LocalSlhDsaSigner(signingService), {
      maxBatchSize: 4,
      maxWaitMs: 10_000,
    });

    const results = await Promise.all(
      Array.from({ length: 4 }, (_, i) =>
        batcher.enqueue({
          organizationId: "org_acme",
          signingKeyDbId,
          signingKeyId,
          payload: payload(200 + i),
        }),
      ),
    );

    const root = Buffer.from(results[0].merkleRoot, "hex");
    const sig = Buffer.from(results[0].rootSignature, "base64");
    const pub = Buffer.from(slhdsaPublicKeyB64, "base64");
    expect(await slhDsaVerify(pub, root, sig)).toBe(true);
  });

  it("flushAll drains pending items immediately", async () => {
    const batcher = new BatchSigner(prisma as unknown as never, new LocalSlhDsaSigner(signingService), {
      maxBatchSize: 1024,
      maxWaitMs: 60_000, // would normally never flush
    });

    const promise = batcher.enqueue({
      organizationId: "org_acme",
      signingKeyDbId,
      signingKeyId,
      payload: payload(300),
    });

    // Fire flushAll on the next tick — promise should resolve well under
    // the 60s wait window.
    setTimeout(() => batcher.flushAll(), 5);
    const result = await promise;
    expect(result.batchId).toBeDefined();
  });

  it("rejects new enqueues after flushAll closes the batcher", async () => {
    const batcher = new BatchSigner(prisma as unknown as never, new LocalSlhDsaSigner(signingService), {
      maxBatchSize: 1,
      maxWaitMs: 1,
    });
    await batcher.flushAll();
    await expect(
      batcher.enqueue({
        organizationId: "org_acme",
        signingKeyDbId,
        signingKeyId,
        payload: payload(400),
      }),
    ).rejects.toThrow(/closed/);
  });
});
