import "./test-setup.js";
import { describe, it, expect, beforeAll } from "vitest";
import { mkdtempSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createSign } from "node:crypto";

import {
  HybridSigningService,
} from "../../api/src/services/hybrid-signing.js";
import { SigningService } from "../../api/src/services/signing.js";
import { BatchSigner } from "../../api/src/services/batch-signer.js";
import { LocalSlhDsaSigner } from "../../api/src/services/slhdsa-signer/index.js";
import type { EcdsaSigner } from "../../api/src/services/ecdsa-signer/index.js";
import { slhDsaGenerateKeyPair } from "../../api/src/services/slhdsa-adapter.js";
import { generateKeyPair } from "../../api/src/lib/crypto.js";
import { config } from "../../api/src/lib/config.js";
import { encryptAtRest } from "../../api/src/lib/key-at-rest.js";

/**
 * AUDIT-FINDING-016 moved ECDSA signing behind the `EcdsaSigner` abstraction
 * and the on-disk format to `.ecdsa.enc` encrypted envelopes. The hybrid
 * test used to drop a plaintext `.pem` in a tmp dir and rely on the
 * default `LocalEcdsaSigner` to read it; that path is gone. AUDIT-2 N-7
 * re-baselines the test against the current shape by injecting an
 * in-memory `EcdsaSigner` into `SigningService(prisma, ecdsaSigner?)` so
 * the test never touches disk for ECDSA. The injected signer applies the
 * AUDIT-2 N-2 `qrauth:ecdsa-canonical:v1:` domain-separation prefix
 * byte-for-byte with `LocalEcdsaSigner`, so any drift is caught by
 * `ecdsa-signer-roundtrip.test.ts` rather than this file.
 */
class InMemoryEcdsaSigner implements EcdsaSigner {
  constructor(private readonly privateKeyPem: string) {}

  async signCanonical(_keyId: string, canonical: string): Promise<string> {
    const signer = createSign("SHA256");
    signer.update("qrauth:ecdsa-canonical:v1:" + canonical, "utf8");
    signer.end();
    return signer.sign(this.privateKeyPem, "base64");
  }
}

/**
 * Full hybrid signing round-trip without standing up Postgres.
 *
 * The HybridSigningService normally talks to Prisma to persist SignedBatch
 * rows and look them up at verification time. Here we hand it an in-memory
 * fake that captures writes to a Map and serves them back out — enough to
 * exercise the issue → verify flow including the SLH-DSA verify against the
 * stored public key.
 */

interface FakeSignedBatchRow {
  id: string;
  batchId: string;
  organizationId: string;
  signingKeyId: string;
  algVersion: string;
  merkleRoot: string;
  rootSignature: string;
  tokenCount: number;
  issuedAt: Date;
  createdAt: Date;
  signingKey: {
    id: string;
    keyId: string;
    slhdsaPublicKey: string | null;
  };
}

class FakePrisma {
  signedBatches = new Map<string, FakeSignedBatchRow>();
  signingKeyByDbId = new Map<string, { id: string; keyId: string; slhdsaPublicKey: string | null }>();

  signedBatch = {
    create: async ({ data }: { data: any }) => {
      const sk = this.signingKeyByDbId.get(data.signingKeyId);
      if (!sk) throw new Error("FakePrisma: unknown signingKey");
      const row: FakeSignedBatchRow = {
        id: `b_${this.signedBatches.size}`,
        batchId: data.batchId,
        organizationId: data.organizationId,
        signingKeyId: data.signingKeyId,
        algVersion: data.algVersion,
        merkleRoot: data.merkleRoot,
        rootSignature: data.rootSignature,
        tokenCount: data.tokenCount,
        issuedAt: data.issuedAt,
        createdAt: new Date(),
        signingKey: { ...sk },
      };
      this.signedBatches.set(row.batchId, row);
      return row;
    },
    findUnique: async ({ where, include }: any) => {
      void include;
      return this.signedBatches.get(where.batchId) ?? null;
    },
  };

  signingKey = {
    findUnique: async ({ where }: any) => {
      for (const sk of this.signingKeyByDbId.values()) {
        if (sk.keyId === where.keyId) {
          return { ...sk, slhdsaPublicKey: sk.slhdsaPublicKey };
        }
      }
      return null;
    },
  };
}

let prisma: FakePrisma;
let signingService: SigningService;
let hybrid: HybridSigningService;
let signingKeyDbId: string;
let signingKeyId: string;

beforeAll(async () => {
  // Point ECDSA + SLH-DSA key storage at an isolated tmp dir so this test
  // never touches a real deployment's keys/ folder.
  const tmpKeysDir = mkdtempSync(join(tmpdir(), "qrauth-hybrid-test-"));
  mkdirSync(tmpKeysDir, { recursive: true });
  // SigningService reads `config.kms.ecdsaPrivateKeyPath` lazily; mutate it
  // before any signing call lands on disk.
  (config.kms as { ecdsaPrivateKeyPath: string }).ecdsaPrivateKeyPath = tmpKeysDir;

  prisma = new FakePrisma();

  // Mint an ECDSA + SLH-DSA pair and write them to the tmp keys dir, so the
  // SigningService finds the PEM and SLH-DSA file when asked. We bypass
  // SigningService.createKeyPair (which wants a real Prisma) and stage the
  // files ourselves.
  const ecdsa = await generateKeyPair();
  signingKeyId = ecdsa.keyId;
  writeFileSync(
    join(tmpKeysDir, `${ecdsa.keyId}.ecdsa.enc`),
    encryptAtRest(Buffer.from(ecdsa.privateKey, "utf8")),
    { mode: 0o600 },
  );
  const slh = await slhDsaGenerateKeyPair();
  // AUDIT-FINDING-016: production writes `${keyId}.slhdsa.enc` encrypted
  // envelopes. Match that here so `loadSlhDsaKeyPair` can decrypt.
  writeFileSync(
    join(tmpKeysDir, `${ecdsa.keyId}.slhdsa.enc`),
    encryptAtRest(slh.privateKey),
    { mode: 0o600 },
  );

  signingKeyDbId = "sk_test";
  prisma.signingKeyByDbId.set(signingKeyDbId, {
    id: signingKeyDbId,
    keyId: signingKeyId,
    slhdsaPublicKey: slh.publicKey.toString("base64"),
  });

  signingService = new SigningService(
    prisma as unknown as never,
    new InMemoryEcdsaSigner(ecdsa.privateKey),
  );
  // Use a tight batch window so the test runs quickly — every enqueue
  // immediately fills a batch of one and flushes.
  const batchSigner = new BatchSigner(
    prisma as unknown as never,
    new LocalSlhDsaSigner(signingService),
    { maxBatchSize: 1, maxWaitMs: 1 },
  );
  hybrid = new HybridSigningService(
    prisma as unknown as never,
    signingService,
    batchSigner,
  );
});

describe("HybridSigningService end-to-end", () => {
  it("issues a hybrid signature whose Merkle leg verifies", async () => {
    const result = await hybrid.signSingleQR({
      organizationId: "org_acme",
      signingKeyDbId,
      signingKeyId,
      token: "tok_abc",
      contentType: "url",
      destinationUrl: "https://acme.example/p",
      contentHashHex: "",
      expiresAt: "",
      lat: 40.7128,
      lng: -74.006,
      radiusM: 100,
    });

    expect(result.algVersion).toBe("hybrid-ecdsa-slhdsa-v1");
    expect(result.ecdsaSignature).toMatch(/^[A-Za-z0-9+/=]+$/);
    expect(result.merkleRoot).toMatch(/^[0-9a-f]{64}$/);
    expect(result.leafIndex).toBe(0);

    const verify = await hybrid.verifyHybridLeg({
      leafHash: result.leafHash,
      merklePath: result.merklePath,
      batchId: result.batchId,
    });
    expect(verify.ok).toBe(true);
  });

  it("rejects a tampered leaf hash", async () => {
    const result = await hybrid.signSingleQR({
      organizationId: "org_acme",
      signingKeyDbId,
      signingKeyId,
      token: "tok_def",
      contentType: "url",
      destinationUrl: "https://acme.example/q",
      contentHashHex: "",
      expiresAt: "",
      lat: null,
      lng: null,
      radiusM: null,
    });

    const verify = await hybrid.verifyHybridLeg({
      leafHash: "00".repeat(32),
      merklePath: result.merklePath,
      batchId: result.batchId,
    });
    expect(verify.ok).toBe(false);
    if (!verify.ok) expect(verify.reason).toBe("MERKLE_PROOF_INVALID");
  });

  it("rejects when batch is unknown", async () => {
    const verify = await hybrid.verifyHybridLeg({
      leafHash: "00".repeat(32),
      merklePath: [],
      batchId: "batch_does_not_exist",
    });
    expect(verify.ok).toBe(false);
    if (!verify.ok) expect(verify.reason).toBe("BATCH_NOT_FOUND");
  });
});
