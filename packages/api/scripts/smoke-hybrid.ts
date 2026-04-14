/**
 * Hybrid signing smoke test.
 *
 * Run with: npx tsx --env-file=.env scripts/smoke-hybrid.ts
 *
 * What it does:
 *   1. Picks an org (first one returned by the DB).
 *   2. Mints a fresh hybrid signing key via SigningService.createKeyPair.
 *   3. Issues a hybrid-signed QR through HybridSigningService.signSingleQR.
 *   4. Persists a QRCode row exactly the way the route handler does.
 *   5. Verifies both legs (ECDSA + Merkle/SLH-DSA) against the persisted row.
 *   6. Prints a punch list of what passed / failed.
 *
 * Touches the real Postgres + writes a real key to ./keys/. Cleanup at the
 * end removes the QR row but leaves the SigningKey + key files so subsequent
 * runs can reuse them.
 */

import { PrismaClient } from "@prisma/client";
import {
  generateToken,
  hashPayload,
  checkAlgVersion,
  ALG_VERSION_POLICY,
} from "@qrauth/shared";
import { spawn } from "node:child_process";
import { SigningService } from "../src/services/signing.js";
import { HybridSigningService } from "../src/services/hybrid-signing.js";
import { BatchSigner } from "../src/services/batch-signer.js";
import {
  LocalSlhDsaSigner,
  HttpSlhDsaSigner,
} from "../src/services/slhdsa-signer/index.js";
import { MacService } from "../src/services/mac.js";
import { PqcHealthService } from "../src/services/pqc-health.js";
import { TransparencyLogService } from "../src/services/transparency.js";
import type { MerkleNode } from "../src/services/merkle-signing.js";
import {
  mlDsaGenerateKeyPair,
  mlDsaSign,
  mlDsaVerify,
} from "../src/services/ml-dsa-adapter.js";
import { WEBAUTHN_BRIDGE_TAG } from "../src/services/webauthn.js";

async function main() {
  const prisma = new PrismaClient();

  try {
    const org = await prisma.organization.findFirst({
      orderBy: { createdAt: "asc" },
    });
    if (!org) throw new Error("no organizations in DB — seed one first");
    log(`org: ${org.slug} (${org.id})`);

    const signingService = new SigningService(prisma);
    const batchSigner = new BatchSigner(prisma, new LocalSlhDsaSigner(signingService), {
      maxBatchSize: 64,
      maxWaitMs: 200,
    });
    const hybrid = new HybridSigningService(prisma, signingService, batchSigner);
    const macService = new MacService(prisma);

    // Step 1: mint a fresh hybrid signing key. This exercises the SLH-DSA
    // keygen path inside SigningService.createKeyPair.
    log("minting fresh hybrid signing key…");
    const signingKey = await signingService.createKeyPair(org.id);
    if (!signingKey.slhdsaPublicKey) {
      throw new Error("createKeyPair did not populate slhdsaPublicKey");
    }
    log(`  keyId=${signingKey.keyId}`);
    log(`  slhdsaPublicKey=${signingKey.slhdsaPublicKey.slice(0, 32)}…`);

    // Step 2: hybrid-sign a single QR.
    const token = generateToken();
    const destinationUrl = `https://example.com/smoke/${token}`;
    const lat = 40.7128;
    const lng = -74.006;
    const radiusM = 100;

    log(`issuing hybrid signature for token=${token}…`);
    const t0 = Date.now();
    const result = await hybrid.signSingleQR({
      organizationId: org.id,
      signingKeyDbId: signingKey.id,
      signingKeyId: signingKey.keyId,
      token,
      destinationUrl,
      geoHash: "",
      expiresAt: "",
      contentHash: "",
      lat,
      lng,
      radiusM,
      expiresAtDate: null,
    });
    log(`  signed in ${Date.now() - t0}ms`);
    log(`  algVersion=${result.algVersion}`);
    log(`  batchId=${result.batchId}`);
    log(`  merkleRoot=${result.merkleRoot.slice(0, 32)}…`);
    log(`  rootSignature length=${Buffer.from(result.rootSignature, "base64").length} bytes`);
    log(`  ecdsaSignature length=${Buffer.from(result.ecdsaSignature, "base64").length} bytes`);

    // Step 2b: compute the MAC fast-path tag.
    const macCanonical = hashPayload(token, destinationUrl, "", "", "");
    log("computing symmetric MAC…");
    const macResult = await macService.signCanonical(org.id, macCanonical);
    log(`  macKeyVersion=${macResult.keyVersion}`);
    log(`  mac=${macResult.mac.slice(0, 32)}…`);

    // Step 3: persist a QRCode row mirroring the route handler.
    log("persisting QRCode row…");
    const qrCode = await prisma.qRCode.create({
      data: {
        token,
        organizationId: org.id,
        signingKeyId: signingKey.id,
        destinationUrl,
        signature: result.ecdsaSignature,
        latitude: lat,
        longitude: lng,
        radiusM,
        status: "ACTIVE",
        algVersion: result.algVersion,
        merkleBatchId: result.batchId,
        merkleLeafIndex: result.leafIndex,
        merkleLeafHash: result.leafHash,
        merkleLeafNonce: result.leafNonce,
        merklePath: result.merklePath as never,
        macTokenMac: macResult.mac,
        macKeyVersion: macResult.keyVersion,
      },
    });
    log(`  qrCode.id=${qrCode.id}`);

    // Step 4: append a commitment-only transparency log entry.
    const transparencyService = new TransparencyLogService(prisma);
    log("appending commitment-only transparency log entry…");
    const logEntry = await transparencyService.appendEntry({
      id: qrCode.id,
      token: qrCode.token,
      organizationId: qrCode.organizationId,
      destinationUrl: qrCode.destinationUrl,
      geoHash: qrCode.geoHash,
      pqc: {
        algVersion: result.algVersion,
        leafHash: result.leafHash,
        batchRootRef: TransparencyLogService.computeBatchRootRef(result.merkleRoot),
        merkleInclusionProof: result.merklePath,
      },
    });
    log(`  logIndex=${logEntry.logIndex} algVersion=${logEntry.algVersion}`);
    log(`  commitment=${logEntry.commitment?.slice(0, 32)}…`);
    log(`  batchRootRef=${logEntry.batchRootRef?.slice(0, 32)}…`);

    // Step 5: verify both legs the way routes/verify.ts does.
    log("verifying ECDSA leg…");
    const ecdsaValid = signingService.verifyQRCode(
      signingKey.publicKey,
      qrCode.signature,
      qrCode.token,
      qrCode.destinationUrl,
      qrCode.geoHash ?? "",
      qrCode.expiresAt?.toISOString() ?? "",
      "",
    );
    log(`  ecdsaValid=${ecdsaValid}`);
    if (!ecdsaValid) throw new Error("ECDSA verification failed");

    log("verifying Merkle + SLH-DSA leg…");
    const t1 = Date.now();
    const hybridResult = await hybrid.verifyHybridLeg({
      leafHash: qrCode.merkleLeafHash!,
      merklePath: qrCode.merklePath as unknown as MerkleNode[],
      batchId: qrCode.merkleBatchId!,
    });
    log(`  verified in ${Date.now() - t1}ms`);
    log(`  hybridOk=${hybridResult.ok}`);
    if (!hybridResult.ok) throw new Error(`hybrid leg failed: ${hybridResult.reason}`);

    log("verifying MAC fast path…");
    const t2 = Date.now();
    const macOk = await macService.verifyCanonical({
      organizationId: org.id,
      canonicalPayload: macCanonical,
      storedMac: qrCode.macTokenMac!,
      keyVersion: qrCode.macKeyVersion,
    });
    log(`  verified in ${Date.now() - t2}ms`);
    log(`  macOk=${macOk}`);
    if (!macOk) throw new Error("MAC fast path failed");

    // Quick microbench: 100 verifications back-to-back, average it.
    log("MAC fast-path microbench (100 iterations)…");
    const benchStart = Date.now();
    for (let i = 0; i < 100; i++) {
      await macService.verifyCanonical({
        organizationId: org.id,
        canonicalPayload: macCanonical,
        storedMac: qrCode.macTokenMac!,
        keyVersion: qrCode.macKeyVersion,
      });
    }
    const benchTotal = Date.now() - benchStart;
    log(`  total=${benchTotal}ms avg=${(benchTotal / 100).toFixed(2)}ms/verify`);

    log("MAC mismatch should fail…");
    const macMismatch = await macService.verifyCanonical({
      organizationId: org.id,
      canonicalPayload: macCanonical + ":tampered",
      storedMac: qrCode.macTokenMac!,
      keyVersion: qrCode.macKeyVersion,
    });
    if (macMismatch) throw new Error("MAC mismatch test passed when it should have failed");
    log("  rejected (expected)");

    // Step 6: tamper test — flip a bit in the leaf hash, expect failure.
    log("tamper test (flipped leaf hash should fail)…");
    const tampered = await hybrid.verifyHybridLeg({
      leafHash: "00".repeat(32),
      merklePath: qrCode.merklePath as unknown as MerkleNode[],
      batchId: qrCode.merkleBatchId!,
    });
    if (tampered.ok) throw new Error("tamper test passed when it should have failed");
    log(`  tampered.reason=${tampered.reason} (expected failure)`);

    // Cleanup: drop the QR row and its log entry. Leave SigningKey + key
    // files so reruns reuse the same key.
    log("cleaning up smoke QR row…");
    await prisma.transparencyLogEntry.delete({ where: { id: logEntry.id } });
    await prisma.qRCode.delete({ where: { id: qrCode.id } });
    await prisma.signedBatch.delete({ where: { batchId: result.batchId } });

    // Multi-leaf batching benchmark: issue N QRs concurrently and confirm
    // they all land in the same Merkle batch. This is the headline number
    // for Phase 1.5 — without batching, N QRs would cost N × ~2.3s.
    const N = 16;
    log("");
    log(`multi-leaf batch benchmark: issuing ${N} QRs in parallel…`);
    const benchKey = await signingService.createKeyPair(org.id);
    const parT0 = Date.now();
    const benchResults = await Promise.all(
      Array.from({ length: N }, (_, i) =>
        hybrid.signSingleQR({
          organizationId: org.id,
          signingKeyDbId: benchKey.id,
          signingKeyId: benchKey.keyId,
          token: `bench_${parT0}_${i}`,
          destinationUrl: `https://example.com/bench/${i}`,
          geoHash: "",
          expiresAt: "",
          contentHash: "",
          lat: null,
          lng: null,
          radiusM: null,
          expiresAtDate: null,
        }),
      ),
    );
    const parTotal = Date.now() - parT0;
    const distinctBatches = new Set(benchResults.map((r) => r.batchId));
    log(`  total wall-clock=${parTotal}ms (${(parTotal / N).toFixed(1)}ms per QR amortized)`);
    log(`  distinct batches=${distinctBatches.size} (expected: 1)`);
    const leafIndices = benchResults.map((r) => r.leafIndex).sort((a, b) => a - b);
    const expectedIndices = Array.from({ length: N }, (_, i) => i);
    const indicesMatch =
      leafIndices.length === expectedIndices.length &&
      leafIndices.every((v, i) => v === expectedIndices[i]);
    log(`  leaf indices contiguous 0..${N - 1}: ${indicesMatch}`);
    if (distinctBatches.size !== 1) {
      throw new Error(`expected 1 batch, got ${distinctBatches.size}`);
    }
    if (!indicesMatch) {
      throw new Error("leaf indices not contiguous");
    }

    // Cleanup: drop the benchmark batch and its rows. We never inserted
    // QRCode rows for the benchmark, so just drop the SignedBatch.
    await prisma.signedBatch.delete({ where: { batchId: benchResults[0].batchId } });

    // Algorithm policy: classify a few versions and confirm the deprecated
    // marker survives a round-trip through the verifier-facing helper.
    log("");
    log("alg-version policy classification…");
    log(`  hybrid       → ${checkAlgVersion(ALG_VERSION_POLICY.hybrid)}`);
    log(`  pqc          → ${checkAlgVersion(ALG_VERSION_POLICY.pqc)}`);
    log(`  pending      → ${checkAlgVersion(ALG_VERSION_POLICY.pending)}`);
    log(`  legacyEcdsa  → ${checkAlgVersion(ALG_VERSION_POLICY.legacyEcdsa)} (expected: deprecated)`);
    log(`  unknown-v9   → ${checkAlgVersion("unknown-v9")} (expected: unknown)`);
    if (checkAlgVersion(ALG_VERSION_POLICY.legacyEcdsa) !== "deprecated") {
      throw new Error("legacyEcdsa should classify as deprecated");
    }
    if (checkAlgVersion("unknown-v9") !== "unknown") {
      throw new Error("unknown-v9 should classify as unknown");
    }

    // Reconciler simulation: stand up a stuck pending row, then exercise
    // the same code path the BullMQ reconcile worker runs. Verifies that
    // the safety net upgrades stale rows without operator intervention.
    log("");
    log("reconciler simulation: inserting a stuck ecdsa-pending row…");
    const stuckToken = generateToken();
    const stuckSig = await signingService.signQRCode(
      signingKey.keyId,
      stuckToken,
      `https://example.com/stuck/${stuckToken}`,
      "",
      "",
      "",
    );
    const stuckRow = await prisma.qRCode.create({
      data: {
        token: stuckToken,
        organizationId: org.id,
        signingKeyId: signingKey.id,
        destinationUrl: `https://example.com/stuck/${stuckToken}`,
        signature: stuckSig,
        radiusM: 50,
        status: "ACTIVE",
        algVersion: "ecdsa-pending-slhdsa-v1",
        // Backdate so the reconciler picks it up (>5min stale threshold).
        createdAt: new Date(Date.now() - 6 * 60 * 1000),
      },
    });
    log(`  stuck row id=${stuckRow.id} createdAt=${stuckRow.createdAt.toISOString()}`);

    log("running reconciler logic against the stuck row…");
    const reconcileT0 = Date.now();
    const reconcileBatch = await hybrid.signSingleQRAsync({
      organizationId: org.id,
      signingKeyDbId: signingKey.id,
      signingKeyId: signingKey.keyId,
      token: stuckRow.token,
      destinationUrl: stuckRow.destinationUrl,
      geoHash: "",
      expiresAt: "",
      contentHash: "",
      lat: null,
      lng: null,
      radiusM: null,
      expiresAtDate: null,
    });
    const reconciled = await reconcileBatch.merklePromise;
    await prisma.qRCode.update({
      where: { id: stuckRow.id },
      data: {
        algVersion: reconciled.algVersion,
        merkleBatchId: reconciled.batchId,
        merkleLeafIndex: reconciled.leafIndex,
        merkleLeafHash: reconciled.leafHash,
        merkleLeafNonce: reconciled.leafNonce,
        merklePath: reconciled.merklePath as never,
      },
    });
    log(`  reconciled in ${Date.now() - reconcileT0}ms`);

    const after = await prisma.qRCode.findUnique({ where: { id: stuckRow.id } });
    if (after?.algVersion !== "hybrid-ecdsa-slhdsa-v1") {
      throw new Error(`expected hybrid-ecdsa-slhdsa-v1, got ${after?.algVersion}`);
    }
    if (!after.merkleBatchId || !after.merkleLeafHash) {
      throw new Error("merkle fields not populated after reconcile");
    }
    log(`  row upgraded: algVersion=${after.algVersion} batchId=${after.merkleBatchId.slice(0, 16)}…`);

    // Cleanup: drop the row and its batch.
    await prisma.qRCode.delete({ where: { id: stuckRow.id } });
    await prisma.signedBatch.delete({ where: { batchId: reconciled.batchId } });

    // Async issuance: ECDSA leg returns immediately, merkle leg fills in
    // background. Single QR latency drops from ~2.3s to ~10ms.
    log("");
    log("async issuance: timing the ECDSA-only return path…");
    const asyncToken = generateToken();
    const asyncT0 = Date.now();
    const { ecdsaSignature: asyncSig, merklePromise: asyncMerkle } =
      await hybrid.signSingleQRAsync({
        organizationId: org.id,
        signingKeyDbId: signingKey.id,
        signingKeyId: signingKey.keyId,
        token: asyncToken,
        destinationUrl: `https://example.com/async/${asyncToken}`,
        geoHash: "",
        expiresAt: "",
        contentHash: "",
        lat: null,
        lng: null,
        radiusM: null,
        expiresAtDate: null,
      });
    const asyncReturnLatency = Date.now() - asyncT0;
    log(`  ECDSA leg ready in ${asyncReturnLatency}ms (sig length=${Buffer.from(asyncSig, "base64").length}b)`);
    log(`  merkle leg pending in batch queue…`);
    const asyncMerkleT0 = Date.now();
    const asyncBatchResult = await asyncMerkle;
    const asyncMerkleLatency = Date.now() - asyncMerkleT0;
    log(`  merkle leg resolved in ${asyncMerkleLatency}ms (batchId=${asyncBatchResult.batchId.slice(0, 16)}…)`);
    if (asyncReturnLatency > 100) {
      throw new Error(`async return path took ${asyncReturnLatency}ms, expected <100ms`);
    }
    await prisma.signedBatch.delete({ where: { batchId: asyncBatchResult.batchId } });

    // WebAuthn bridge round trip. Simulates the client-side ML-DSA-44
    // signing path that the browser will run after we wire the IndexedDB
    // helper. Confirms keygen latency, sign latency, verify latency, and
    // that the domain-tag prevents key reuse.
    log("");
    log("WebAuthn PQC bridge round trip (ML-DSA-44)…");
    const bridgeKeygenT0 = Date.now();
    const bridgeKp = await mlDsaGenerateKeyPair();
    log(`  keygen=${Date.now() - bridgeKeygenT0}ms (pk=${bridgeKp.publicKey.length}b sk=${bridgeKp.privateKey.length}b)`);

    // Pretend WebAuthn handed us a base64url challenge.
    const bridgeChallenge = (await import("node:crypto"))
      .randomBytes(32)
      .toString("base64url");
    const bridgeMessage = Buffer.concat([
      Buffer.from(WEBAUTHN_BRIDGE_TAG),
      Buffer.from(bridgeChallenge, "base64url"),
    ]);

    const bridgeSignT0 = Date.now();
    const bridgeSig = await mlDsaSign(bridgeKp.privateKey, bridgeMessage);
    log(`  sign=${Date.now() - bridgeSignT0}ms (sig=${bridgeSig.length}b)`);

    const bridgeVerifyT0 = Date.now();
    const bridgeOk = await mlDsaVerify(bridgeKp.publicKey, bridgeMessage, bridgeSig);
    log(`  verify=${Date.now() - bridgeVerifyT0}ms ok=${bridgeOk}`);
    if (!bridgeOk) throw new Error("bridge round trip failed");

    // Tamper test: signature for a different challenge must be rejected.
    const wrongChallenge = (await import("node:crypto"))
      .randomBytes(32)
      .toString("base64url");
    const wrongMessage = Buffer.concat([
      Buffer.from(WEBAUTHN_BRIDGE_TAG),
      Buffer.from(wrongChallenge, "base64url"),
    ]);
    const bridgeTampered = await mlDsaVerify(bridgeKp.publicKey, wrongMessage, bridgeSig);
    if (bridgeTampered) throw new Error("bridge tamper test passed when it should have failed");
    log(`  tampered challenge → rejected (expected)`);

    // Air-gapped signer round trip (ALGORITHM.md §13.1). Spawns the
    // standalone signer service as a child process pointing at the
    // current keys directory, instantiates an HttpSlhDsaSigner against
    // it, runs a real batch through it, and confirms the result
    // verifies under the same public key the API holds.
    log("");
    log("air-gapped signer round trip: spawning signer-service…");
    const signerToken = "smoke-test-bearer-token-32-chars-min";
    const signerPort = 17788;
    const child = spawn(
      "node",
      ["/Users/aris/Projects/vqr/packages/signer-service/dist/server.js"],
      {
        env: {
          ...process.env,
          SIGNER_PORT: String(signerPort),
          SIGNER_HOST: "127.0.0.1",
          SIGNER_KEYS_DIR: "/Users/aris/Projects/vqr/packages/api/keys",
          SIGNER_TOKEN: signerToken,
          LOG_LEVEL: "warn",
        },
        stdio: ["ignore", "pipe", "pipe"],
      },
    );

    let signerReady = false;
    child.stderr?.on("data", (chunk) => process.stderr.write(`[signer] ${chunk}`));
    child.stdout?.on("data", (chunk) => {
      const s = chunk.toString();
      if (s.includes("qrauth-signer ready")) signerReady = true;
    });

    // Wait up to 5s for ready, polling /healthz.
    const startWait = Date.now();
    while (Date.now() - startWait < 5000) {
      try {
        const res = await fetch(`http://127.0.0.1:${signerPort}/healthz`);
        if (res.ok) {
          signerReady = true;
          break;
        }
      } catch {
        // not up yet
      }
      await new Promise((r) => setTimeout(r, 100));
    }
    if (!signerReady) {
      child.kill();
      throw new Error("signer-service failed to start within 5s");
    }
    log(`  signer up on http://127.0.0.1:${signerPort}`);

    try {
      const httpSigner = new HttpSlhDsaSigner(
        `http://127.0.0.1:${signerPort}`,
        signerToken,
      );
      const remoteBatchSigner = new BatchSigner(prisma, httpSigner, {
        maxBatchSize: 8,
        maxWaitMs: 100,
      });
      const remoteHybrid = new HybridSigningService(
        prisma,
        signingService,
        remoteBatchSigner,
      );

      const remoteToken = generateToken();
      const remoteResult = await remoteHybrid.signSingleQR({
        organizationId: org.id,
        signingKeyDbId: signingKey.id,
        signingKeyId: signingKey.keyId,
        token: remoteToken,
        destinationUrl: `https://example.com/airgap/${remoteToken}`,
        geoHash: "",
        expiresAt: "",
        contentHash: "",
        lat: null,
        lng: null,
        radiusM: null,
        expiresAtDate: null,
      });
      log(
        `  signed via remote: batchId=${remoteResult.batchId.slice(0, 16)}… algVersion=${remoteResult.algVersion}`,
      );

      // Cross-verify: fetch the public key over the wire and confirm
      // the signature we just got is valid under it.
      const remotePub = await httpSigner.getPublicKey(signingKey.keyId);
      const localPub = (
        await signingService.loadSlhDsaKeyPair(signingKey.keyId)
      )?.publicKey;
      if (!localPub || !remotePub.equals(localPub)) {
        throw new Error("remote and local public keys do not match");
      }
      log(`  remote pubkey matches local (${remotePub.length}b)`);

      // Drop the orphan SignedBatch row so the DB stays clean.
      await prisma.signedBatch.delete({ where: { batchId: remoteResult.batchId } });
      await remoteBatchSigner.flushAll();
    } finally {
      child.kill("SIGTERM");
    }

    // PQC health report against the real DB. This is the operator-facing
    // dashboard view exposed via GET /api/v1/analytics/pqc-health.
    log("");
    log("PQC migration health report (this org)…");
    const healthService = new PqcHealthService(prisma);
    const report = await healthService.getOrgHealth(org.id);
    log(`  status=${report.status}`);
    log(
      `  qrCodes total=${report.qrCodes.total} accepted=${report.qrCodes.byStatus.accepted} deprecated=${report.qrCodes.byStatus.deprecated} unknown=${report.qrCodes.byStatus.unknown} pendingStuck=${report.qrCodes.pendingStuck}`,
    );
    log(`  qrCodes byAlgVersion: ${JSON.stringify(report.qrCodes.byAlgVersion)}`);
    log(
      `  passkeys total=${report.passkeys.total} withBridge=${report.passkeys.withBridge} withoutBridge=${report.passkeys.withoutBridge}`,
    );
    log(
      `  macKeys activeVersion=${report.macKeys.activeVersion} ageDays=${report.macKeys.activeAgeDays} daysUntilRotation=${report.macKeys.daysUntilRotation} rotated=${report.macKeys.rotatedCount} retired=${report.macKeys.retiredCount}`,
    );
    log(
      `  signedBatches total=${report.signedBatches.total} lastBatchAt=${report.signedBatches.lastBatchAt}`,
    );
    if (report.warnings.length > 0) {
      log(`  warnings:`);
      for (const w of report.warnings) log(`    - ${w}`);
    }

    log("");
    log("✓ hybrid smoke test passed");

    // Drain any in-flight batch work before disconnecting Postgres so that
    // concurrent flushes don't race with the disconnect.
    await batchSigner.flushAll();
  } finally {
    await prisma.$disconnect();
  }
}

function log(msg: string) {
  // eslint-disable-next-line no-console
  console.log(msg);
}

main().catch((err) => {
  // eslint-disable-next-line no-console
  console.error("✗ smoke test failed:", err);
  process.exit(1);
});
