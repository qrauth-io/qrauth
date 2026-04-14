import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Fastify, { type FastifyInstance } from "fastify";

import {
  HttpSlhDsaSigner,
  LocalSlhDsaSigner,
} from "../../api/src/services/slhdsa-signer/index.js";
import { SigningService } from "../../api/src/services/signing.js";
import {
  slhDsaGenerateKeyPair,
  slhDsaVerify,
} from "../../api/src/services/slhdsa-adapter.js";
import { generateKeyPair } from "../../api/src/lib/crypto.js";
import { config } from "../../api/src/lib/config.js";

/**
 * Tests both SLH-DSA signer backends end-to-end:
 *   1. LocalSlhDsaSigner — loads from disk, signs in-process. Used by
 *      the dev loop and the protocol-test suite itself.
 *   2. HttpSlhDsaSigner  — POSTs to a remote signer service. Tested
 *      against an in-process fastify server that mimics the wire format
 *      of `packages/signer-service/`. Avoids spawning a child process
 *      while still exercising the actual fetch/parse/error paths.
 *
 * Key sharing strategy: both backends are pointed at the same on-disk
 * keypair so the verify step can cross-check that signatures from each
 * backend verify under the same public key. That guards against
 * accidentally drifting the wire format or the message encoding between
 * client and server.
 */

const tmpKeysDir = mkdtempSync(join(tmpdir(), "qrauth-signer-test-"));
let signingKeyId: string;
let publicKey: Buffer;
let signingService: SigningService;

const TOKEN = "test-bearer-token-do-not-use-in-prod-x";

beforeAll(async () => {
  (config.kms as { ecdsaPrivateKeyPath: string }).ecdsaPrivateKeyPath = tmpKeysDir;

  const ecdsa = await generateKeyPair();
  signingKeyId = ecdsa.keyId;
  writeFileSync(join(tmpKeysDir, `${ecdsa.keyId}.pem`), ecdsa.privateKey, { mode: 0o600 });

  const slh = await slhDsaGenerateKeyPair();
  writeFileSync(
    join(tmpKeysDir, `${ecdsa.keyId}.slhdsa.key`),
    slh.privateKey.toString("base64"),
    { mode: 0o600 },
  );
  publicKey = slh.publicKey;

  // SigningService here is only used by LocalSlhDsaSigner — the in-memory
  // Prisma fake just has to return slhdsaPublicKey for the row.
  const fakePrisma = {
    signingKey: {
      findUnique: async () => ({
        keyId: signingKeyId,
        slhdsaPublicKey: publicKey.toString("base64"),
      }),
    },
  };
  signingService = new SigningService(fakePrisma as unknown as never);
});

describe("LocalSlhDsaSigner", () => {
  it("signs a message that verifies against the loaded public key", async () => {
    const signer = new LocalSlhDsaSigner(signingService);
    const message = Buffer.from("hello-from-local");
    const sig = await signer.signRoot(signingKeyId, message);
    expect(sig.length).toBe(7856);
    expect(await slhDsaVerify(publicKey, message, sig)).toBe(true);
  });

  it("returns the same public key as the underlying file", async () => {
    const signer = new LocalSlhDsaSigner(signingService);
    const pub = await signer.getPublicKey(signingKeyId);
    expect(pub.equals(publicKey)).toBe(true);
  });

  it("throws for an unknown keyId", async () => {
    const signer = new LocalSlhDsaSigner(signingService);
    // Force the inner findUnique to return null
    const orig = signingService;
    const fake = {
      signingKey: { findUnique: async () => null },
    } as unknown as never;
    const blankSvc = new SigningService(fake);
    const blankSigner = new LocalSlhDsaSigner(blankSvc);
    await expect(blankSigner.signRoot("missing", Buffer.alloc(32))).rejects.toThrow(
      /no SLH-DSA material/,
    );
    void orig;
  });
});

// ---------------------------------------------------------------------------
// HttpSlhDsaSigner against an in-process fastify server
// ---------------------------------------------------------------------------

let app: FastifyInstance;
let port: number;

beforeAll(async () => {
  app = Fastify();
  app.addHook("onRequest", async (request, reply) => {
    if (request.url === "/healthz") return;
    const auth = request.headers.authorization ?? "";
    if (auth !== `Bearer ${TOKEN}`) {
      return reply.status(401).send({ error: "unauthorized" });
    }
  });
  app.post<{ Body: { keyId: string; message: string } }>(
    "/v1/sign",
    async (request, reply) => {
      const { keyId, message } = request.body ?? ({} as { keyId: string; message: string });
      if (typeof keyId !== "string" || typeof message !== "string") {
        return reply.status(400).send({ error: "malformed_request" });
      }
      if (keyId !== signingKeyId) {
        return reply.status(404).send({ error: "key_not_found" });
      }
      // Sign with the same on-disk key the LocalSigner uses, so the
      // tests below can cross-verify both backends produce signatures
      // valid under the same public key.
      const local = new LocalSlhDsaSigner(signingService);
      const sig = await local.signRoot(keyId, Buffer.from(message, "base64"));
      return { signature: sig.toString("base64") };
    },
  );
  app.get<{ Params: { keyId: string } }>(
    "/v1/keys/:keyId/public",
    async (request, reply) => {
      if (request.params.keyId !== signingKeyId) {
        return reply.status(404).send({ error: "key_not_found" });
      }
      return { publicKey: publicKey.toString("base64"), algorithm: "slh-dsa-sha2-128s" };
    },
  );
  await app.listen({ port: 0, host: "127.0.0.1" });
  const addr = app.server.address();
  if (typeof addr === "object" && addr) port = addr.port;
});

afterAll(async () => {
  await app?.close();
});

describe("HttpSlhDsaSigner against a real fastify server", () => {
  it("signs through the wire and the result verifies under the published pubkey", async () => {
    const signer = new HttpSlhDsaSigner(`http://127.0.0.1:${port}`, TOKEN);
    const message = Buffer.from("hello-from-http-signer");
    const sig = await signer.signRoot(signingKeyId, message);
    expect(sig.length).toBe(7856);
    expect(await slhDsaVerify(publicKey, message, sig)).toBe(true);
  });

  it("fetches the public key over the wire", async () => {
    const signer = new HttpSlhDsaSigner(`http://127.0.0.1:${port}`, TOKEN);
    const pub = await signer.getPublicKey(signingKeyId);
    expect(pub.equals(publicKey)).toBe(true);
  });

  it("throws on 401 with a clear error", async () => {
    const signer = new HttpSlhDsaSigner(`http://127.0.0.1:${port}`, "wrong-token");
    await expect(signer.signRoot(signingKeyId, Buffer.alloc(32))).rejects.toThrow(/401/);
  });

  it("throws on 404 for an unknown key", async () => {
    const signer = new HttpSlhDsaSigner(`http://127.0.0.1:${port}`, TOKEN);
    await expect(signer.signRoot("nonexistent", Buffer.alloc(32))).rejects.toThrow(
      /key_not_found/,
    );
  });

  it("normalizes a trailing slash in the base URL", async () => {
    const signer = new HttpSlhDsaSigner(`http://127.0.0.1:${port}/`, TOKEN);
    const pub = await signer.getPublicKey(signingKeyId);
    expect(pub.equals(publicKey)).toBe(true);
  });

  it("rejects an empty token at construction time", () => {
    expect(() => new HttpSlhDsaSigner(`http://127.0.0.1:${port}`, "")).toThrow();
  });

  it("rejects an empty base URL at construction time", () => {
    expect(() => new HttpSlhDsaSigner("", TOKEN)).toThrow();
  });
});
