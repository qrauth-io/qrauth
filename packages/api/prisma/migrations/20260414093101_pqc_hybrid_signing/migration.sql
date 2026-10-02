-- AlterTable
ALTER TABLE "ephemeral_sessions" ALTER COLUMN "scopes" SET DEFAULT ARRAY[]::TEXT[];

-- AlterTable
ALTER TABLE "qr_codes" ADD COLUMN     "algVersion" TEXT DEFAULT 'ecdsa-p256-sha256-v1',
ADD COLUMN     "merkleBatchId" TEXT,
ADD COLUMN     "merkleLeafHash" TEXT,
ADD COLUMN     "merkleLeafIndex" INTEGER,
ADD COLUMN     "merkleLeafNonce" TEXT,
ADD COLUMN     "merklePath" JSONB;

-- AlterTable
ALTER TABLE "signing_keys" ADD COLUMN     "slhdsaAlgorithm" TEXT DEFAULT 'slh-dsa-sha2-128s',
ADD COLUMN     "slhdsaPublicKey" TEXT;

-- AlterTable
ALTER TABLE "transparency_log" ADD COLUMN     "algVersion" TEXT DEFAULT 'ecdsa-p256-sha256-v1',
ADD COLUMN     "batchRootRef" TEXT,
ADD COLUMN     "commitment" TEXT,
ADD COLUMN     "merkleInclusionProof" JSONB;

-- CreateTable
CREATE TABLE "signed_batches" (
    "id" TEXT NOT NULL,
    "batchId" TEXT NOT NULL,
    "organizationId" TEXT NOT NULL,
    "signingKeyId" TEXT NOT NULL,
    "algVersion" TEXT NOT NULL DEFAULT 'hybrid-ecdsa-slhdsa-v1',
    "merkleRoot" TEXT NOT NULL,
    "rootSignature" TEXT NOT NULL,
    "tokenCount" INTEGER NOT NULL,
    "issuedAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "signed_batches_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "signed_batches_batchId_key" ON "signed_batches"("batchId");

-- CreateIndex
CREATE INDEX "signed_batches_organizationId_idx" ON "signed_batches"("organizationId");

-- CreateIndex
CREATE INDEX "signed_batches_signingKeyId_idx" ON "signed_batches"("signingKeyId");

-- AddForeignKey
ALTER TABLE "qr_codes" ADD CONSTRAINT "qr_codes_merkleBatchId_fkey" FOREIGN KEY ("merkleBatchId") REFERENCES "signed_batches"("batchId") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "signed_batches" ADD CONSTRAINT "signed_batches_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "signed_batches" ADD CONSTRAINT "signed_batches_signingKeyId_fkey" FOREIGN KEY ("signingKeyId") REFERENCES "signing_keys"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
