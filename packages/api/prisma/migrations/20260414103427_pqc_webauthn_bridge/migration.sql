-- AlterTable
ALTER TABLE "passkeys" ADD COLUMN     "bridgeAlgorithm" TEXT DEFAULT 'ml-dsa-44',
ADD COLUMN     "bridgePublicKey" BYTEA;
