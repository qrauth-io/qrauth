ALTER TABLE "organizations" ADD COLUMN "domainVerified" BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE "organizations" ADD COLUMN "domainVerifyToken" TEXT;
