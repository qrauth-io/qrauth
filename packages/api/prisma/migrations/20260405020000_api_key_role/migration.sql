-- AlterTable: add role column to api_keys with default MEMBER
ALTER TABLE "api_keys" ADD COLUMN "role" "MembershipRole" NOT NULL DEFAULT 'MEMBER';
