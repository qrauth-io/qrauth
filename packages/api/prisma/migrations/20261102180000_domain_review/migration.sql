-- Lookalike review of organization domains (ADR-0007 D9). Additive.
CREATE TYPE "DomainReviewStatus" AS ENUM ('PENDING_REVIEW', 'APPROVED', 'REJECTED');

ALTER TABLE "organizations" ADD COLUMN "domainReviewStatus" "DomainReviewStatus",
ADD COLUMN "domainReview" JSONB;
