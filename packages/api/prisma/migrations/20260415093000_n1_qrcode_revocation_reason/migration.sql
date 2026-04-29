-- AUDIT-2 N-1: add structured revocation-reason column to QRCode so the
-- pending-reconciler's auto-revoke path can record why it revoked an
-- orphaned-merkle row ('ORPHANED_PENDING_MERKLE') without colliding
-- with user-driven revocations (which leave the column null).
ALTER TABLE "qr_codes" ADD COLUMN "revocationReason" TEXT;
