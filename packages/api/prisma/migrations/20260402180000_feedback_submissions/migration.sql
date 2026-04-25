CREATE TABLE "feedback_submissions" (
    "id" TEXT NOT NULL,
    "qrCodeId" TEXT NOT NULL,
    "rating" INTEGER NOT NULL,
    "comment" TEXT,
    "ipHash" TEXT,
    "userAgent" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "feedback_submissions_pkey" PRIMARY KEY ("id")
);
CREATE INDEX "feedback_submissions_qrCodeId_createdAt_idx" ON "feedback_submissions"("qrCodeId", "createdAt");
ALTER TABLE "feedback_submissions" ADD CONSTRAINT "feedback_submissions_qrCodeId_fkey" FOREIGN KEY ("qrCodeId") REFERENCES "qr_codes"("id") ON DELETE CASCADE ON UPDATE CASCADE;
