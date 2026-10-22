-- Pricing tiers 2026-10: a self-serve Business tier between Pro and the
-- contract-only ENTERPRISE (sold as "Regulated"). Additive; no rows change.
ALTER TYPE "Plan" ADD VALUE IF NOT EXISTS 'BUSINESS' BEFORE 'ENTERPRISE';
