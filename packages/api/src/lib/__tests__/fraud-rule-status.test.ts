import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  EVALUATED_RULE_STATUSES,
  isShadowStatus,
  ruleStatusData,
  statusFromEnabled,
} from '../fraud-rule-status.js';

const MIGRATIONS_DIR = fileURLToPath(new URL('../../../prisma/migrations', import.meta.url));

function statusMigrationSql(): string {
  const dir = readdirSync(MIGRATIONS_DIR).find((d) => d.endsWith('_fraud_rule_status'));
  if (!dir) throw new Error('fraud_rule_status migration not found');
  return readFileSync(join(MIGRATIONS_DIR, dir, 'migration.sql'), 'utf8');
}

describe('fraud rule status mapping', () => {
  it('maps the legacy enabled flag to ACTIVE / DISABLED', () => {
    expect(statusFromEnabled(true)).toBe('ACTIVE');
    expect(statusFromEnabled(false)).toBe('DISABLED');
  });

  it('keeps enabled true only for ACTIVE when writing a status', () => {
    expect(ruleStatusData('ACTIVE')).toEqual({ status: 'ACTIVE', enabled: true });
    expect(ruleStatusData('SHADOW')).toEqual({ status: 'SHADOW', enabled: false });
    expect(ruleStatusData('DISABLED')).toEqual({ status: 'DISABLED', enabled: false });
  });

  it('evaluates ACTIVE and SHADOW rules only', () => {
    expect([...EVALUATED_RULE_STATUSES].sort()).toEqual(['ACTIVE', 'SHADOW']);
  });

  it('treats a missing status (rules cached before the upgrade) as not shadow', () => {
    expect(isShadowStatus(undefined)).toBe(false);
    expect(isShadowStatus('ACTIVE')).toBe(false);
    expect(isShadowStatus('SHADOW')).toBe(true);
  });
});

describe('fraud_rule_status migration', () => {
  const sql = statusMigrationSql();

  it('adds status with default ACTIVE and backfills disabled rules to DISABLED', () => {
    expect(sql).toMatch(/CREATE TYPE "FraudRuleStatus" AS ENUM \('SHADOW', 'ACTIVE', 'DISABLED'\)/);
    expect(sql).toMatch(/ADD COLUMN "status" "FraudRuleStatus" NOT NULL DEFAULT 'ACTIVE'/);
    expect(sql).toMatch(/UPDATE "fraud_rules" SET "status" = 'DISABLED' WHERE "enabled" = false/);
  });

  it('adds the shadow flag to incidents with default false', () => {
    expect(sql).toMatch(/ALTER TABLE "fraud_incidents" ADD COLUMN "shadow" BOOLEAN NOT NULL DEFAULT false/);
  });

  it('is additive only', () => {
    expect(sql).not.toMatch(/\bDROP\b/i);
  });
});
