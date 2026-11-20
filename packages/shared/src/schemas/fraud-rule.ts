import { z } from 'zod';

/**
 * Feature fields the fraud rule engine can evaluate: exactly the keys
 * produced by `packages/api/src/services/feature-extraction.ts`
 * (FEATURE_KEYS there). A parity test in the API fails on any difference.
 * The enum bounds what the AI agent (or any future rule author) can
 * reference; an unknown field evaluates to false and would mask a broken
 * rule.
 *
 * Validation applies when a rule is created; rules already stored are not
 * re-validated.
 *
 * Audit ref: F-003 (docs/security/audit-2026-05-17-api-and-server.md)
 */
export const FRAUD_RULE_FEATURE_FIELDS = [
  'scanVelocity5m',
  'scanVelocity1h',
  'ipDispersion1h',
  'hourOfDay',
  'dayOfWeek',
  'isBot',
  'isNewIp',
  'timeSinceLastScan',
  'trustScoreTrend',
] as const;

/** Rule lifecycle; mirrors the Prisma FraudRuleStatus enum. */
export const FRAUD_RULE_STATUSES = ['SHADOW', 'ACTIVE', 'DISABLED'] as const;
export type FraudRuleStatus = (typeof FRAUD_RULE_STATUSES)[number];

const ALLOWED_OPERATORS = ['gt', 'lt', 'gte', 'lte', 'eq', 'neq', 'between', 'in'] as const;

const ALLOWED_ACTION_TYPES = [
  'PATTERN_ANOMALY',
  'GEO_IMPOSSIBLE',
  'PROXY_DETECTED',
  'DUPLICATE_LOCATION',
  'MANUAL_REPORT',
] as const;

// Booleans are needed for the isBot / isNewIp features (the engine compares
// with ===, so `true` and `1` are different values).
const RuleValueSchema = z.union([
  z.boolean(),
  z.number(),
  z.string(),
  z.array(z.union([z.number(), z.string()])),
  z.tuple([z.number(), z.number()]),
]);

export const FraudRuleConditionSchema = z.object({
  field: z.enum(FRAUD_RULE_FEATURE_FIELDS),
  operator: z.enum(ALLOWED_OPERATORS),
  value: RuleValueSchema,
});

export const FraudRuleActionSchema = z.object({
  type: z.enum(ALLOWED_ACTION_TYPES).optional().default('PATTERN_ANOMALY'),
  deductScore: z.number().int().min(1).max(40),
  severity: z.enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']),
  reason: z.string().min(1).max(200),
});

export const FraudRuleInputSchema = z.object({
  name: z.string().min(1).max(100),
  description: z.string().max(500).optional(),
  conditions: z.array(FraudRuleConditionSchema).min(1).max(10),
  action: FraudRuleActionSchema,
  priority: z.number().int().min(1).max(1000).optional().default(100),
});

export type FraudRuleCondition = z.infer<typeof FraudRuleConditionSchema>;
export type FraudRuleAction = z.infer<typeof FraudRuleActionSchema>;
export type FraudRuleInput = z.infer<typeof FraudRuleInputSchema>;
