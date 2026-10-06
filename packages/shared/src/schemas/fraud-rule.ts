import { z } from 'zod';

/**
 * Allowed feature fields that the fraud rule engine can evaluate.
 *
 * MUST stay in sync with the keys produced by
 * `packages/api/src/services/feature-extraction.ts`. The enum bounds what
 * the AI agent (or any future rule author) can reference — unknown fields
 * silently evaluated to false would mask broken rules.
 *
 * Audit ref: F-003 (docs/security/audit-2026-05-17-api-and-server.md)
 */
const ALLOWED_FEATURE_FIELDS = [
  // Velocity / volume
  'scanCount',
  'scanVelocity5m',
  'scanVelocity1h',
  'uniqueIps',
  'uniqueDevices',
  'uniqueLocations',
  'avgTimeBetweenScans',
  'maxVelocity',
  // Risk signals
  'proxyScore',
  'botScore',
  'isBot',
  // Clustering / distribution
  'deviceClusterSize',
  'ipDispersion',
  'ipDispersion1h',
  'geoImpossibility',
] as const;

const ALLOWED_OPERATORS = ['gt', 'lt', 'gte', 'lte', 'eq', 'neq', 'between', 'in'] as const;

const ALLOWED_ACTION_TYPES = [
  'PATTERN_ANOMALY',
  'GEO_IMPOSSIBLE',
  'PROXY_DETECTED',
  'DUPLICATE_LOCATION',
  'MANUAL_REPORT',
] as const;

const RuleValueSchema = z.union([
  z.number(),
  z.string(),
  z.array(z.union([z.number(), z.string()])),
  z.tuple([z.number(), z.number()]),
]);

export const FraudRuleConditionSchema = z.object({
  field: z.enum(ALLOWED_FEATURE_FIELDS),
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
