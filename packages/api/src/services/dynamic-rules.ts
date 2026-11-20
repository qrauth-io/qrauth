import type { FraudRuleStatus, PrismaClient } from '@prisma/client';
import { cacheGet, cacheSet } from '../lib/cache.js';
import { config } from '../lib/config.js';
import { EVALUATED_RULE_STATUSES, FRAUD_RULE_CACHE_KEY, isShadowStatus } from '../lib/fraud-rule-status.js';
import type { FeatureVector } from './feature-extraction.js';

interface RuleCondition {
  field: string;
  operator: 'gt' | 'lt' | 'gte' | 'lte' | 'eq' | 'neq' | 'between' | 'in';
  value: any;
}

interface RuleAction {
  deductScore: number;
  severity: string;
  type: string;
  reason: string;
}

interface FraudRuleRecord {
  id: string;
  name: string;
  conditions: RuleCondition[];
  action: RuleAction;
  priority: number;
  source: string | null;
  /** Absent on entries cached by a process that predates status. */
  status?: FraudRuleStatus;
}

export interface RuleEvalResult {
  ruleId: string;
  ruleName: string;
  action: RuleAction;
  /** True when the rule is SHADOW: the incident is internal only. */
  shadow: boolean;
}

export class DynamicRuleEngine {
  constructor(private prisma: PrismaClient) {}

  /**
   * Load ACTIVE and SHADOW rules (cached in Redis for 60 seconds).
   */
  private async loadRules(): Promise<FraudRuleRecord[]> {
    const cached = await cacheGet<FraudRuleRecord[]>(FRAUD_RULE_CACHE_KEY);
    if (cached) return cached;

    const rules = await this.prisma.fraudRule.findMany({
      where: { status: { in: [...EVALUATED_RULE_STATUSES] } },
      orderBy: { priority: 'asc' },
      select: { id: true, name: true, conditions: true, action: true, priority: true, source: true, status: true },
    });

    const parsed = rules.map((r) => ({
      id: r.id,
      name: r.name,
      conditions: r.conditions as unknown as RuleCondition[],
      action: r.action as unknown as RuleAction,
      priority: r.priority,
      source: r.source,
      status: r.status,
    }));

    await cacheSet(FRAUD_RULE_CACHE_KEY, parsed, 60);
    return parsed;
  }

  /**
   * Evaluate all conditions for a single rule.
   *
   * F-016 (audit 2026-05-17): every operator below is constant-time
   * (numeric compare, equality, fixed-size `in` membership). If you
   * extend this switch with `matches`, `regex`, `jsonpath`, or anything
   * that walks a user-supplied expression, wrap the per-condition body
   * in `AbortSignal.timeout(50)` or a per-tick counter cap to mitigate
   * ReDoS / expression-bomb risk against the agent-authored rule path.
   */
  private evaluateConditions(conditions: RuleCondition[], features: Record<string, any>): boolean {
    return conditions.every((cond) => {
      const val = features[cond.field];
      if (val === undefined) return false;

      switch (cond.operator) {
        case 'gt': return val > cond.value;
        case 'lt': return val < cond.value;
        case 'gte': return val >= cond.value;
        case 'lte': return val <= cond.value;
        case 'eq': return val === cond.value;
        case 'neq': return val !== cond.value;
        case 'between': {
          const [min, max] = cond.value as [number, number];
          return val >= min && val <= max;
        }
        case 'in': return (cond.value as any[]).includes(val);
        default: return false;
      }
    });
  }

  /**
   * Evaluate ACTIVE and SHADOW rules against a feature vector.
   * Returns fired rules sorted by priority; SHADOW ones carry shadow = true.
   */
  async evaluate(features: FeatureVector): Promise<RuleEvalResult[]> {
    const allRules = await this.loadRules();

    // F-003 kill switch: AGENT_RULES_ENABLED=false filters out any rule
    // sourced from the agent. Operator-authored rules (source ≠ 'agent')
    // are unaffected. Lets us shut down a misbehaving agent run in <60s
    // (cache TTL) without manually disabling each rule.
    const rules = config.fraud.agentRulesEnabled
      ? allRules
      : allRules.filter((r) => r.source !== 'agent');

    const results: RuleEvalResult[] = [];

    for (const rule of rules) {
      if (this.evaluateConditions(rule.conditions, features as unknown as Record<string, any>)) {
        results.push({
          ruleId: rule.id,
          ruleName: rule.name,
          action: rule.action,
          shadow: isShadowStatus(rule.status),
        });
      }
    }

    return results;
  }
}
