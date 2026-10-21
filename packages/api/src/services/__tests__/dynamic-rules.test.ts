import { describe, it, expect, vi, beforeEach } from 'vitest';

// Force the DB path (no Redis) — cacheGet returns null by default; tests that
// exercise the cache-hit path override it.
const cacheGet = vi.fn(async () => null);
const cacheSet = vi.fn(async () => undefined);
vi.mock('../../lib/cache.js', () => ({
  cacheGet: (...args: unknown[]) => cacheGet(...args),
  cacheSet: (...args: unknown[]) => cacheSet(...args),
}));

vi.mock('../../lib/config.js', () => ({ config: { fraud: { agentRulesEnabled: true } } }));

import { config } from '../../lib/config.js';
import { DynamicRuleEngine } from '../dynamic-rules.js';

type AnyRule = any;

function engineWith(rules: AnyRule[]) {
  const findMany = vi.fn(async () => rules);
  const prisma = { fraudRule: { findMany } } as any;
  return { engine: new DynamicRuleEngine(prisma), findMany };
}

function rule(conditions: AnyRule[], over: Partial<AnyRule> = {}): AnyRule {
  return {
    id: 'r1',
    name: 'rule-1',
    conditions,
    action: { deductScore: 20, severity: 'HIGH', type: 'PATTERN_ANOMALY', reason: 'test' },
    priority: 1,
    source: 'operator',
    ...over,
  };
}

beforeEach(() => {
  cacheGet.mockReset().mockResolvedValue(null);
  cacheSet.mockReset().mockResolvedValue(undefined);
  config.fraud.agentRulesEnabled = true;
});

describe('DynamicRuleEngine.evaluate — operators', () => {
  const cases: Array<[string, AnyRule, Record<string, unknown>, boolean]> = [
    ['gt fires above threshold', { field: 'v', operator: 'gt', value: 10 }, { v: 11 }, true],
    ['gt does not fire at threshold', { field: 'v', operator: 'gt', value: 10 }, { v: 10 }, false],
    ['lt fires below', { field: 'v', operator: 'lt', value: 10 }, { v: 9 }, true],
    ['gte fires at threshold', { field: 'v', operator: 'gte', value: 10 }, { v: 10 }, true],
    ['lte fires at threshold', { field: 'v', operator: 'lte', value: 10 }, { v: 10 }, true],
    ['eq fires on equality', { field: 'v', operator: 'eq', value: 'bot' }, { v: 'bot' }, true],
    ['neq fires on inequality', { field: 'v', operator: 'neq', value: 'bot' }, { v: 'human' }, true],
    ['between fires inside range', { field: 'v', operator: 'between', value: [5, 15] }, { v: 10 }, true],
    ['between does not fire outside range', { field: 'v', operator: 'between', value: [5, 15] }, { v: 20 }, false],
    ['in fires on membership', { field: 'v', operator: 'in', value: ['a', 'b'] }, { v: 'b' }, true],
    ['in does not fire when absent', { field: 'v', operator: 'in', value: ['a', 'b'] }, { v: 'z' }, false],
  ];

  it.each(cases)('%s', async (_label, cond, features, shouldFire) => {
    const { engine } = engineWith([rule([cond])]);
    const results = await engine.evaluate(features as never);
    expect(results.length).toBe(shouldFire ? 1 : 0);
  });

  it('returns false when the referenced field is missing', async () => {
    const { engine } = engineWith([rule([{ field: 'missing', operator: 'gt', value: 0 }])]);
    const results = await engine.evaluate({ v: 1 } as never);
    expect(results).toHaveLength(0);
  });
});

describe('DynamicRuleEngine.evaluate — composition + shaping', () => {
  it('requires ALL conditions to match (AND semantics)', async () => {
    const r = rule([
      { field: 'a', operator: 'gt', value: 5 },
      { field: 'b', operator: 'eq', value: 'x' },
    ]);
    const { engine } = engineWith([r]);

    expect(await engine.evaluate({ a: 6, b: 'x' } as never)).toHaveLength(1);
    expect(await engine.evaluate({ a: 6, b: 'y' } as never)).toHaveLength(0);
  });

  it('shapes a fired result as { ruleId, ruleName, action }', async () => {
    const action = { deductScore: 33, severity: 'CRITICAL', type: 'PROXY_DETECTED', reason: 'vpn' };
    const { engine } = engineWith([
      rule([{ field: 'v', operator: 'gt', value: 0 }], { id: 'rX', name: 'proxy-rule', action }),
    ]);

    const [result] = await engine.evaluate({ v: 1 } as never);
    expect(result).toEqual({ ruleId: 'rX', ruleName: 'proxy-rule', action });
  });
});

describe('DynamicRuleEngine.evaluate — caching + agent kill switch', () => {
  it('uses the cache and skips the DB when rules are cached', async () => {
    cacheGet.mockResolvedValueOnce([rule([{ field: 'v', operator: 'gt', value: 0 }])]);
    const { engine, findMany } = engineWith([]);

    const results = await engine.evaluate({ v: 1 } as never);

    expect(results).toHaveLength(1);
    expect(findMany).not.toHaveBeenCalled();
  });

  it('drops agent-authored rules when AGENT_RULES_ENABLED is false', async () => {
    config.fraud.agentRulesEnabled = false;
    const { engine } = engineWith([
      rule([{ field: 'v', operator: 'gt', value: 0 }], { id: 'agentRule', source: 'agent' }),
      rule([{ field: 'v', operator: 'gt', value: 0 }], { id: 'opRule', source: 'operator' }),
    ]);

    const results = await engine.evaluate({ v: 1 } as never);

    expect(results.map((r) => r.ruleId)).toEqual(['opRule']);
  });
});
