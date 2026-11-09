import { describe, it, expect, vi, beforeEach } from 'vitest';

const { fraudRuleCreate } = vi.hoisted(() => ({
  fraudRuleCreate: vi.fn(async ({ data }: { data: Record<string, unknown> }) => ({ id: 'rule_1', ...data })),
}));
vi.mock('@prisma/client', () => ({
  PrismaClient: class {
    fraudRule = { create: fraudRuleCreate };
  },
}));

import { TOOL_DEFINITIONS, executeTool } from '../tools/index.js';

const VALID_RULE = {
  name: 'burst-from-new-ips',
  description: 'Burst of scans from unseen IPs',
  conditions: [
    { field: 'scanVelocity5m', operator: 'gt', value: 30 },
    { field: 'isNewIp', operator: 'eq', value: true },
  ],
  action: { deductScore: 10, severity: 'MEDIUM', reason: 'burst_new_ips' },
};

beforeEach(() => {
  fraudRuleCreate.mockClear();
  vi.spyOn(console, 'info').mockImplementation(() => {});
});

describe('create_fraud_rule', () => {
  it('creates agent rules in SHADOW status, not evaluated as live (enabled false)', async () => {
    const out = JSON.parse(await executeTool('create_fraud_rule', VALID_RULE, 'run_shadow_1'));

    expect(out).toMatchObject({ created: true, ruleId: 'rule_1', status: 'SHADOW' });
    expect(fraudRuleCreate).toHaveBeenCalledWith({
      data: expect.objectContaining({ source: 'agent', status: 'SHADOW', enabled: false }),
    });
  });

  it('accepts every produced feature key, including ones the old list missed', async () => {
    const out = JSON.parse(
      await executeTool(
        'create_fraud_rule',
        { ...VALID_RULE, conditions: [{ field: 'timeSinceLastScan', operator: 'lt', value: 2 }] },
        'run_shadow_2',
      ),
    );

    expect(out.created).toBe(true);
  });

  it('rejects a field feature extraction does not produce', async () => {
    const out = JSON.parse(
      await executeTool(
        'create_fraud_rule',
        { ...VALID_RULE, conditions: [{ field: 'uniqueIps', operator: 'gt', value: 2 }] },
        'run_shadow_3',
      ),
    );

    expect(out.error).toBeDefined();
    expect(fraudRuleCreate).not.toHaveBeenCalled();
  });

  it('describes shadow mode and feature units to the agent', () => {
    const tool = TOOL_DEFINITIONS.find((t) => t.name === 'create_fraud_rule')!;
    const text = JSON.stringify(tool);

    expect(tool.description).toMatch(/shadow/i);
    expect(text).toMatch(/timeSinceLastScan[^"]*seconds/);
    expect(text).toMatch(/999999/);
    expect(text).toMatch(/UTC/);
  });
});
