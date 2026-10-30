import { describe, it, expect, vi } from 'vitest';
import { recordRuleIncidents } from '../rule-incidents.js';

const FEATURES = { scanVelocity5m: 12 } as never;
const ACTION = { deductScore: 10, severity: 'MEDIUM', type: 'PATTERN_ANOMALY', reason: 'burst' };

function makeDb(failOn?: string) {
  const created: Array<Record<string, unknown>> = [];
  const db = {
    fraudIncident: {
      create: vi.fn(async ({ data }: { data: Record<string, unknown> }) => {
        if (failOn && (data.details as { ruleId: string }).ruleId === failOn) throw new Error('dup');
        created.push(data);
        return data;
      }),
    },
  };
  return { db: db as never, created };
}

describe('recordRuleIncidents', () => {
  it('records an ACTIVE rule incident exactly as before (shadow false)', async () => {
    const { db, created } = makeDb();

    await recordRuleIncidents(db, { qrCodeId: 'qr_1', scanId: 's_1', features: FEATURES }, [
      { ruleId: 'r1', ruleName: 'live', action: ACTION, shadow: false },
    ]);

    expect(created).toEqual([
      {
        qrCodeId: 'qr_1',
        scanId: 's_1',
        type: 'PATTERN_ANOMALY',
        severity: 'MEDIUM',
        shadow: false,
        details: { reason: 'burst', ruleName: 'live', ruleId: 'r1', features: FEATURES },
      },
    ]);
  });

  it('marks incidents from SHADOW rules as shadow', async () => {
    const { db, created } = makeDb();

    await recordRuleIncidents(db, { qrCodeId: 'qr_1', scanId: 's_1', features: FEATURES }, [
      { ruleId: 'r2', ruleName: 'trial', action: ACTION, shadow: true },
    ]);

    expect(created[0]).toMatchObject({ shadow: true, details: { ruleId: 'r2' } });
  });

  it('continues past a failed insert', async () => {
    const { db, created } = makeDb('r1');

    await recordRuleIncidents(db, { qrCodeId: 'qr_1', scanId: 's_1', features: FEATURES }, [
      { ruleId: 'r1', ruleName: 'a', action: ACTION, shadow: false },
      { ruleId: 'r2', ruleName: 'b', action: ACTION, shadow: true },
    ]);

    expect(created.map((c) => (c.details as { ruleId: string }).ruleId)).toEqual(['r2']);
  });
});
