import { describe, expect, it } from 'vitest';

import {
  ALLOWLIST_MAX_ENTRIES,
  higherRole,
  orgPolicyPreviewSchema,
  orgPolicyUpdateSchema,
  roleAtLeast,
} from '../org-policy.js';
import { qrListFilterSchema } from '../qr-organize.js';

describe('roleAtLeast and higherRole', () => {
  it('orders roles OWNER > ADMIN > MANAGER > MEMBER > VIEWER', () => {
    expect(roleAtLeast('OWNER', 'ADMIN')).toBe(true);
    expect(roleAtLeast('MANAGER', 'MANAGER')).toBe(true);
    expect(roleAtLeast('MEMBER', 'MANAGER')).toBe(false);
    expect(roleAtLeast('VIEWER', 'MEMBER')).toBe(false);
    expect(roleAtLeast('SUPERADMIN', 'MEMBER')).toBe(false);
    expect(higherRole('MEMBER', 'MANAGER')).toBe('MANAGER');
    expect(higherRole('ADMIN', 'MANAGER')).toBe('ADMIN');
  });
});

describe('orgPolicyUpdateSchema', () => {
  const valid = { allowlistMode: 'ENFORCE', allowlist: [{ domain: 'example.com' }], destinationEditMinRole: 'MANAGER' };

  it('defaults includeSubdomains to true', () => {
    expect(orgPolicyUpdateSchema.parse(valid).allowlist).toEqual([{ domain: 'example.com', includeSubdomains: true }]);
  });

  it('refuses OWNER or VIEWER as the minimum, unknown modes and unknown fields', () => {
    expect(orgPolicyUpdateSchema.safeParse({ ...valid, destinationEditMinRole: 'OWNER' }).success).toBe(false);
    expect(orgPolicyUpdateSchema.safeParse({ ...valid, destinationEditMinRole: 'VIEWER' }).success).toBe(false);
    expect(orgPolicyUpdateSchema.safeParse({ ...valid, allowlistMode: 'WARN' }).success).toBe(false);
    expect(orgPolicyUpdateSchema.safeParse({ ...valid, organizationId: 'x' }).success).toBe(false);
    expect(orgPolicyUpdateSchema.safeParse({ ...valid, allowlist: [{ domain: 'a.com', note: 'x' }] }).success).toBe(false);
  });

  it(`holds at most ${ALLOWLIST_MAX_ENTRIES} entries`, () => {
    const entries = (n: number) => Array.from({ length: n }, (_, i) => ({ domain: `d${i}.example` }));
    expect(orgPolicyPreviewSchema.safeParse({ allowlist: entries(ALLOWLIST_MAX_ENTRIES) }).success).toBe(true);
    expect(orgPolicyPreviewSchema.safeParse({ allowlist: entries(ALLOWLIST_MAX_ENTRIES + 1) }).success).toBe(false);
  });
});

describe('qrListFilterSchema outsidePolicy', () => {
  it('reads "true" and "false" as booleans and refuses anything else', () => {
    expect(qrListFilterSchema.parse({ outsidePolicy: 'true' }).outsidePolicy).toBe(true);
    expect(qrListFilterSchema.parse({ outsidePolicy: 'false' }).outsidePolicy).toBe(false);
    expect(qrListFilterSchema.parse({}).outsidePolicy).toBeUndefined();
    expect(qrListFilterSchema.safeParse({ outsidePolicy: '1' }).success).toBe(false);
  });
});
