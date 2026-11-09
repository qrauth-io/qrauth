import { describe, it, expect } from 'vitest';
import { canGrantRole, canManageMember, grantableRoles } from '../member-roles.js';

describe('canManageMember', () => {
  it('lets an OWNER act on anyone, other owners included', () => {
    expect(canManageMember('OWNER', 'OWNER')).toBe(true);
    expect(canManageMember('OWNER', 'VIEWER')).toBe(true);
  });

  it('lets anyone else act only on lower roles', () => {
    expect(canManageMember('ADMIN', 'OWNER')).toBe(false);
    expect(canManageMember('ADMIN', 'ADMIN')).toBe(false);
    expect(canManageMember('ADMIN', 'MANAGER')).toBe(true);
    expect(canManageMember('MEMBER', 'VIEWER')).toBe(true);
  });
});

describe('canGrantRole', () => {
  it('only an OWNER makes an OWNER', () => {
    expect(canGrantRole('OWNER', 'OWNER')).toBe(true);
    expect(canGrantRole('ADMIN', 'OWNER')).toBe(false);
  });

  it('lets anyone else grant at most their own role', () => {
    expect(canGrantRole('ADMIN', 'ADMIN')).toBe(true);
    expect(canGrantRole('MANAGER', 'ADMIN')).toBe(false);
    expect(canGrantRole('MANAGER', 'VIEWER')).toBe(true);
  });
});

describe('grantableRoles', () => {
  it('lists the roles in order, highest first', () => {
    expect(grantableRoles('OWNER')).toEqual(['OWNER', 'ADMIN', 'MANAGER', 'MEMBER', 'VIEWER']);
    expect(grantableRoles('ADMIN')).toEqual(['ADMIN', 'MANAGER', 'MEMBER', 'VIEWER']);
  });
});
