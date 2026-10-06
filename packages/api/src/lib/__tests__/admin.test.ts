import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { isAdminEmail, isSuperAdmin, isVerifiedAdmin } from '../admin.js';

/**
 * Superadmin is granted by address (ADMIN_EMAILS), but only for an address
 * the account has verified: an account can hold an unverified address.
 */

const ADMIN = 'admin@qrauth.example';
let before: string | undefined;

beforeEach(() => {
  before = process.env.ADMIN_EMAILS;
  process.env.ADMIN_EMAILS = `${ADMIN}, second@qrauth.example`;
});

afterEach(() => {
  if (before === undefined) delete process.env.ADMIN_EMAILS;
  else process.env.ADMIN_EMAILS = before;
});

function db(account: { email: string; emailVerified: boolean } | null) {
  return { user: { findUnique: vi.fn(async () => account) } };
}

describe('isSuperAdmin', () => {
  it('is true for a verified admin-list address', () => {
    expect(isSuperAdmin({ email: ADMIN, emailVerified: true })).toBe(true);
  });

  it('is false for an UNVERIFIED admin-list address', () => {
    expect(isSuperAdmin({ email: ADMIN, emailVerified: false })).toBe(false);
  });

  it('is false for a verified address that is not on the list, and for no user', () => {
    expect(isSuperAdmin({ email: 'member@example.com', emailVerified: true })).toBe(false);
    expect(isSuperAdmin(null)).toBe(false);
    expect(isSuperAdmin(undefined)).toBe(false);
  });

  it('fails closed when ADMIN_EMAILS is unset', () => {
    delete process.env.ADMIN_EMAILS;
    expect(isSuperAdmin({ email: ADMIN, emailVerified: true })).toBe(false);
  });
});

describe('isVerifiedAdmin', () => {
  it('grants a verified account whose address is on the list', async () => {
    await expect(isVerifiedAdmin(db({ email: ADMIN, emailVerified: true }), { id: 'u_1', email: ADMIN }))
      .resolves.toBe(true);
  });

  it('refuses an UNVERIFIED account whose address is on the list', async () => {
    await expect(isVerifiedAdmin(db({ email: ADMIN, emailVerified: false }), { id: 'u_1', email: ADMIN }))
      .resolves.toBe(false);
  });

  it('refuses an address that is not on the list without reading the database', async () => {
    const database = db({ email: 'member@example.com', emailVerified: true });
    await expect(isVerifiedAdmin(database, { id: 'u_1', email: 'member@example.com' })).resolves.toBe(false);
    expect(database.user.findUnique).not.toHaveBeenCalled();
  });

  it('refuses when the token says admin but the account row no longer holds that address', async () => {
    await expect(isVerifiedAdmin(db({ email: 'renamed@example.com', emailVerified: true }), { id: 'u_1', email: ADMIN }))
      .resolves.toBe(false);
  });

  it('refuses when there is no request user, no account row, or an API-key identity with no email', async () => {
    await expect(isVerifiedAdmin(db(null), { id: 'u_gone', email: ADMIN })).resolves.toBe(false);
    await expect(isVerifiedAdmin(db({ email: ADMIN, emailVerified: true }), undefined)).resolves.toBe(false);
    await expect(isVerifiedAdmin(db({ email: ADMIN, emailVerified: true }), { id: 'k_1', email: '' })).resolves.toBe(false);
  });

  it('isAdminEmail alone still only answers whether the address is listed', () => {
    expect(isAdminEmail(ADMIN)).toBe(true);
    expect(isAdminEmail('')).toBe(false);
  });
});
