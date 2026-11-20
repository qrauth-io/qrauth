import { describe, it, expect } from 'vitest';
import { classifyProviderError, extractAadstsCode } from '../oauth-provider-error.js';

const description = (code: string) =>
  `AADSTS${code}: The user or administrator has not consented to use the application with ID 'x' named 'QRAuth'. Trace ID: abc`;

describe('classifyProviderError (Microsoft)', () => {
  it.each(['65001', '90094', '90095'])('AADSTS%s needs admin consent', (code) => {
    expect(classifyProviderError('microsoft', 'invalid_client', description(code))).toEqual({
      outcome: 'microsoft_admin_consent',
      error: 'invalid_client',
      aadstsCode: code,
    });
  });

  it('consent_required needs admin consent even without an AADSTS code', () => {
    expect(classifyProviderError('microsoft', 'consent_required', undefined)).toEqual({
      outcome: 'microsoft_admin_consent',
      error: 'consent_required',
    });
  });

  it('access_denied with an admin-consent code is admin consent, not a cancel', () => {
    expect(classifyProviderError('microsoft', 'access_denied', description('90094')).outcome).toBe('microsoft_admin_consent');
  });

  it('access_denied without those codes stays cancelled', () => {
    expect(classifyProviderError('microsoft', 'access_denied', description('65004'))).toEqual({
      outcome: 'cancelled',
      error: 'access_denied',
      aadstsCode: '65004',
    });
  });

  it('an unknown error is failed', () => {
    expect(classifyProviderError('microsoft', 'server_error', description('50000')).outcome).toBe('failed');
    expect(classifyProviderError('microsoft', undefined, undefined)).toEqual({ outcome: 'failed' });
  });

  it('does not match a longer code that merely starts with an admin-consent code', () => {
    expect(classifyProviderError('microsoft', 'invalid_request', 'AADSTS650010: other').outcome).toBe('failed');
  });

  it('drops an error value that is not a plain OAuth error token', () => {
    expect(classifyProviderError('microsoft', 'bad value\nforged=1', undefined)).toEqual({ outcome: 'failed' });
    expect(classifyProviderError('microsoft', ['access_denied'], undefined)).toEqual({ outcome: 'failed' });
  });
});

describe('classifyProviderError (other providers)', () => {
  it('keeps the existing mapping and ignores AADSTS codes', () => {
    expect(classifyProviderError('google', 'access_denied', undefined).outcome).toBe('cancelled');
    expect(classifyProviderError('google', 'consent_required', description('65001'))).toEqual({
      outcome: 'failed',
      error: 'consent_required',
    });
  });
});

describe('extractAadstsCode', () => {
  it('returns only the digits', () => {
    expect(extractAadstsCode(description('65001'))).toBe('65001');
  });

  it('returns undefined when there is no code or the value is not a string', () => {
    expect(extractAadstsCode('no code here')).toBeUndefined();
    expect(extractAadstsCode(42)).toBeUndefined();
  });
});
