import { describe, it, expect } from 'vitest';
import type { FastifyRequest } from 'fastify';
import { CODE_VERIFIER_HEADER, readCodeVerifier } from '../auth-session-verifier.js';

/**
 * Audit 2026-10 FINDING-013: the PKCE verifier for auth-session polling
 * travels in a header, which is not written to access logs. The query
 * parameter still works for web components already deployed.
 */

const request = (headers: Record<string, unknown>, query: Record<string, unknown> = {}) =>
  ({ headers, query }) as unknown as FastifyRequest;

describe('readCodeVerifier', () => {
  it('names the header', () => {
    expect(CODE_VERIFIER_HEADER).toBe('x-qrauth-code-verifier');
  });

  it('reads the header', () => {
    expect(readCodeVerifier(request({ 'x-qrauth-code-verifier': 'verifier-from-header' }))).toBe('verifier-from-header');
  });

  it('falls back to the query parameter', () => {
    expect(readCodeVerifier(request({}, { code_verifier: 'verifier-from-query' }))).toBe('verifier-from-query');
  });

  it('prefers the header when both are sent', () => {
    expect(
      readCodeVerifier(request({ 'x-qrauth-code-verifier': 'from-header' }, { code_verifier: 'from-query' })),
    ).toBe('from-header');
  });

  it('returns undefined when neither is a usable string', () => {
    expect(readCodeVerifier(request({}))).toBeUndefined();
    expect(readCodeVerifier(request({ 'x-qrauth-code-verifier': '' }, { code_verifier: '' }))).toBeUndefined();
    expect(readCodeVerifier(request({ 'x-qrauth-code-verifier': ['a', 'b'] }, { code_verifier: ['a', 'b'] }))).toBeUndefined();
  });
});
