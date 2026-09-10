import { describe, it, expect } from 'vitest';
import { parsePrompt, isInvalidPromptCombo } from '../oidc-prompt.js';

describe('parsePrompt', () => {
  it('returns all-false for missing/empty prompt', () => {
    for (const raw of [undefined, null, '', '   ']) {
      const p = parsePrompt(raw);
      expect(p.none).toBe(false);
      expect(p.login).toBe(false);
      expect(p.values).toEqual([]);
    }
  });

  it('parses none', () => {
    const p = parsePrompt('none');
    expect(p.none).toBe(true);
    expect(p.login).toBe(false);
    expect(p.values).toEqual(['none']);
  });

  it('parses login', () => {
    const p = parsePrompt('login');
    expect(p.login).toBe(true);
    expect(p.none).toBe(false);
  });

  it('parses space-delimited multi-value (login consent) and ignores unknowns', () => {
    const p = parsePrompt('login consent');
    expect(p.login).toBe(true);
    expect(p.none).toBe(false);
    expect(p.values).toEqual(['login', 'consent']);
  });

  it('collapses extra whitespace', () => {
    expect(parsePrompt('  login   consent  ').values).toEqual(['login', 'consent']);
  });

  it('is case-sensitive (NONE is not none)', () => {
    expect(parsePrompt('NONE').none).toBe(false);
  });
});

describe('isInvalidPromptCombo', () => {
  it('flags none combined with another value', () => {
    expect(isInvalidPromptCombo(parsePrompt('none login'))).toBe(true);
    expect(isInvalidPromptCombo(parsePrompt('none consent'))).toBe(true);
  });
  it('allows none alone', () => {
    expect(isInvalidPromptCombo(parsePrompt('none'))).toBe(false);
  });
  it('allows non-none combinations', () => {
    expect(isInvalidPromptCombo(parsePrompt('login consent'))).toBe(false);
    expect(isInvalidPromptCombo(parsePrompt(''))).toBe(false);
  });
});
