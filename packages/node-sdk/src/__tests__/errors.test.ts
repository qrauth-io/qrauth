import { describe, it, expect } from 'vitest';
import { formatApiErrorMessage } from '../errors.js';

describe('formatApiErrorMessage', () => {
  it('returns a plain string message unchanged', () => {
    expect(formatApiErrorMessage({ message: 'Not allowed' }, 'fallback')).toBe('Not allowed');
  });

  it('formats an array of Zod issues as "path: message" joined by "; "', () => {
    const body = {
      error: 'Validation Error',
      message: [
        { path: ['body', 'destinationUrl'], message: 'Invalid url' },
        { path: ['body', 'label'], message: 'Too long' },
      ],
    };

    expect(formatApiErrorMessage(body, 'fallback')).toBe(
      'body.destinationUrl: Invalid url; body.label: Too long',
    );
  });

  it('never yields "[object Object]" for an array message (the original bug)', () => {
    const body = { message: [{ path: ['body', 'x'], message: 'bad' }] };
    expect(formatApiErrorMessage(body, 'fallback')).not.toContain('[object Object]');
  });

  it('falls back to the error field when message is absent', () => {
    expect(formatApiErrorMessage({ error: 'Forbidden' }, 'fallback')).toBe('Forbidden');
  });

  it('uses the fallback for an empty, blank, or non-object body', () => {
    expect(formatApiErrorMessage({}, 'Bad Request')).toBe('Bad Request');
    expect(formatApiErrorMessage(null, 'Bad Request')).toBe('Bad Request');
    expect(formatApiErrorMessage({ message: '' }, 'Bad Request')).toBe('Bad Request');
  });

  it('tolerates issues missing a path or a message', () => {
    expect(formatApiErrorMessage({ message: [{ message: 'just a message' }] }, 'fb')).toBe('just a message');
    expect(formatApiErrorMessage({ message: [{ path: ['body', 'x'] }] }, 'fb')).toBe('body.x');
  });
});
