import { describe, it, expect } from 'vitest';

process.env.DATABASE_URL ??= 'postgresql://test:test@localhost:5432/test';
process.env.REDIS_URL ??= 'redis://localhost:6379';
process.env.JWT_SECRET ??= 'a'.repeat(32);

const { devMailPreview } = await import('../email.js');

describe('devMailPreview', () => {
  it('development without SMTP (jsonTransport): the logged message', () => {
    expect(devMailPreview({ message: JSON.stringify({ subject: 'Hi' }) }, true)).toEqual({ subject: 'Hi' });
  });

  it('development with a real SMTP host: no JSON message, no throw', () => {
    expect(devMailPreview({ message: undefined }, true)).toBeNull();
    expect(devMailPreview({}, true)).toBeNull();
    expect(devMailPreview({ message: Buffer.from('raw') }, true)).toBeNull();
    expect(devMailPreview({ message: 'not json' }, true)).toBeNull();
  });

  it('outside development: nothing', () => {
    expect(devMailPreview({ message: JSON.stringify({ subject: 'Hi' }) }, false)).toBeNull();
  });
});
