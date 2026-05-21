import { describe, it, expect } from 'vitest';
import Fastify from 'fastify';
import { z } from 'zod';
import { zodValidator } from '../validate.js';

/**
 * The validation-error envelope must match server.ts setErrorHandler:
 * `message` is a human-readable string, `details` carries the structured
 * issues. A previous version sent the raw issue array as `message`, which
 * rendered as "[object Object]" in the CLI and dashboard.
 */
describe('zodValidator error envelope', () => {
  it('responds with a string message + structured details on invalid input', async () => {
    const app = Fastify();
    app.post(
      '/t',
      { preValidation: zodValidator({ body: z.object({ url: z.string().url() }) }) },
      async () => ({ ok: true }),
    );

    const res = await app.inject({ method: 'POST', url: '/t', payload: { url: 'not-a-url' } });

    expect(res.statusCode).toBe(400);
    const body = res.json();
    expect(body.error).toBe('Validation Error');
    expect(typeof body.message).toBe('string');
    expect(body.message).toContain('body.url');
    expect(body.message).not.toContain('[object Object]');
    expect(Array.isArray(body.details)).toBe(true);
    expect(body.details.length).toBeGreaterThan(0);

    await app.close();
  });

  it('joins multiple issues into one message and prefixes the request part', async () => {
    const app = Fastify();
    app.post(
      '/t',
      {
        preValidation: zodValidator({
          body: z.object({ a: z.string(), b: z.number() }),
        }),
      },
      async () => ({ ok: true }),
    );

    const res = await app.inject({ method: 'POST', url: '/t', payload: {} });

    expect(res.statusCode).toBe(400);
    const body = res.json();
    expect(body.message).toContain('body.a');
    expect(body.message).toContain('body.b');
    expect(body.message).toContain('; ');

    await app.close();
  });

  it('passes through and coerces valid input', async () => {
    const app = Fastify();
    app.post(
      '/t',
      { preValidation: zodValidator({ body: z.object({ n: z.coerce.number() }) }) },
      async (req) => req.body,
    );

    const res = await app.inject({ method: 'POST', url: '/t', payload: { n: '42' } });

    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ n: 42 });

    await app.close();
  });
});
