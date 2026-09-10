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

  /**
   * Contract test. This is the guard that was MISSING when zod v4 silently
   * changed its internal issue object: the 400 envelope and the per-issue
   * `details[]` shape are part of the public API and must stay stable
   * regardless of the validation library's internals. If a future
   * dependency bump (or a refactor) reshapes these, this test fails loudly.
   */
  it('emits the stable 400 envelope: { statusCode, error, message, details:[{path,code,message}] }', async () => {
    const app = Fastify();
    app.post(
      '/t',
      { preValidation: zodValidator({ body: z.object({ email: z.string().email() }) }) },
      async () => ({ ok: true }),
    );

    const res = await app.inject({ method: 'POST', url: '/t', payload: { email: 'nope' } });

    expect(res.statusCode).toBe(400);
    const body = res.json();

    // Envelope contract.
    expect(body.statusCode).toBe(400);
    expect(body.error).toBe('Validation Error');
    expect(typeof body.message).toBe('string');
    expect(Array.isArray(body.details)).toBe(true);
    expect(body.details.length).toBeGreaterThan(0);

    // Per-issue contract: exactly { path, code, message } — no leaked zod internals.
    const issue = body.details[0];
    expect(Object.keys(issue).sort()).toEqual(['code', 'message', 'path']);
    expect(Array.isArray(issue.path)).toBe(true);
    expect(issue.path.every((segment: unknown) => typeof segment === 'string')).toBe(true);
    expect(issue.path[0]).toBe('body'); // request-part prefix preserved
    expect(issue.path).toEqual(['body', 'email']);
    expect(typeof issue.code).toBe('string');
    expect(typeof issue.message).toBe('string');

    await app.close();
  });
});
