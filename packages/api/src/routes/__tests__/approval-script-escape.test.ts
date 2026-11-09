import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';

/**
 * Audit 2026-10 FINDING-024: the approval page writes the session token and
 * the stored redirect URL into an inline script. Neither may be able to end
 * the script element.
 */

process.env.REDIS_URL ??= 'redis://localhost:6379';
process.env.JWT_SECRET ??= 'a'.repeat(32);
process.env.ANIMATED_QR_SECRET ??= 'a'.repeat(64);

const HOSTILE_REDIRECT = 'https://shop.example/cb?x=</script><img src=x onerror=alert(1)>';

vi.mock('../../services/auth-session.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../services/auth-session.js')>()),
  AuthSessionService: class {
    async getSessionByToken() {
      return {
        id: 'sess-1',
        status: 'SCANNED',
        expiresAt: new Date(Date.now() + 5 * 60_000),
        redirectUrl: HOSTILE_REDIRECT,
        app: { slug: 'some-app', name: 'Some App' },
        scopes: [],
      };
    }
    async markScanned() {}
  },
}));

let app: FastifyInstance;

beforeAll(async () => {
  app = Fastify({ logger: false });
  app.decorate('prisma', {} as never);
  app.decorate('signingService', {} as never);
  const { default: approvalRoutes } = await import('../approval.js');
  await app.register(approvalRoutes, { prefix: '/a' });
  await app.ready();
});

afterAll(async () => {
  await app?.close();
});

/** Everything between the page script's opening tag and the first </script>. */
function pageScript(html: string): string {
  const start = html.indexOf('var TOKEN');
  expect(start).toBeGreaterThan(-1);
  return html.slice(start, html.indexOf('</script>', start));
}

describe('approval page inline script', () => {
  it('a redirect URL containing a closing script tag does not end the script', async () => {
    const res = await app.inject({ method: 'GET', url: `/a/as_${'B'.repeat(32)}` });

    expect(res.statusCode).toBe(200);
    expect(res.body).not.toContain('</script><img');
    // The script still runs to its real end: the code after the values is there.
    expect(pageScript(res.body)).toContain('WANT_REDIRECT');
    expect(pageScript(res.body)).toContain('\\u003c/script\\u003e\\u003cimg');
  });

  it('a token from the URL cannot break out of its string or the script', async () => {
    const hostile = `as_x';alert(1);//</script><script>alert(2)</script>`;

    const res = await app.inject({ method: 'GET', url: `/a/${encodeURIComponent(hostile)}` });

    // The token is a double-quoted JSON string now: its single quote ends
    // nothing, and its angle brackets are escapes.
    expect(res.body).toContain(String.raw`var TOKEN = "as_x';alert(1);//\u003c/script\u003e`);
    expect(res.body).not.toContain("var TOKEN = 'as_x'");
    expect(res.body).not.toContain('<script>alert(2)');
  });
});
