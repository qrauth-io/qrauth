import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest';
import Fastify, { type FastifyInstance } from 'fastify';
import { JSDOM } from 'jsdom';

/**
 * The hosted approval page (/a/<token>) shows a readable message when a social
 * sign-in comes back with ?oauth_error=<code>, and removes the code from the URL.
 * The page script is a string inside the route, so this runs the real rendered
 * script in jsdom.
 */

process.env.REDIS_URL ??= 'redis://localhost:6379';
process.env.JWT_SECRET ??= 'a'.repeat(32);
process.env.ANIMATED_QR_SECRET ??= 'a'.repeat(64);
// One enabled provider so the page renders a social sign-in button.
process.env.GOOGLE_CLIENT_ID ??= 'google-client';
process.env.GOOGLE_CLIENT_SECRET ??= 'google-secret';
process.env.APPLE_CLIENT_ID ??= 'apple-client';
process.env.APPLE_CLIENT_SECRET ??= 'apple-secret';
process.env.MICROSOFT_CLIENT_ID ??= 'microsoft-client';
process.env.MICROSOFT_CLIENT_SECRET ??= 'microsoft-secret';

const TOKEN = `as_${'B'.repeat(32)}`;

vi.mock('../../services/auth-session.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../services/auth-session.js')>()),
  AuthSessionService: class {
    async getSessionByToken() {
      return {
        id: 'sess-1',
        status: 'SCANNED',
        expiresAt: new Date(Date.now() + 5 * 60_000),
        redirectUrl: null,
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

/** A JWT whose payload the page reads client-side (the signature is not checked there). */
function fakeSessionJwt(email: string): string {
  const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString('base64url');
  return `${b64({ alg: 'none' })}.${b64({ email, exp: Math.floor(Date.now() / 1000) + 600 })}.x`;
}

async function openPage(search: string, signedInAs?: string): Promise<JSDOM> {
  const res = await app.inject({ method: 'GET', url: `/a/${TOKEN}${search}` });
  expect(res.statusCode).toBe(200);
  const dom = new JSDOM(res.body, {
    url: `https://qrauth.test/a/${TOKEN}${search}`,
    runScripts: 'dangerously',
    beforeParse(window) {
      // No session in the browser: tryRefresh fails, so the sign-in form is shown.
      window.fetch = (async () => ({ ok: false, json: async () => ({}) })) as never;
      if (signedInAs) window.localStorage.setItem('jwt_access_token', fakeSessionJwt(signedInAs));
    },
  });
  await new Promise((resolve) => setTimeout(resolve, 50));
  return dom;
}

describe('approval page oauth_error', () => {
  it('shows the failure message on the sign-in form and strips oauth_error from the URL', async () => {
    const dom = await openPage('?oauth_error=failed&dr=1');
    const doc = dom.window.document;
    const banner = doc.getElementById('oauth-error');

    expect(banner?.style.display).toBe('block');
    expect(banner?.textContent).toContain("couldn't sign you in with that account");
    expect(dom.window.location.search).toBe('?dr=1');
    // Above the provider buttons, so it is on screen on a phone.
    const firstButton = doc.querySelector('.oauth-btn');
    expect(firstButton).not.toBeNull();
    expect(banner!.compareDocumentPosition(firstButton!) & dom.window.Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    // The bottom-of-form error line stays for email/password errors only.
    expect(doc.getElementById('auth-error')?.style.display).toBe('none');
  });

  it('shows the cancelled message', async () => {
    const dom = await openPage('?oauth_error=cancelled');

    expect(dom.window.document.getElementById('oauth-error')?.textContent).toBe('Sign-in was cancelled.');
    expect(dom.window.location.search).toBe('');
  });

  it('shows no error without oauth_error', async () => {
    const dom = await openPage('');

    expect(dom.window.document.getElementById('oauth-error')?.style.display).toBe('none');
  });

  it('explains that personal Microsoft accounts cannot be used', async () => {
    const dom = await openPage('?oauth_error=microsoft_personal');

    expect(dom.window.document.getElementById('oauth-error')?.textContent).toContain(
      "Personal Microsoft accounts (Outlook, Hotmail, Live) can't be used here.",
    );
  });

  it('shows a hint line under the Microsoft and Apple labels, and none for Google', async () => {
    const dom = await openPage('');
    const doc = dom.window.document;
    const hint = (p: string) => doc.querySelector(`.oauth-btn[data-provider="${p}"] .oauth-hint`)?.textContent;

    expect(doc.querySelector('.oauth-btn[data-provider="microsoft"]')?.textContent).toContain('Continue with Microsoft');
    expect(hint('microsoft')).toBe('Work or school accounts only');
    expect(hint('apple')).toBe('Choose “Share My Email” to use your account');
    expect(hint('google')).toBeUndefined();
  });

  it('labels an Apple "Hide My Email" address on the approve screen', async () => {
    const dom = await openPage('', 'p5c9s8h5rf@privaterelay.appleid.com');
    const doc = dom.window.document;

    expect(doc.getElementById('user-email')?.textContent).toBe('p5c9s8h5rf@privaterelay.appleid.com');
    expect(doc.getElementById('user-email-note')?.style.display).toBe('block');
  });

  it('shows no relay note for a normal address', async () => {
    const dom = await openPage('', 'jane@example.com');

    expect(dom.window.document.getElementById('user-email-note')?.style.display).toBe('none');
  });
});
