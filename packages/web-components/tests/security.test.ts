import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

import '../src/login.js';
import '../src/twofa.js';
import '../src/ephemeral.js';
import { QRAuthElement, safeRedirectTarget } from '../src/base.js';

/**
 * Audit 2026-10 FINDING-014, FINDING-013 (verifier) and FINDING-027.
 *   - Text that came from the server is shown as text, never parsed as HTML.
 *   - The PKCE verifier travels in a header, not in the polled URL.
 *   - `redirect-url` only takes the browser to an http(s) or same-origin URL.
 */

const MARKUP = '<img src=x onerror="window.__pwned = 1"><b>bold</b> redirectUrl "<script>1</script>"';

type Internals = HTMLElement & {
  shadowRoot: ShadowRoot;
  _startAuth?: () => Promise<void>;
  _startSession?: () => Promise<void>;
  _handleStatusChange: (status: string, data?: unknown) => void;
};

async function mount(tag: string, attrs: Record<string, string> = {}): Promise<Internals> {
  const el = document.createElement(tag) as Internals;
  el.setAttribute('tenant', 'test-tenant');
  el.setAttribute('base-url', 'https://test.qrauth.io');
  for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
  document.body.appendChild(el);
  await Promise.resolve();
  return el;
}

const jsonResponse = (status: number, body: unknown) =>
  ({ ok: status >= 200 && status < 300, status, json: async () => body }) as Response;

beforeEach(() => {
  document.body.innerHTML = '';
  delete (window as unknown as Record<string, unknown>).__pwned;
});

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
  document.body.innerHTML = '';
});

describe('server error text is rendered as text (FINDING-014)', () => {
  const cases: Array<[string, Record<string, string>, (el: Internals) => Promise<void>]> = [
    ['qrauth-login', { display: 'inline' }, (el) => el._startAuth!()],
    ['qrauth-2fa', { 'session-token': 'tok' }, (el) => el._startAuth!()],
    ['qrauth-ephemeral', { display: 'inline' }, (el) => el._startSession!()],
  ];

  it.each(cases)('<%s> creates no element from an error message containing markup', async (tag, attrs, start) => {
    vi.stubGlobal('fetch', vi.fn(async () => jsonResponse(400, { message: MARKUP })));
    const el = await mount(tag, attrs);

    await start(el);

    const root = el.shadowRoot;
    expect(root.querySelector('img')).toBeNull();
    expect(root.querySelector('script')).toBeNull();
    expect(root.querySelector('.state-error b')).toBeNull();
    expect(root.querySelector('.state-error .subtitle')?.textContent).toBe(MARKUP);
    expect((window as unknown as Record<string, unknown>).__pwned).toBeUndefined();
  });

  it.each(cases)('<%s> still shows its own default text when the server sends none', async (tag, attrs, start) => {
    vi.stubGlobal('fetch', vi.fn(async () => jsonResponse(500, {})));
    const el = await mount(tag, attrs);

    await start(el);

    const text = el.shadowRoot.querySelector('.state-error .subtitle')?.textContent ?? '';
    expect(text.length).toBeGreaterThan(5);
  });
});

describe('the PKCE verifier is sent in a header when polling (FINDING-013)', () => {
  const session = {
    sessionId: 'sess_1',
    token: 'as_tok',
    qrUrl: 'https://test.qrauth.io/a/as_tok',
    expiresAt: new Date(Date.now() + 300_000).toISOString(),
  };

  it.each([
    ['qrauth-login', { display: 'inline' }],
    ['qrauth-2fa', { 'session-token': 'tok' }],
  ] as Array<[string, Record<string, string>]>)('<%s>', async (tag, attrs) => {
    vi.useFakeTimers();
    const fetchMock = vi.fn(async (url: string, init?: RequestInit) =>
      init?.method === 'POST' ? jsonResponse(201, session) : jsonResponse(200, { sessionId: 'sess_1', status: 'PENDING' }),
    );
    vi.stubGlobal('fetch', fetchMock);
    const el = await mount(tag, attrs);

    await el._startAuth!();
    await vi.advanceTimersByTimeAsync(2100);

    const poll = fetchMock.mock.calls.find(([url, init]) => String(url).includes('/auth-sessions/sess_1') && init?.method !== 'POST');
    expect(poll, 'a poll request was made').toBeDefined();
    const [url, init] = poll!;
    expect(String(url)).toBe('https://test.qrauth.io/api/v1/auth-sessions/sess_1');
    expect(String(url)).not.toContain('code_verifier');
    const headers = init!.headers as Record<string, string>;
    expect(headers['X-QRAuth-Code-Verifier']).toMatch(/^[A-Za-z0-9._~-]{43,128}$/);
    expect(headers['X-Client-Id']).toBe('test-tenant');
  });
});

describe('an approval that comes back without the user', () => {
  it.each([
    ['qrauth-login', { display: 'inline' }, 'qrauth:authenticated'],
    ['qrauth-2fa', { 'session-token': 'tok' }, 'qrauth:verified'],
  ] as Array<[string, Record<string, string>, string]>)('<%s> reports an error, not a sign-in', async (tag, attrs, successEvent) => {
    const el = await mount(tag, attrs);
    const events: string[] = [];
    el.addEventListener(successEvent, () => events.push('success'));
    el.addEventListener('qrauth:error', () => events.push('error'));
    // As after _startAuth: a PKCE verifier was generated for this session.
    (el as unknown as { _codeVerifier: string })._codeVerifier = 'v'.repeat(43);

    el._handleStatusChange('APPROVED', { sessionId: 's', status: 'APPROVED', user: null, signature: null });

    expect(events).toEqual(['error']);
    expect(el.shadowRoot.querySelector('.state-error')).not.toBeNull();
  });
});

describe('<qrauth-login on-auth>', () => {
  const globals = window as unknown as Record<string, unknown>;

  afterEach(() => {
    delete globals.onLoginOk;
    delete globals.onLoginThrows;
  });

  async function approveWith(onAuth: string): Promise<{ navigate: ReturnType<typeof vi.fn> }> {
    vi.useFakeTimers();
    const navigate = vi.fn();
    vi.spyOn(QRAuthElement.prototype as unknown as { navigate: (url: string) => void }, 'navigate').mockImplementation(navigate);
    vi.spyOn(console, 'error').mockImplementation(() => undefined);
    const el = await mount('qrauth-login', { display: 'inline', 'on-auth': onAuth, 'redirect-url': '/done' });
    el._handleStatusChange('APPROVED', { sessionId: 's', status: 'APPROVED', user: { id: 'u' } });
    await vi.advanceTimersByTimeAsync(1600);
    return { navigate };
  }

  it('calls a function defined on window with the result', async () => {
    const seen: unknown[] = [];
    globals.onLoginOk = (data: unknown) => seen.push(data);

    await approveWith('onLoginOk');

    expect(seen).toHaveLength(1);
    expect(seen[0]).toMatchObject({ sessionId: 's' });
  });

  it('still redirects when the callback throws', async () => {
    globals.onLoginThrows = () => { throw new Error('boom'); };

    const { navigate } = await approveWith('onLoginThrows');

    expect(navigate).toHaveBeenCalledTimes(1);
  });

  it.each(['constructor', 'toString'])('does not call the inherited %s', async (name) => {
    const inherited = vi.fn();
    const proto = Object.getPrototypeOf(window) as Record<string, unknown>;
    const had = Object.prototype.hasOwnProperty.call(globals, name);
    const original = globals[name];
    if (had) delete globals[name];
    const protoOriginal = proto[name];
    proto[name] = inherited;
    try {
      const { navigate } = await approveWith(name);

      expect(inherited).not.toHaveBeenCalled();
      expect(navigate).toHaveBeenCalledTimes(1);
    } finally {
      proto[name] = protoOriginal;
      if (had) globals[name] = original;
    }
  });
});

describe('safeRedirectTarget (FINDING-027)', () => {
  const page = 'https://shop.example/checkout/login';

  it.each([
    ['/account', 'https://shop.example/account'],
    ['welcome?x=1', 'https://shop.example/checkout/welcome?x=1'],
    ['https://shop.example/home', 'https://shop.example/home'],
    ['https://other.example/landing', 'https://other.example/landing'],
    ['http://localhost:3000/cb', 'http://localhost:3000/cb'],
    ['//cdn.example/x', 'https://cdn.example/x'],
  ])('allows %s', (raw, expected) => {
    expect(safeRedirectTarget(raw, page)).toBe(expected);
  });

  it.each([
    'javascript:alert(1)',
    'JaVaScRiPt:alert(1)',
    ' javascript:alert(1)',
    'data:text/html,<script>alert(1)</script>',
    'vbscript:x',
    'file:///etc/passwd',
    'blob:https://shop.example/1',
    'java\nscript:alert(1)',
    'java\tscript:alert(1)',
    'myapp://open',
    '',
    '   ',
  ])('refuses %j', (raw) => {
    expect(safeRedirectTarget(raw, page)).toBeNull();
  });
});

describe('<qrauth-login redirect-url> (FINDING-027)', () => {
  async function approve(redirectUrl: string): Promise<{ navigate: ReturnType<typeof vi.fn>; warn: ReturnType<typeof vi.fn> }> {
    vi.useFakeTimers();
    const navigate = vi.fn();
    vi.spyOn(QRAuthElement.prototype as unknown as { navigate: (url: string) => void }, 'navigate').mockImplementation(navigate);
    const warn = vi.fn();
    vi.spyOn(console, 'warn').mockImplementation(warn);
    const el = await mount('qrauth-login', { display: 'inline', 'redirect-url': redirectUrl });

    el._handleStatusChange('APPROVED', { sessionId: 's', status: 'APPROVED', user: { id: 'u' } });
    await vi.advanceTimersByTimeAsync(1600);
    return { navigate, warn };
  }

  it('goes to an https URL', async () => {
    const { navigate } = await approve('https://shop.example/home');

    expect(navigate).toHaveBeenCalledWith('https://shop.example/home');
  });

  it('ignores a javascript: URL and says so in the console', async () => {
    const { navigate, warn } = await approve('javascript:alert(document.cookie)');

    expect(navigate).not.toHaveBeenCalled();
    expect(warn).toHaveBeenCalledTimes(1);
    expect(String(warn.mock.calls[0][0])).toContain('redirect-url');
  });
});
