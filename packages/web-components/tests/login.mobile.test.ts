import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

// Importing the source module registers the custom element.
import '../src/login.js';
import { MOBILE_MEDIA_QUERY } from '../src/base.js';

type MatchMediaMock = (query: string) => { matches: boolean; media: string; addListener?: unknown };

function mockMatchMedia(matcher: MatchMediaMock): void {
  Object.defineProperty(window, 'matchMedia', {
    configurable: true,
    writable: true,
    value: matcher,
  });
}

function coarseMobileMatch(query: string) {
  return {
    matches: query === '(pointer: coarse)' || query === '(hover: none)' || query === MOBILE_MEDIA_QUERY,
    media: query,
    addListener: () => {},
    removeListener: () => {},
    onchange: null,
    dispatchEvent: () => false,
    addEventListener: () => {},
    removeEventListener: () => {},
  };
}

function desktopMatch(query: string) {
  return {
    matches: false,
    media: query,
    addListener: () => {},
    removeListener: () => {},
    onchange: null,
    dispatchEvent: () => false,
    addEventListener: () => {},
    removeEventListener: () => {},
  };
}

type LoginWithInternals = HTMLElement & {
  shadowRoot: ShadowRoot;
  _bodyForStatus?: (status: string, data?: Record<string, unknown>) => string;
  _sessionToken?: string | null;
};

async function mountLogin(attrs: Record<string, string> = {}): Promise<LoginWithInternals> {
  const el = document.createElement('qrauth-login') as LoginWithInternals;
  for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
  el.setAttribute('tenant', 'test-tenant');
  el.setAttribute('base-url', 'https://test.qrauth.io');
  document.body.appendChild(el);
  // Allow the connectedCallback render pass to run.
  await Promise.resolve();
  return el;
}

function pendingBodyHtml(el: LoginWithInternals, qrUrl = 'https://test.qrauth.io/a/test-token'): string {
  const bodyFn = (el as unknown as { _bodyForStatus: (s: string, d: Record<string, unknown>) => string })._bodyForStatus;
  return bodyFn.call(el, 'pending', { qrUrl });
}

describe('<qrauth-login> mobile-aware pending body', () => {
  beforeEach(() => {
    document.body.innerHTML = '';
  });

  afterEach(() => {
    document.body.innerHTML = '';
  });

  it('renders the mobile CTA + alt-device expander when force-mode="mobile"', async () => {
    mockMatchMedia(desktopMatch); // verify the force-mode attr wins over matchMedia
    const el = await mountLogin({ 'force-mode': 'mobile' });
    const html = pendingBodyHtml(el);
    expect(html).toContain('class="mobile-cta"');
    expect(html).toContain('Continue with QRAuth');
    expect(html).toContain('<details class="alt-device">');
    expect(html).toContain('<summary>Use another device</summary>');
    // QR frame is present but nested inside the expander, not at top level.
    expect(html.indexOf('<details class="alt-device">'))
      .toBeLessThan(html.indexOf('qr-frame'));
  });

  it('renders the QR-first desktop body when force-mode="desktop"', async () => {
    mockMatchMedia(coarseMobileMatch); // verify the force-mode attr wins over matchMedia
    const el = await mountLogin({ 'force-mode': 'desktop' });
    const html = pendingBodyHtml(el);
    expect(html).toContain('Scan this QR code with your phone camera');
    expect(html).not.toContain('class="mobile-cta"');
    expect(html).not.toContain('<details class="alt-device">');
  });

  it('keeps the QR-first body when mobile-fallback-only is set, even on coarse pointer', async () => {
    mockMatchMedia(coarseMobileMatch);
    const el = await mountLogin({ 'mobile-fallback-only': '' });
    const html = pendingBodyHtml(el);
    expect(html).toContain('Scan this QR code with your phone camera');
    expect(html).not.toContain('class="mobile-cta"');
  });

  it('auto-detects mobile via matchMedia (coarse + no-hover) and renders the mobile body', async () => {
    mockMatchMedia(coarseMobileMatch);
    const el = await mountLogin();
    const html = pendingBodyHtml(el);
    expect(html).toContain('class="mobile-cta"');
    expect(html).toContain('<details class="alt-device">');
  });

  it('opens the hosted approval page in a new tab when the mobile CTA is clicked', async () => {
    mockMatchMedia(coarseMobileMatch);
    const el = await mountLogin();
    // Prime session token on the element instance (bypass the network round-trip).
    (el as unknown as { _sessionToken: string })._sessionToken = 'tok-abc-123';

    // Re-render pending body + bind buttons by calling the public update path.
    const bodyEl = el.shadowRoot.getElementById('modal-body');
    if (bodyEl) bodyEl.innerHTML = pendingBodyHtml(el);
    // Re-bind via private hook.
    (el as unknown as { _bindModalButtons: () => void })._bindModalButtons();

    const openSpy = vi.spyOn(window, 'open').mockImplementation(() => ({} as Window));
    const cta = el.shadowRoot.getElementById('mobile-cta') as HTMLButtonElement;
    expect(cta).toBeTruthy();
    cta.click();

    expect(openSpy).toHaveBeenCalledWith(
      'https://test.qrauth.io/a/tok-abc-123',
      '_blank',
      'noopener',
    );
    openSpy.mockRestore();
  });

  it('falls back to same-tab navigation when window.open returns null (popup blocked)', async () => {
    mockMatchMedia(coarseMobileMatch);
    const el = await mountLogin();
    (el as unknown as { _sessionToken: string })._sessionToken = 'tok-blocked';

    const bodyEl = el.shadowRoot.getElementById('modal-body');
    if (bodyEl) bodyEl.innerHTML = pendingBodyHtml(el);
    (el as unknown as { _bindModalButtons: () => void })._bindModalButtons();

    vi.spyOn(window, 'open').mockImplementation(() => null);
    // happy-dom's Location doesn't allow href assignment by default — stub it.
    const hrefSetter = vi.fn();
    Object.defineProperty(window, 'location', {
      configurable: true,
      value: new Proxy({ href: '' }, {
        set(target, prop, value) {
          if (prop === 'href') hrefSetter(value);
          (target as Record<string, unknown>)[prop as string] = value;
          return true;
        },
      }),
    });

    const cta = el.shadowRoot.getElementById('mobile-cta') as HTMLButtonElement;
    cta.click();

    expect(hrefSetter).toHaveBeenCalledWith('https://test.qrauth.io/a/tok-blocked');
  });
});
