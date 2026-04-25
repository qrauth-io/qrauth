import { describe, it, expect, beforeEach, afterEach } from 'vitest';

// Importing the source module registers the custom element.
import '../src/ephemeral.js';

type EphemeralEl = HTMLElement & {
  shadowRoot: ShadowRoot;
  forceMode: 'mobile' | 'desktop' | 'auto';
  mobileFallbackOnly: boolean;
};

async function mountEphemeral(attrs: Record<string, string> = {}): Promise<EphemeralEl> {
  const el = document.createElement('qrauth-ephemeral') as EphemeralEl;
  for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
  el.setAttribute('tenant', 'test-tenant');
  el.setAttribute('base-url', 'https://test.qrauth.io');
  document.body.appendChild(el);
  await Promise.resolve();
  return el;
}

describe('<qrauth-ephemeral> force-mode plumbing (0.3.0)', () => {
  beforeEach(() => { document.body.innerHTML = ''; });
  afterEach(() => { document.body.innerHTML = ''; });

  it('exposes force-mode getter with expected defaults', async () => {
    const el = await mountEphemeral();
    expect(el.forceMode).toBe('auto');
    expect(el.mobileFallbackOnly).toBe(false);
  });

  it('reads force-mode="mobile" and "desktop" correctly', async () => {
    const elMobile = await mountEphemeral({ 'force-mode': 'mobile' });
    expect(elMobile.forceMode).toBe('mobile');

    document.body.innerHTML = '';
    const elDesktop = await mountEphemeral({ 'force-mode': 'desktop' });
    expect(elDesktop.forceMode).toBe('desktop');
  });

  it('falls back to "auto" when force-mode has an unrecognised value', async () => {
    const el = await mountEphemeral({ 'force-mode': 'nonsense' });
    expect(el.forceMode).toBe('auto');
  });

  it('reflects mobile-fallback-only as boolean attribute', async () => {
    const el = await mountEphemeral({ 'mobile-fallback-only': '' });
    expect(el.mobileFallbackOnly).toBe(true);
  });

  it('observes force-mode so setAttribute triggers the render pipeline', async () => {
    const el = await mountEphemeral();
    const observed = (customElements.get('qrauth-ephemeral') as unknown as { observedAttributes: string[] }).observedAttributes;
    expect(observed).toContain('force-mode');
    expect(observed).toContain('mobile-fallback-only');
  });

  it('renders the SAME markup across force-mode values (no default mobile UI change in 0.3.0)', async () => {
    const desktopEl = await mountEphemeral({ 'force-mode': 'desktop' });
    const desktopHtml = desktopEl.shadowRoot.innerHTML;
    document.body.innerHTML = '';

    const mobileEl = await mountEphemeral({ 'force-mode': 'mobile' });
    const mobileHtml = mobileEl.shadowRoot.innerHTML;

    // Both render paths produce the same inline idle start button.
    expect(desktopHtml).toContain('Get Access QR');
    expect(mobileHtml).toContain('Get Access QR');
    // Neither should contain the mobile-CTA class that <qrauth-login>/<qrauth-2fa> use.
    expect(desktopHtml).not.toContain('class="mobile-cta"');
    expect(mobileHtml).not.toContain('class="mobile-cta"');
  });
});
