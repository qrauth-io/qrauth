/**
 * QRAuthElement — base class for all QRAuth Web Components.
 * Provides: Shadow DOM setup, CSS custom property theming, SSE connection management,
 * lifecycle hooks, and event dispatching.
 */

/**
 * Media query that identifies mobile-like devices (coarse pointer + no hover).
 * Exported for documentation and test mocks.
 */
export const MOBILE_MEDIA_QUERY = '(pointer: coarse) and (hover: none)';

/** Header the API reads the PKCE verifier from when an auth session is polled. */
export const CODE_VERIFIER_HEADER = 'X-QRAuth-Code-Verifier';

/**
 * Where `redirect-url` may send the browser: an http(s) URL, or a relative
 * one resolved against the current page. Anything that does not resolve to
 * http(s), `javascript:` and `data:` in particular, is refused. Returns the
 * absolute URL to navigate to, or null. This is a scheme check, not an
 * origin check: an absolute URL on another site is allowed, as documented.
 */
export function safeRedirectTarget(raw: string | null | undefined, pageUrl: string): string | null {
  const value = (raw ?? '').trim();
  if (!value) return null;
  let target: URL;
  try {
    target = new URL(value, pageUrl);
  } catch {
    return null;
  }
  return target.protocol === 'https:' || target.protocol === 'http:' ? target.href : null;
}

export abstract class QRAuthElement extends HTMLElement {
  protected shadow: ShadowRoot;
  private _sseConnection: EventSource | null = null;
  private _pollInterval: ReturnType<typeof setInterval> | null = null;

  static get observedAttributes(): string[] {
    return ['tenant', 'theme', 'base-url', 'force-mode', 'mobile-fallback-only'];
  }

  constructor() {
    super();
    this.shadow = this.attachShadow({ mode: 'open' });
  }

  // Getters for common attributes
  get tenant(): string { return this.getAttribute('tenant') || ''; }
  get theme(): string { return this.getAttribute('theme') || 'light'; }
  get baseUrl(): string {
    const val = this.getAttribute('base-url');
    // Allow empty string for local dev (relative URLs), fallback to production
    return val !== null ? val : 'https://qrauth.io';
  }

  connectedCallback(): void {
    this.render();
  }

  disconnectedCallback(): void {
    this.cleanup();
  }

  attributeChangedCallback(_name: string, oldValue: string | null, newValue: string | null): void {
    if (oldValue !== newValue) {
      this.render();
    }
  }

  // Subclasses implement this
  protected abstract render(): void;

  /**
   * Detect whether the component is running on a mobile-like device. Subclasses
   * may use this to branch UX — e.g. `<qrauth-login>` swaps the big QR for a
   * "Continue on this device" CTA when isMobileLike() returns true, since the
   * scan-with-another-device flow is a dead end when the user already IS the
   * phone. Resolution order:
   *
   *   1. `force-mode="mobile"` or `force-mode="desktop"` attribute — wins.
   *   2. `mobile-fallback-only` attribute — always returns false (keeps the
   *      component's QR-only behaviour even on phones; consumers opt in here
   *      when they provide their own alternative flow around the component).
   *   3. matchMedia on `(pointer: coarse)` + `(hover: none)` (both must match).
   *   4. UA sniff fallback for environments without matchMedia (headless tests,
   *      old browsers).
   */
  protected isMobileLike(): boolean {
    if (typeof window === 'undefined') return false;
    const forced = this.getAttribute('force-mode');
    if (forced === 'mobile') return true;
    if (forced === 'desktop') return false;
    if (this.hasAttribute('mobile-fallback-only')) return false;
    if (typeof window.matchMedia === 'function') {
      const coarse = window.matchMedia('(pointer: coarse)').matches;
      const noHover = window.matchMedia('(hover: none)').matches;
      if (coarse && noHover) return true;
    }
    return /Android|iPhone|iPad|iPod|Mobile|Tablet|BlackBerry|Opera Mini/i
      .test(navigator.userAgent);
  }

  // --- SSE Management ---
  protected connectSSE(url: string): void {
    this.disconnectSSE();
    // EventSource doesn't support custom headers natively.
    // For public (unauthenticated) SSE endpoints this works directly.
    this._sseConnection = new EventSource(url);

    this._sseConnection.onerror = () => {
      // Fall back to polling on SSE failure — caller should initiate polling
      this.disconnectSSE();
    };
  }

  protected onSSEEvent(event: string, callback: (data: unknown) => void): void {
    if (this._sseConnection) {
      this._sseConnection.addEventListener(event, (e: Event) => {
        const msg = e as MessageEvent;
        try { callback(JSON.parse(msg.data as string)); } catch { /* invalid JSON */ }
      });
    }
  }

  protected disconnectSSE(): void {
    if (this._sseConnection) {
      this._sseConnection.close();
      this._sseConnection = null;
    }
  }

  // --- Polling (fallback / primary for authenticated endpoints) ---
  protected startPolling(
    url: string,
    intervalMs: number,
    callback: (data: unknown) => void,
    headers?: Record<string, string>,
  ): void {
    this.stopPolling();
    const poll = async () => {
      try {
        const res = await fetch(url, { headers });
        if (res.ok) callback(await res.json());
      } catch { /* network error — retry next interval */ }
    };
    poll(); // immediate first poll
    this._pollInterval = setInterval(poll, intervalMs);
  }

  protected stopPolling(): void {
    if (this._pollInterval) {
      clearInterval(this._pollInterval);
      this._pollInterval = null;
    }
  }

  // --- Cleanup ---
  protected cleanup(): void {
    this.disconnectSSE();
    this.stopPolling();
  }

  // --- Event dispatch ---
  /**
   * Put a message into the rendered error state as text. The message can come
   * from the API, so it is never parsed as HTML; the template only supplies
   * the element and its default wording.
   */
  protected setErrorText(message: string | null | undefined): void {
    if (!message) return;
    const target = this.shadow.querySelector('.state-error .subtitle');
    if (target) target.textContent = message;
  }

  /**
   * True when a PKCE-bound session came back APPROVED without the user: the
   * API did not accept the verifier (an API older than the verifier header
   * ignores it). There is no identity to hand to the page, so this must not
   * be reported as a successful sign-in.
   */
  protected isApprovalWithoutIdentity(sentVerifier: boolean, data: { user?: unknown } | undefined): boolean {
    return sentVerifier && !data?.user;
  }

  /**
   * Call the function named by an `on-*` attribute. Only an own property of
   * `window` is called, not an inherited one (`constructor`, `toString`), and
   * a throwing callback does not stop the component. Built-ins such as
   * `alert` are own properties of `window` in browsers, so the attribute must
   * still come from the embedding page's own markup, as documented.
   */
  protected callGlobal(name: string | null, payload: unknown): void {
    if (!name || !Object.prototype.hasOwnProperty.call(window, name)) return;
    const callback = (window as unknown as Record<string, unknown>)[name];
    if (typeof callback !== 'function') return;
    try {
      (callback as (d: unknown) => void).call(window, payload);
    } catch (err) {
      console.error(`[qrauth] ${name} threw:`, err);
    }
  }

  /** Leave the page. Separate so it can be observed in tests. */
  protected navigate(url: string): void {
    window.location.href = url;
  }

  protected emit(name: string, detail?: unknown): void {
    this.dispatchEvent(new CustomEvent(name, {
      bubbles: true,
      composed: true, // crosses shadow DOM boundary
      detail,
    }));
  }

  // --- PKCE helpers ---
  protected async generateCodeVerifier(): Promise<string> {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    return this._base64url(bytes);
  }

  protected async computeCodeChallenge(verifier: string): Promise<string> {
    const encoder = new TextEncoder();
    const data = encoder.encode(verifier);
    const hash = await crypto.subtle.digest('SHA-256', data);
    return this._base64url(new Uint8Array(hash));
  }

  private _base64url(bytes: Uint8Array): string {
    const binString = Array.from(bytes, (byte) => String.fromCodePoint(byte)).join('');
    return btoa(binString).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  // --- Shared base styles (host-level theming via CSS custom properties) ---
  protected getBaseStyles(): string {
    return `
      :host {
        display: inline-block;
        font-family: var(--qrauth-font, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif);
        --_primary:       var(--qrauth-primary, #00a76f);
        --_primary-dark:  var(--qrauth-primary-dark, #007a52);
        --_text:          var(--qrauth-text, #1a1a2e);
        --_text-muted:    var(--qrauth-text-muted, #637381);
        --_bg:            var(--qrauth-bg, #ffffff);
        --_surface:       var(--qrauth-surface, #f9fafb);
        --_border:        var(--qrauth-border, #e0e0e0);
        --_radius:        var(--qrauth-radius, 12px);
        --_shadow:        var(--qrauth-shadow, 0 24px 48px rgba(0,0,0,0.15));
        --_btn-bg:        var(--qrauth-btn-bg, #1b2a4a);
        --_btn-hover:     var(--qrauth-btn-hover, #263b66);
        --_success:       #00a76f;
        --_error:         #ff5630;
        --_warning:       #ffab00;
        --_disabled:      #919eab;
      }
      :host([theme="dark"]) {
        --_text:       var(--qrauth-text, #f0f0f0);
        --_text-muted: var(--qrauth-text-muted, #919eab);
        --_bg:         var(--qrauth-bg, #1a1a2e);
        --_surface:    var(--qrauth-surface, #242436);
        --_border:     var(--qrauth-border, rgba(255,255,255,0.12));
        --_shadow:     var(--qrauth-shadow, 0 24px 48px rgba(0,0,0,0.5));
        --_btn-bg:     var(--qrauth-btn-bg, #263b66);
        --_btn-hover:  var(--qrauth-btn-hover, #2e4578);
      }
      * { box-sizing: border-box; margin: 0; padding: 0; }
    `;
  }
}
