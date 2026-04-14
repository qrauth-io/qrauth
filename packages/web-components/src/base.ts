/**
 * QRAuthElement — base class for all QRAuth Web Components.
 * Provides: Shadow DOM setup, CSS custom property theming, SSE connection management,
 * lifecycle hooks, and event dispatching.
 */
export abstract class QRAuthElement extends HTMLElement {
  protected shadow: ShadowRoot;
  private _sseConnection: EventSource | null = null;
  private _pollInterval: ReturnType<typeof setInterval> | null = null;

  static get observedAttributes(): string[] {
    return ['tenant', 'theme', 'base-url'];
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
