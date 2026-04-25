import { QRAuthElement } from './base.js';

// Same shield SVG as the browser SDK
const SHIELD_SVG = `<svg viewBox="0 0 200 200" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
  <path d="M48 24 H152 Q166 24 166 38 V108 Q166 156 100 182 Q34 156 34 108 V38 Q34 24 48 24 Z"
        fill="none" stroke="#fff" stroke-width="5"/>
  <g fill="#fff" opacity="0.2">
    <rect x="52" y="40" width="18" height="18" rx="3"/>
    <rect x="78" y="40" width="18" height="18" rx="3"/>
    <rect x="130" y="40" width="18" height="18" rx="3"/>
    <rect x="52" y="66" width="18" height="18" rx="3"/>
    <rect x="104" y="66" width="18" height="18" rx="3"/>
    <rect x="78" y="92" width="18" height="18" rx="3"/>
    <rect x="130" y="92" width="18" height="18" rx="3"/>
    <rect x="52" y="118" width="18" height="18" rx="3"/>
    <rect x="104" y="118" width="18" height="18" rx="3"/>
  </g>
  <path d="M62 104 L88 134 L144 64"
        fill="none" stroke="#fff" stroke-width="15"
        stroke-linecap="round" stroke-linejoin="round"/>
</svg>`;

// Check icon for success state
const CHECK_SVG = `<svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
  <path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41L9 16.17z" fill="currentColor"/>
</svg>`;

// Spinner SVG
const SPINNER_SVG = `<svg class="spinner" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
  <circle cx="12" cy="12" r="10" fill="none" stroke="currentColor" stroke-width="2.5"
          stroke-dasharray="31.416" stroke-dashoffset="10" stroke-linecap="round"/>
</svg>`;

type AuthStatus =
  | 'idle'
  | 'loading'
  | 'pending'
  | 'SCANNED'
  | 'APPROVED'
  | 'DENIED'
  | 'EXPIRED'
  | 'error';

interface AuthSession {
  sessionId: string;
  token: string;
  qrUrl: string;
  expiresAt: string;
  status: AuthStatus;
}

interface PollResponse {
  sessionId: string;
  status: AuthStatus;
  user?: Record<string, unknown>;
  signature?: string;
}

/**
 * <qrauth-login> — Drop-in QR authentication button / inline widget.
 *
 * Attributes:
 *   tenant                — Your QRAuth App client ID (required)
 *   theme                 — "light" (default) | "dark"
 *   base-url              — API base URL (default: https://qrauth.io)
 *   scopes                — Space-separated scopes (default: "identity")
 *   redirect-url          — Optional redirect after successful auth
 *   on-auth               — Name of a global callback function to call on success
 *   display               — "button" (default) | "inline"
 *   animated              — If present, enables subtle QR pulse animation
 *   force-mode            — "mobile" | "desktop" | "auto" (default "auto").
 *                           Overrides the automatic mobile-like detection that
 *                           swaps the QR-first body for a "Continue with
 *                           QRAuth" CTA + QR expander on phones and tablets.
 *   mobile-fallback-only  — If present, disables the mobile-aware UI entirely
 *                           and keeps the QR-first body on every device. Use
 *                           this when the surrounding page already provides an
 *                           alternative same-device login path and the
 *                           component is only there as the cross-device scan
 *                           option.
 *   redirect-uri          — Where the QRAuth hosted approval page should send
 *                           the user after they tap Approve. Required for the
 *                           mobile-CTA flow to feel complete — without it,
 *                           the new tab lands on a "you can close this page"
 *                           message and the user has to manually switch tabs.
 *                           Must match one of the app's registered
 *                           `redirectUrls` (configured in the QRAuth
 *                           dashboard) — same allowlist semantics as OAuth
 *                           2.0 redirect URIs. Comparison strips trailing
 *                           slashes and ignores query string + fragment, so
 *                           consumers can pass `?from=qrauth` etc. without
 *                           re-registering. The desktop QR flow ignores this
 *                           attribute (the user is already on the consumer
 *                           site when polling fires qrauth:authenticated).
 *
 * Events (bubbles + composed, cross shadow-DOM):
 *   qrauth:authenticated  — detail: { sessionId, user, signature }
 *   qrauth:expired        — fired when session times out
 *   qrauth:error          — detail: { message }
 *   qrauth:scanned        — fired when QR is scanned (before approval)
 *
 * @example
 *   <qrauth-login tenant="qrauth_app_xxx"></qrauth-login>
 *   <qrauth-login tenant="qrauth_app_xxx" display="inline" theme="dark"></qrauth-login>
 */
export class QRAuthLogin extends QRAuthElement {
  static override get observedAttributes(): string[] {
    return [...super.observedAttributes, 'scopes', 'redirect-url', 'on-auth', 'display', 'animated', 'redirect-uri'];
  }

  private _sessionId: string | null = null;
  private _sessionToken: string | null = null;
  private _codeVerifier: string | null = null;
  private _status: AuthStatus = 'idle';
  private _expiresAt: number | null = null;
  private _timerInterval: ReturnType<typeof setInterval> | null = null;
  private _pollTimeout: ReturnType<typeof setTimeout> | null = null;

  get scopes(): string { return this.getAttribute('scopes') || 'identity'; }
  get redirectUrl(): string | null { return this.getAttribute('redirect-url'); }
  get onAuth(): string | null { return this.getAttribute('on-auth'); }
  get display(): string { return this.getAttribute('display') || 'button'; }
  get animated(): boolean { return this.hasAttribute('animated'); }
  /**
   * Where the hosted approval page should send the user after Approve.
   * Forwarded as `redirectUrl` in the auth-session create POST body and
   * validated server-side against the app's registered redirectUrls.
   */
  get redirectUri(): string | null { return this.getAttribute('redirect-uri'); }
  get forceMode(): 'mobile' | 'desktop' | 'auto' {
    const val = this.getAttribute('force-mode');
    return val === 'mobile' || val === 'desktop' ? val : 'auto';
  }
  get mobileFallbackOnly(): boolean { return this.hasAttribute('mobile-fallback-only'); }

  // ---- Lifecycle ---------------------------------------------------------

  override disconnectedCallback(): void {
    super.disconnectedCallback();
    this._clearTimers();
  }

  // ---- Render ------------------------------------------------------------

  protected render(): void {
    if (this.display === 'inline') {
      this._renderInline();
    } else {
      this._renderButton();
    }
  }

  private _renderButton(): void {
    this.shadow.innerHTML = `
      <style>
        ${this.getBaseStyles()}
        :host { display: inline-block; }

        .btn {
          display: inline-flex;
          align-items: center;
          gap: 10px;
          padding: 12px 24px;
          background: var(--_btn-bg);
          color: #fff;
          border: none;
          border-radius: var(--_radius);
          font-size: 15px;
          font-weight: 600;
          cursor: pointer;
          transition: background 0.2s, transform 0.15s, box-shadow 0.2s;
          user-select: none;
          line-height: 1.4;
          font-family: inherit;
        }
        .btn:hover:not(:disabled) {
          background: var(--_btn-hover);
          transform: translateY(-1px);
          box-shadow: 0 4px 12px rgba(27,42,74,0.3);
        }
        .btn:active:not(:disabled) { transform: translateY(0); }
        .btn:disabled { opacity: 0.6; cursor: not-allowed; }
        .btn-icon { width: 22px; height: 22px; flex-shrink: 0; }

        /* Modal overlay */
        .overlay {
          position: fixed;
          inset: 0;
          background: rgba(0,0,0,0.55);
          z-index: 99999;
          display: flex;
          align-items: center;
          justify-content: center;
          animation: fade-in 0.2s ease;
        }
        .overlay.hidden { display: none; }

        @keyframes fade-in { from { opacity: 0; } to { opacity: 1; } }
        @keyframes slide-up {
          from { transform: translateY(24px); opacity: 0; }
          to   { transform: translateY(0); opacity: 1; }
        }

        .modal {
          background: var(--_bg);
          border-radius: 16px;
          padding: 32px 28px 24px;
          max-width: 380px;
          width: 90vw;
          box-shadow: var(--_shadow);
          text-align: center;
          animation: slide-up 0.3s ease;
          position: relative;
        }

        ${this._sharedModalStyles()}
      </style>

      <button class="btn" id="open-btn" aria-label="Sign in with QRAuth">
        <span class="btn-icon">${SHIELD_SVG}</span>
        Sign in with QRAuth
      </button>

      <div class="overlay hidden" id="overlay" role="dialog" aria-modal="true" aria-label="QRAuth sign-in">
        <div class="modal">
          ${this._modalContent()}
        </div>
      </div>
    `;

    this._bindButtonEvents();
  }

  private _renderInline(): void {
    this.shadow.innerHTML = `
      <style>
        ${this.getBaseStyles()}
        :host { display: block; }

        .inline-container {
          background: var(--_bg);
          border: 1px solid var(--_border);
          border-radius: 16px;
          padding: 28px 24px 20px;
          text-align: center;
          max-width: 360px;
          margin: 0 auto;
        }

        /* Idle state: show start button */
        .start-btn {
          display: inline-flex;
          align-items: center;
          gap: 10px;
          padding: 12px 24px;
          background: var(--_btn-bg);
          color: #fff;
          border: none;
          border-radius: var(--_radius);
          font-size: 15px;
          font-weight: 600;
          cursor: pointer;
          transition: background 0.2s, transform 0.15s, box-shadow 0.2s;
          font-family: inherit;
          width: 100%;
          justify-content: center;
        }
        .start-btn:hover:not(:disabled) {
          background: var(--_btn-hover);
          transform: translateY(-1px);
        }
        .start-btn:disabled { opacity: 0.6; cursor: not-allowed; }
        .btn-icon { width: 22px; height: 22px; flex-shrink: 0; }

        ${this._sharedModalStyles()}
      </style>

      <div class="inline-container">
        <div id="inline-body">
          ${this._inlineIdleContent()}
        </div>
      </div>
    `;

    this._bindInlineEvents();
  }

  private _inlineIdleContent(): string {
    return `
      <button class="start-btn" id="start-btn" aria-label="Sign in with QRAuth">
        <span class="btn-icon">${SHIELD_SVG}</span>
        Sign in with QRAuth
      </button>
    `;
  }

  // ---- Shared modal HTML -------------------------------------------------

  private _modalContent(): string {
    return `
      <button class="close-btn" id="close-btn" aria-label="Close">&times;</button>
      <div id="modal-body">
        ${this._bodyForStatus('idle')}
      </div>
    `;
  }

  private _bodyForStatus(status: AuthStatus, data?: {
    qrUrl?: string;
    sessionId?: string;
    timerHtml?: string;
    errorMessage?: string;
  }): string {
    switch (status) {
      case 'idle':
        return `
          <div class="state-header">
            <div class="brand-icon">${SHIELD_SVG}</div>
            <h3>Sign in with QRAuth</h3>
            <p>Secure, passwordless authentication</p>
          </div>
        `;

      case 'loading':
        return `
          <div class="state-loading">
            <div class="spinner-wrap">${SPINNER_SVG}</div>
            <p class="status-text">Generating QR code...</p>
          </div>
        `;

      case 'pending':
      case 'SCANNED': {
        if (this.isMobileLike()) {
          return this._mobilePendingBody(status, data);
        }

        const isScanned = status === 'SCANNED';

        return `
          <h3>Sign in with QRAuth</h3>
          <p class="subtitle">Scan this QR code with your phone camera</p>
          ${this._qrFrameHtml(data?.qrUrl ?? '', isScanned)}
          <div class="status-text ${isScanned ? 'status-scanned' : ''}">
            ${isScanned
              ? '&#10003; QR code scanned &mdash; waiting for approval...'
              : 'Waiting for scan...'}
          </div>
          <div class="timer" id="timer">${data?.timerHtml ?? ''}</div>
          <div class="footer">Secured by <a href="https://qrauth.io" target="_blank" rel="noopener">QRAuth</a></div>
        `;
      }

      case 'APPROVED':
        return `
          <div class="state-approved">
            <div class="success-icon">${CHECK_SVG}</div>
            <h3>Identity verified!</h3>
            <p class="subtitle">You are now signed in</p>
          </div>
        `;

      case 'DENIED':
        return `
          <div class="state-denied">
            <div class="error-icon">&#10007;</div>
            <h3>Authentication denied</h3>
            <p class="subtitle">The request was declined on your device.</p>
            <button class="retry-btn" id="retry-btn">Try again</button>
          </div>
        `;

      case 'EXPIRED':
        return `
          <div class="state-expired">
            <div class="expired-icon">&#8987;</div>
            <h3>Session expired</h3>
            <p class="subtitle">The QR code has timed out.</p>
            <button class="retry-btn" id="retry-btn">Try again</button>
          </div>
        `;

      case 'error':
        return `
          <div class="state-error">
            <div class="error-icon">&#9888;</div>
            <h3>Something went wrong</h3>
            <p class="subtitle">${data?.errorMessage ?? 'Failed to start authentication.'}</p>
            <button class="retry-btn" id="retry-btn">Try again</button>
          </div>
        `;

      default:
        return '';
    }
  }

  /**
   * Shared QR frame markup used by both the desktop pending body and the
   * mobile "Use another device" expander. Centralised so the two paths can't
   * drift.
   */
  private _qrFrameHtml(qrUrl: string, isScanned: boolean): string {
    const qrImageUrl = qrUrl
      ? `https://api.qrserver.com/v1/create-qr-code/?size=440x440&data=${encodeURIComponent(qrUrl)}`
      : '';
    const scanClass = isScanned ? 'scanned' : '';
    return `
      <div class="qr-frame ${scanClass}${this.animated ? ' animated' : ''}">
        <img src="${qrImageUrl}" alt="QR Code for authentication" width="220" height="220" loading="lazy"/>
        <div class="qr-badge">${SHIELD_SVG}</div>
        ${isScanned ? '<div class="scanned-overlay"><span class="scanned-check">' + CHECK_SVG + '</span></div>' : ''}
      </div>
    `;
  }

  /**
   * Mobile-aware pending body. Primary CTA opens the hosted approval page
   * (/a/:token) in a new tab — this same-device path short-circuits the
   * cross-device QR scan that is a dead end on phones. The QR itself is
   * demoted to a collapsed expander for the "I have a second device" case.
   */
  private _mobilePendingBody(status: AuthStatus, data?: { qrUrl?: string; timerHtml?: string }): string {
    const isScanned = status === 'SCANNED';
    return `
      <h3>Sign in with QRAuth</h3>
      <p class="subtitle">Tap continue to verify on this device.</p>
      <button class="mobile-cta" id="mobile-cta" type="button">
        <span class="btn-icon">${SHIELD_SVG}</span>
        Continue with QRAuth
      </button>
      <div class="status-text ${isScanned ? 'status-scanned' : ''}">
        ${isScanned
          ? '&#10003; Scanned &mdash; waiting for approval...'
          : 'Waiting for approval...'}
      </div>
      <div class="timer" id="timer">${data?.timerHtml ?? ''}</div>
      <details class="alt-device">
        <summary>Use another device</summary>
        ${this._qrFrameHtml(data?.qrUrl ?? '', isScanned)}
      </details>
      <div class="footer">Secured by <a href="https://qrauth.io" target="_blank" rel="noopener">QRAuth</a></div>
    `;
  }

  // ---- Shared CSS for modal content --------------------------------------

  private _sharedModalStyles(): string {
    return `
      /* Typography */
      h3 {
        font-size: 18px;
        font-weight: 700;
        color: var(--_text);
        margin: 0 0 6px;
      }
      .subtitle {
        font-size: 13px;
        color: var(--_text-muted);
        margin: 0 0 20px;
        line-height: 1.5;
      }

      /* Close button */
      .close-btn {
        position: absolute;
        top: 12px;
        right: 14px;
        background: none;
        border: none;
        cursor: pointer;
        color: var(--_text-muted);
        font-size: 22px;
        line-height: 1;
        padding: 4px 6px;
        border-radius: 6px;
        transition: color 0.15s, background 0.15s;
        font-family: inherit;
      }
      .close-btn:hover { color: var(--_text); background: var(--_surface); }

      /* Brand icon in idle state */
      .state-header { padding: 8px 0 4px; }
      .brand-icon {
        width: 56px;
        height: 56px;
        background: var(--_btn-bg);
        border-radius: 14px;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        margin-bottom: 14px;
        padding: 10px;
      }
      .brand-icon svg { width: 36px; height: 36px; }

      /* Loading state */
      .state-loading {
        padding: 32px 0;
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 16px;
      }
      .spinner-wrap { color: var(--_primary); }
      .spinner {
        width: 40px;
        height: 40px;
        animation: spin 0.8s linear infinite;
      }
      @keyframes spin { to { transform: rotate(360deg); } }

      /* QR frame */
      .qr-frame {
        display: inline-block;
        padding: 14px;
        background: #fff;
        border: 2px solid var(--_border);
        border-radius: var(--_radius);
        margin-bottom: 14px;
        position: relative;
        transition: border-color 0.3s;
      }
      .qr-frame.scanned { border-color: var(--_success); }
      .qr-frame.animated { animation: qr-pulse 2s ease-in-out infinite; }
      @keyframes qr-pulse {
        0%, 100% { box-shadow: 0 0 0 0 rgba(0,167,111,0); }
        50% { box-shadow: 0 0 0 8px rgba(0,167,111,0.15); }
      }
      .qr-frame img { display: block; width: 220px; height: 220px; border-radius: 4px; }
      .qr-badge {
        position: absolute;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%);
        width: 52px;
        height: 52px;
        background: #1b2a4a;
        border-radius: 10px;
        padding: 6px;
        box-shadow: 0 2px 8px rgba(0,0,0,0.15);
        display: flex;
        align-items: center;
        justify-content: center;
      }
      .qr-badge svg { width: 100%; height: 100%; }

      /* Scanned overlay on QR */
      .scanned-overlay {
        position: absolute;
        inset: 0;
        background: rgba(0,167,111,0.08);
        border-radius: calc(var(--_radius) - 2px);
        display: flex;
        align-items: center;
        justify-content: center;
      }
      .scanned-check {
        width: 48px;
        height: 48px;
        background: var(--_success);
        border-radius: 50%;
        display: flex;
        align-items: center;
        justify-content: center;
        color: #fff;
        opacity: 0;
        animation: pop-in 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275) 0.1s forwards;
      }
      .scanned-check svg { width: 28px; height: 28px; }
      @keyframes pop-in {
        from { transform: scale(0.5); opacity: 0; }
        to   { transform: scale(1); opacity: 1; }
      }

      /* Status text */
      .status-text {
        font-size: 13px;
        color: var(--_text-muted);
        min-height: 20px;
      }
      .status-scanned {
        color: var(--_success);
        font-weight: 600;
      }

      /* Timer */
      .timer {
        font-size: 12px;
        color: var(--_disabled);
        margin-top: 8px;
        font-variant-numeric: tabular-nums;
        min-height: 18px;
      }

      /* Success state */
      .state-approved {
        padding: 24px 0 12px;
        animation: fade-scale-in 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275);
      }
      @keyframes fade-scale-in {
        from { transform: scale(0.85); opacity: 0; }
        to   { transform: scale(1); opacity: 1; }
      }
      .success-icon {
        width: 64px;
        height: 64px;
        background: var(--_success);
        border-radius: 50%;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        color: #fff;
        margin-bottom: 16px;
      }
      .success-icon svg { width: 36px; height: 36px; }

      /* Denied / expired / error states */
      .state-denied, .state-expired, .state-error {
        padding: 20px 0 8px;
      }
      .error-icon, .expired-icon {
        font-size: 48px;
        margin-bottom: 12px;
        line-height: 1;
        display: block;
      }
      .state-denied .error-icon   { color: var(--_error); }
      .state-expired .expired-icon { color: var(--_disabled); }
      .state-error .error-icon    { color: var(--_warning); }

      /* Retry button */
      .retry-btn {
        margin-top: 14px;
        padding: 9px 22px;
        background: var(--_surface);
        border: 1px solid var(--_border);
        border-radius: 8px;
        font-size: 13px;
        font-weight: 500;
        cursor: pointer;
        color: var(--_text-muted);
        font-family: inherit;
        transition: background 0.15s, border-color 0.15s;
      }
      .retry-btn:hover { background: var(--_border); color: var(--_text); }

      /* Mobile-aware pending state: primary CTA + QR expander */
      .mobile-cta {
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 10px;
        width: 100%;
        padding: 14px 20px;
        background: var(--_btn-bg);
        color: #fff;
        border: none;
        border-radius: var(--_radius);
        font-size: 15px;
        font-weight: 600;
        cursor: pointer;
        font-family: inherit;
        margin-bottom: 16px;
      }
      .mobile-cta:hover { background: var(--_btn-hover); }
      .mobile-cta .btn-icon { width: 20px; height: 20px; }

      details.alt-device {
        margin-top: 14px;
        text-align: left;
        border-top: 1px solid var(--_border);
        padding-top: 12px;
      }
      details.alt-device summary {
        cursor: pointer;
        font-size: 13px;
        color: var(--_text-muted);
        user-select: none;
        padding: 6px 0;
        text-align: center;
        list-style: none;
      }
      details.alt-device summary::-webkit-details-marker { display: none; }
      details.alt-device summary::before {
        content: '▸ ';
        display: inline-block;
        transition: transform 0.2s;
      }
      details.alt-device[open] summary::before { transform: rotate(90deg); }
      details.alt-device > .qr-frame { margin-top: 10px; }

      /* Footer */
      .footer {
        margin-top: 18px;
        font-size: 10px;
        color: #c4cdd5;
      }
      .footer a { color: var(--_disabled); text-decoration: none; }
      .footer a:hover { text-decoration: underline; }
    `;
  }

  // ---- Event binding -----------------------------------------------------

  private _bindButtonEvents(): void {
    const openBtn = this.shadow.getElementById('open-btn');
    openBtn?.addEventListener('click', () => {
      this._openModal();
      this._startAuth();
    });

    // Close on overlay click
    const overlay = this.shadow.getElementById('overlay');
    overlay?.addEventListener('click', (e) => {
      if (e.target === overlay) this._closeModal();
    });

    this._bindModalButtons();
  }

  private _bindInlineEvents(): void {
    const startBtn = this.shadow.getElementById('start-btn');
    startBtn?.addEventListener('click', () => {
      this._startAuth();
    });
  }

  private _bindModalButtons(): void {
    this.shadow.getElementById('close-btn')?.addEventListener('click', () => this._closeModal());
    this.shadow.getElementById('retry-btn')?.addEventListener('click', () => this._retry());
    this.shadow.getElementById('mobile-cta')?.addEventListener('click', () => this._openApprovalPage());
  }

  /**
   * Mobile same-device path: open the hosted approval page in a new tab.
   * The existing polling loop in _beginPolling picks up SCANNED / APPROVED
   * transitions from the server once the user completes the flow there,
   * so qrauth:scanned and qrauth:authenticated fire unchanged.
   */
  private _openApprovalPage(): void {
    if (!this._sessionToken) return;
    const url = `${this.baseUrl}/a/${this._sessionToken}`;
    const opened = window.open(url, '_blank', 'noopener');
    if (!opened) {
      // Popup blocked — fall back to same-tab navigation.
      window.location.href = url;
    }
  }

  // ---- Modal open / close (button display mode) --------------------------

  private _openModal(): void {
    const overlay = this.shadow.getElementById('overlay');
    overlay?.classList.remove('hidden');
    this._updateBody(this._bodyForStatus('idle'));
  }

  private _closeModal(): void {
    const overlay = this.shadow.getElementById('overlay');
    overlay?.classList.add('hidden');
    this._clearTimers();
    this._sessionId = null;
    this._sessionToken = null;
    this._codeVerifier = null;
    this._status = 'idle';
    this._expiresAt = null;
  }

  // ---- Auth flow ---------------------------------------------------------

  private async _startAuth(): Promise<void> {
    this._status = 'loading';
    this._updateBody(this._bodyForStatus('loading'));

    try {
      this._codeVerifier = await this.generateCodeVerifier();
      const challenge = await this.computeCodeChallenge(this._codeVerifier);

      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
        'X-Client-Id': this.tenant,
      };

      const body: Record<string, unknown> = {
        scopes: this.scopes.split(/\s+/).filter(Boolean),
        codeChallenge: challenge,
        codeChallengeMethod: 'S256',
      };

      // Forward the consumer-supplied return URL. Server validates against
      // the app's registered redirectUrls allowlist before persisting.
      if (this.redirectUri) {
        body.redirectUrl = this.redirectUri;
      }

      const res = await fetch(`${this.baseUrl}/api/v1/auth-sessions`, {
        method: 'POST',
        headers,
        body: JSON.stringify(body),
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({ message: 'Failed to create session' }));
        throw new Error((err as { message?: string }).message ?? 'Failed to create session');
      }

      const session = await res.json() as AuthSession;
      this._sessionId = session.sessionId;
      // Prefer the discrete token field when the server provides it; fall
      // back to parsing the last path segment of qrUrl for older API versions.
      this._sessionToken = session.token
        || (session.qrUrl ? session.qrUrl.split('/').pop() ?? null : null);
      this._expiresAt = new Date(session.expiresAt).getTime();
      this._status = 'pending';

      this._updateBody(this._bodyForStatus('pending', { qrUrl: session.qrUrl }));
      this._bindModalButtons();
      this._startCountdown();
      this._beginPolling(session.sessionId);

    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unexpected error';
      this._status = 'error';
      this._updateBody(this._bodyForStatus('error', { errorMessage: message }));
      this._bindModalButtons();
      this.emit('qrauth:error', { message });
    }
  }

  private _retry(): void {
    this._clearTimers();
    this._sessionId = null;
    this._sessionToken = null;
    this._codeVerifier = null;
    this._status = 'idle';
    this._expiresAt = null;

    if (this.display === 'inline') {
      // Reset inline to show the start button again
      const inlineBody = this.shadow.getElementById('inline-body');
      if (inlineBody) {
        inlineBody.innerHTML = this._inlineIdleContent();
        this._bindInlineEvents();
      }
    } else {
      this._startAuth();
    }
  }

  // ---- Polling -----------------------------------------------------------

  private _beginPolling(sessionId: string): void {
    let lastStatus: string = 'PENDING';
    let interval = 2000;
    const maxInterval = 5000;
    let errorCount = 0;
    const maxErrors = 20;

    const poll = async () => {
      if (!this._sessionId) return; // component was reset

      let url = `${this.baseUrl}/api/v1/auth-sessions/${sessionId}`;
      if (this._codeVerifier) {
        url += `?code_verifier=${encodeURIComponent(this._codeVerifier)}`;
      }

      try {
        const res = await fetch(url, {
          headers: { 'X-Client-Id': this.tenant },
        });
        const data = await res.json() as PollResponse;
        errorCount = 0;
        interval = 2000;

        if (data.status !== lastStatus) {
          lastStatus = data.status;
          this._handleStatusChange(data.status, data);

          if (['APPROVED', 'DENIED', 'EXPIRED'].includes(data.status)) {
            return; // stop polling
          }
        }

        this._pollTimeout = setTimeout(poll, interval);

      } catch {
        errorCount++;
        if (errorCount >= maxErrors) {
          this._handleStatusChange('EXPIRED', undefined);
          return;
        }
        interval = Math.min(interval * 1.5, maxInterval);
        this._pollTimeout = setTimeout(poll, interval);
      }
    };

    this._pollTimeout = setTimeout(poll, interval);
  }

  // ---- Status handling ---------------------------------------------------

  private _handleStatusChange(status: AuthStatus, data?: PollResponse): void {
    this._status = status;

    switch (status) {
      case 'SCANNED': {
        // Keep QR visible but show scanned overlay
        const currentQrUrl = this.shadow.querySelector<HTMLImageElement>('.qr-frame img')?.src;
        // Extract the data param from the QR image URL
        const rawQrUrl = currentQrUrl
          ? decodeURIComponent(currentQrUrl.replace(/.*[?&]data=/, '').split('&')[0])
          : '';

        this._updateBody(this._bodyForStatus('SCANNED', {
          qrUrl: rawQrUrl,
          timerHtml: this._formatTimer(),
        }));
        this._bindModalButtons();
        this.emit('qrauth:scanned', data);
        break;
      }

      case 'APPROVED': {
        this._clearTimers();
        this._updateBody(this._bodyForStatus('APPROVED'));
        this._bindModalButtons();
        this.emit('qrauth:authenticated', {
          sessionId: data?.sessionId,
          user: data?.user,
          signature: data?.signature,
        });

        // Call the on-auth global callback if set
        const callbackName = this.onAuth;
        if (callbackName) {
          const globalCallback = (window as unknown as Record<string, unknown>)[callbackName];
          if (typeof globalCallback === 'function') {
            (globalCallback as (d: unknown) => void)(data);
          }
        }

        // Redirect if configured
        if (this.redirectUrl) {
          setTimeout(() => { window.location.href = this.redirectUrl!; }, 1500);
        } else if (this.display === 'button') {
          // Auto-close modal after success animation
          setTimeout(() => this._closeModal(), 2200);
        }
        break;
      }

      case 'DENIED':
        this._clearTimers();
        this._updateBody(this._bodyForStatus('DENIED'));
        this._bindModalButtons();
        this.emit('qrauth:denied');
        break;

      case 'EXPIRED':
        this._clearTimers();
        this._status = 'EXPIRED';
        this._updateBody(this._bodyForStatus('EXPIRED'));
        this._bindModalButtons();
        this.emit('qrauth:expired');
        break;
    }
  }

  // ---- Countdown timer ---------------------------------------------------

  private _startCountdown(): void {
    this._timerInterval = setInterval(() => {
      const timerEl = this.shadow.getElementById('timer');
      if (!timerEl || !this._expiresAt) return;

      const remaining = Math.max(0, Math.floor((this._expiresAt - Date.now()) / 1000));
      timerEl.textContent = remaining > 0 ? this._formatTimer(remaining) : '';

      if (remaining <= 0) {
        clearInterval(this._timerInterval!);
        this._timerInterval = null;
        if (this._status === 'pending' || this._status === 'SCANNED') {
          this._handleStatusChange('EXPIRED', undefined);
        }
      }
    }, 1000);
  }

  private _formatTimer(seconds?: number): string {
    const s = seconds ?? (this._expiresAt
      ? Math.max(0, Math.floor((this._expiresAt - Date.now()) / 1000))
      : 0);
    const mins = Math.floor(s / 60);
    const secs = s % 60;
    return `Expires in ${mins}:${secs < 10 ? '0' : ''}${secs}`;
  }

  // ---- DOM helpers -------------------------------------------------------

  /** Update just the inner body content without re-rendering the whole component */
  private _updateBody(html: string): void {
    const bodyEl = this.display === 'inline'
      ? this.shadow.getElementById('inline-body')
      : this.shadow.getElementById('modal-body');

    if (bodyEl) bodyEl.innerHTML = html;
  }

  private _clearTimers(): void {
    if (this._timerInterval) {
      clearInterval(this._timerInterval);
      this._timerInterval = null;
    }
    if (this._pollTimeout) {
      clearTimeout(this._pollTimeout);
      this._pollTimeout = null;
    }
  }
}

customElements.define('qrauth-login', QRAuthLogin);
