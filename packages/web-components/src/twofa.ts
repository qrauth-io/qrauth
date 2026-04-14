import { QRAuthElement } from './base.js';

// Same shield SVG as login component
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

type TwoFAStatus =
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
  qrUrl: string;
  expiresAt: string;
  status: TwoFAStatus;
}

interface PollResponse {
  sessionId: string;
  status: TwoFAStatus;
  user?: Record<string, unknown>;
  signature?: string;
}

/**
 * <qrauth-2fa> — Drop-in second-factor authentication component.
 *
 * After the user completes primary login (e.g. password), render this component
 * to perform QR-based step-up verification. Always displays inline — no button/modal mode.
 *
 * Attributes:
 *   tenant         — Your QRAuth App client ID (required)
 *   theme          — "light" (default) | "dark"
 *   base-url       — API base URL (default: https://qrauth.io)
 *   session-token  — JWT from the primary authentication (required for context)
 *   scopes         — Space-separated scopes (default: "identity")
 *   auto-start     — Boolean attribute; if present, starts 2FA immediately on connect
 *
 * Events (bubbles + composed, cross shadow-DOM):
 *   qrauth:verified  — detail: { sessionId, user, signature }
 *   qrauth:denied    — fired when the user denies on their device
 *   qrauth:expired   — fired when the session times out
 *   qrauth:error     — detail: { message }
 *
 * @example
 *   <qrauth-2fa tenant="qrauth_app_xxx" session-token="eyJ..." auto-start></qrauth-2fa>
 *   <qrauth-2fa tenant="qrauth_app_xxx" scopes="identity payments"></qrauth-2fa>
 */
export class QRAuthTwoFA extends QRAuthElement {
  static override get observedAttributes(): string[] {
    return [...super.observedAttributes, 'session-token', 'scopes', 'auto-start'];
  }

  private _sessionId: string | null = null;
  private _codeVerifier: string | null = null;
  private _status: TwoFAStatus = 'idle';
  private _expiresAt: number | null = null;
  private _timerInterval: ReturnType<typeof setInterval> | null = null;
  private _pollTimeout: ReturnType<typeof setTimeout> | null = null;

  get sessionToken(): string | null { return this.getAttribute('session-token'); }
  get scopes(): string { return this.getAttribute('scopes') || 'identity'; }
  get autoStart(): boolean { return this.hasAttribute('auto-start'); }

  // ---- Lifecycle -----------------------------------------------------------

  override connectedCallback(): void {
    super.connectedCallback(); // calls render()
    if (this.autoStart) {
      this._startAuth();
    }
  }

  override disconnectedCallback(): void {
    super.disconnectedCallback();
    this._clearTimers();
  }

  // ---- Render --------------------------------------------------------------

  protected render(): void {
    this.shadow.innerHTML = `
      <style>
        ${this.getBaseStyles()}
        :host { display: block; }

        .container {
          background: var(--_bg);
          border: 1px solid var(--_border);
          border-radius: 16px;
          padding: 24px 20px 18px;
          text-align: center;
          max-width: 320px;
          margin: 0 auto;
          box-shadow: 0 2px 12px rgba(0,0,0,0.06);
        }

        /* Step indicator */
        .step-label {
          display: inline-flex;
          align-items: center;
          gap: 6px;
          font-size: 11px;
          font-weight: 600;
          letter-spacing: 0.06em;
          text-transform: uppercase;
          color: var(--_primary);
          background: rgba(0,167,111,0.08);
          border-radius: 20px;
          padding: 4px 10px;
          margin-bottom: 14px;
        }
        .step-dot {
          width: 6px;
          height: 6px;
          border-radius: 50%;
          background: var(--_primary);
          flex-shrink: 0;
        }

        /* Idle start button */
        .start-btn {
          display: inline-flex;
          align-items: center;
          gap: 10px;
          padding: 11px 22px;
          background: var(--_btn-bg);
          color: #fff;
          border: none;
          border-radius: var(--_radius);
          font-size: 14px;
          font-weight: 600;
          cursor: pointer;
          transition: background 0.2s, transform 0.15s, box-shadow 0.2s;
          font-family: inherit;
          width: 100%;
          justify-content: center;
          margin-top: 4px;
        }
        .start-btn:hover:not(:disabled) {
          background: var(--_btn-hover);
          transform: translateY(-1px);
          box-shadow: 0 4px 12px rgba(27,42,74,0.3);
        }
        .start-btn:active:not(:disabled) { transform: translateY(0); }
        .start-btn:disabled { opacity: 0.6; cursor: not-allowed; }
        .btn-icon { width: 20px; height: 20px; flex-shrink: 0; }

        ${this._sharedStyles()}
      </style>

      <div class="container" role="region" aria-label="Second-factor authentication">
        <div id="body">
          ${this._bodyForStatus('idle')}
        </div>
      </div>
    `;

    // Re-bind events after full render (attributeChangedCallback re-renders)
    this._bindBodyEvents();
  }

  // ---- Body HTML per status ------------------------------------------------

  private _bodyForStatus(status: TwoFAStatus, data?: {
    qrUrl?: string;
    timerHtml?: string;
    errorMessage?: string;
  }): string {
    const stepLabel = `
      <div class="step-label">
        <span class="step-dot"></span>
        Step 2 of 2 &mdash; Verify identity
      </div>
    `;

    switch (status) {
      case 'idle':
        return `
          ${stepLabel}
          <div class="state-header">
            <div class="brand-icon">${SHIELD_SVG}</div>
            <h3>Verify your identity</h3>
            <p class="subtitle">Scan the QR code with your phone to confirm it&apos;s you</p>
          </div>
          <button class="start-btn" id="start-btn" aria-label="Start 2FA verification">
            <span class="btn-icon">${SHIELD_SVG}</span>
            Verify your identity
          </button>
        `;

      case 'loading':
        return `
          ${stepLabel}
          <div class="state-loading">
            <div class="spinner-wrap">${SPINNER_SVG}</div>
            <p class="status-text">Generating QR code...</p>
          </div>
        `;

      case 'pending':
      case 'SCANNED': {
        const qrImageUrl = data?.qrUrl
          ? `https://api.qrserver.com/v1/create-qr-code/?size=320x320&data=${encodeURIComponent(data.qrUrl)}`
          : '';

        const isScanned = status === 'SCANNED';
        const scanClass = isScanned ? 'scanned' : '';

        return `
          ${stepLabel}
          <h3>Scan to verify</h3>
          <p class="subtitle">Use your phone camera to complete verification</p>
          <div class="qr-frame ${scanClass}">
            <img src="${qrImageUrl}" alt="QR Code for 2FA verification" width="160" height="160" loading="lazy"/>
            <div class="qr-badge">${SHIELD_SVG}</div>
            ${isScanned ? '<div class="scanned-overlay"><span class="scanned-check">' + CHECK_SVG + '</span></div>' : ''}
          </div>
          <div class="status-text ${isScanned ? 'status-scanned' : ''}">
            ${isScanned
              ? '&#10003; Scanned &mdash; waiting for approval...'
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
            <p class="subtitle">Second factor confirmed</p>
          </div>
        `;

      case 'DENIED':
        return `
          <div class="state-denied">
            <div class="error-icon">&#10007;</div>
            <h3>Verification denied</h3>
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
            <p class="subtitle">${data?.errorMessage ?? 'Failed to start verification.'}</p>
            <button class="retry-btn" id="retry-btn">Try again</button>
          </div>
        `;

      default:
        return '';
    }
  }

  // ---- Shared CSS ----------------------------------------------------------

  private _sharedStyles(): string {
    return `
      /* Typography */
      h3 {
        font-size: 16px;
        font-weight: 700;
        color: var(--_text);
        margin: 0 0 5px;
      }
      .subtitle {
        font-size: 12px;
        color: var(--_text-muted);
        margin: 0 0 16px;
        line-height: 1.5;
      }

      /* Brand icon in idle state */
      .state-header { padding: 4px 0 2px; }
      .brand-icon {
        width: 48px;
        height: 48px;
        background: var(--_btn-bg);
        border-radius: 12px;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        margin-bottom: 12px;
        padding: 8px;
      }
      .brand-icon svg { width: 32px; height: 32px; }

      /* Loading state */
      .state-loading {
        padding: 24px 0;
        display: flex;
        flex-direction: column;
        align-items: center;
        gap: 14px;
      }
      .spinner-wrap { color: var(--_primary); }
      .spinner {
        width: 36px;
        height: 36px;
        animation: spin 0.8s linear infinite;
      }
      @keyframes spin { to { transform: rotate(360deg); } }

      /* QR frame — compact 160x160 */
      .qr-frame {
        display: inline-block;
        padding: 10px;
        background: #fff;
        border: 2px solid var(--_border);
        border-radius: var(--_radius);
        margin-bottom: 12px;
        position: relative;
        transition: border-color 0.3s;
      }
      .qr-frame.scanned { border-color: var(--_success); }
      .qr-frame img { display: block; width: 160px; height: 160px; border-radius: 4px; }

      /* Smaller badge for compact QR */
      .qr-badge {
        position: absolute;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%);
        width: 40px;
        height: 40px;
        background: #1b2a4a;
        border-radius: 8px;
        padding: 5px;
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
        width: 40px;
        height: 40px;
        background: var(--_success);
        border-radius: 50%;
        display: flex;
        align-items: center;
        justify-content: center;
        color: #fff;
        opacity: 0;
        animation: pop-in 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275) 0.1s forwards;
      }
      .scanned-check svg { width: 22px; height: 22px; }
      @keyframes pop-in {
        from { transform: scale(0.5); opacity: 0; }
        to   { transform: scale(1); opacity: 1; }
      }

      /* Status text */
      .status-text {
        font-size: 12px;
        color: var(--_text-muted);
        min-height: 18px;
      }
      .status-scanned {
        color: var(--_success);
        font-weight: 600;
      }

      /* Timer */
      .timer {
        font-size: 11px;
        color: var(--_disabled);
        margin-top: 6px;
        font-variant-numeric: tabular-nums;
        min-height: 16px;
      }

      /* Success state */
      .state-approved {
        padding: 16px 0 8px;
        animation: fade-scale-in 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275);
      }
      @keyframes fade-scale-in {
        from { transform: scale(0.85); opacity: 0; }
        to   { transform: scale(1); opacity: 1; }
      }
      .success-icon {
        width: 56px;
        height: 56px;
        background: var(--_success);
        border-radius: 50%;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        color: #fff;
        margin-bottom: 14px;
      }
      .success-icon svg { width: 30px; height: 30px; }

      /* Denied / expired / error states */
      .state-denied, .state-expired, .state-error {
        padding: 16px 0 6px;
      }
      .error-icon, .expired-icon {
        font-size: 40px;
        margin-bottom: 10px;
        line-height: 1;
        display: block;
      }
      .state-denied .error-icon    { color: var(--_error); }
      .state-expired .expired-icon { color: var(--_disabled); }
      .state-error .error-icon     { color: var(--_warning); }

      /* Retry button */
      .retry-btn {
        margin-top: 12px;
        padding: 8px 20px;
        background: var(--_surface);
        border: 1px solid var(--_border);
        border-radius: 8px;
        font-size: 12px;
        font-weight: 500;
        cursor: pointer;
        color: var(--_text-muted);
        font-family: inherit;
        transition: background 0.15s, border-color 0.15s;
      }
      .retry-btn:hover { background: var(--_border); color: var(--_text); }

      /* Footer */
      .footer {
        margin-top: 14px;
        font-size: 10px;
        color: #c4cdd5;
      }
      .footer a { color: var(--_disabled); text-decoration: none; }
      .footer a:hover { text-decoration: underline; }
    `;
  }

  // ---- Event binding -------------------------------------------------------

  private _bindBodyEvents(): void {
    this.shadow.getElementById('start-btn')?.addEventListener('click', () => this._startAuth());
    this.shadow.getElementById('retry-btn')?.addEventListener('click', () => this._retry());
  }

  // ---- Auth flow -----------------------------------------------------------

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
      this._expiresAt = new Date(session.expiresAt).getTime();
      this._status = 'pending';

      this._updateBody(this._bodyForStatus('pending', { qrUrl: session.qrUrl }));
      this._bindBodyEvents();
      this._startCountdown();
      this._beginPolling(session.sessionId);

    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unexpected error';
      this._status = 'error';
      this._updateBody(this._bodyForStatus('error', { errorMessage: message }));
      this._bindBodyEvents();
      this.emit('qrauth:error', { message });
    }
  }

  private _retry(): void {
    this._clearTimers();
    this._sessionId = null;
    this._codeVerifier = null;
    this._status = 'idle';
    this._expiresAt = null;

    this._updateBody(this._bodyForStatus('idle'));
    this._bindBodyEvents();
  }

  // ---- Polling -------------------------------------------------------------

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

  // ---- Status handling -----------------------------------------------------

  private _handleStatusChange(status: TwoFAStatus, data?: PollResponse): void {
    this._status = status;

    switch (status) {
      case 'SCANNED': {
        // Preserve current QR URL from the existing img element
        const currentQrUrl = this.shadow.querySelector<HTMLImageElement>('.qr-frame img')?.src;
        const rawQrUrl = currentQrUrl
          ? decodeURIComponent(currentQrUrl.replace(/.*[?&]data=/, '').split('&')[0])
          : '';

        this._updateBody(this._bodyForStatus('SCANNED', {
          qrUrl: rawQrUrl,
          timerHtml: this._formatTimer(),
        }));
        this._bindBodyEvents();
        break;
      }

      case 'APPROVED': {
        this._clearTimers();
        this._updateBody(this._bodyForStatus('APPROVED'));
        this.emit('qrauth:verified', {
          sessionId: data?.sessionId,
          user: data?.user,
          signature: data?.signature,
        });
        break;
      }

      case 'DENIED':
        this._clearTimers();
        this._updateBody(this._bodyForStatus('DENIED'));
        this._bindBodyEvents();
        this.emit('qrauth:denied');
        break;

      case 'EXPIRED':
        this._clearTimers();
        this._status = 'EXPIRED';
        this._updateBody(this._bodyForStatus('EXPIRED'));
        this._bindBodyEvents();
        this.emit('qrauth:expired');
        break;
    }
  }

  // ---- Countdown timer -----------------------------------------------------

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

  // ---- DOM helpers ---------------------------------------------------------

  private _updateBody(html: string): void {
    const bodyEl = this.shadow.getElementById('body');
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

customElements.define('qrauth-2fa', QRAuthTwoFA);
