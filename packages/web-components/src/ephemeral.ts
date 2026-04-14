import { QRAuthElement } from './base.js';

// Same SVGs as login.ts
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

type EphemeralStatus =
  | 'idle'
  | 'loading'
  | 'active'
  | 'CLAIMED'
  | 'EXPIRED'
  | 'REVOKED'
  | 'error';

interface EphemeralSession {
  sessionId: string;
  token: string;
  claimUrl: string;
  expiresAt: string;
  scopes: string[];
  ttlSeconds: number;
  maxUses: number;
}

interface PollResponse {
  sessionId: string;
  token: string;
  status: string;
  scopes: string[];
  ttlSeconds: number;
  maxUses: number;
  useCount: number;
  metadata?: Record<string, unknown>;
}

/**
 * <qrauth-ephemeral> — Displays an ephemeral access QR code with TTL countdown
 * and claim status updates.
 *
 * Attributes:
 *   tenant         — Your QRAuth App client ID (required)
 *   theme          — "light" (default) | "dark"
 *   base-url       — API base URL (default: https://qrauth.io)
 *   scopes         — Space-separated scope strings (default: "access")
 *   ttl            — TTL string like "30m", "6h", "1d" (default: "30m")
 *   max-uses       — Maximum number of claims (default: "1")
 *   device-binding — Boolean attribute; present = device binding enabled
 *   display        — "button" | "inline" (default: "inline")
 *
 * Events (bubbles + composed, cross shadow-DOM):
 *   qrauth:claimed  — detail: { sessionId, status, scopes, metadata, useCount, maxUses }
 *   qrauth:expired  — fired when session times out
 *   qrauth:revoked  — fired when session is revoked
 *   qrauth:error    — detail: { message }
 *
 * @example
 *   <qrauth-ephemeral tenant="qrauth_app_xxx" scopes="read:menu write:order" ttl="30m">
 *   </qrauth-ephemeral>
 */
export class QRAuthEphemeral extends QRAuthElement {
  static override get observedAttributes(): string[] {
    return [...super.observedAttributes, 'scopes', 'ttl', 'max-uses', 'device-binding', 'display'];
  }

  private _sessionId: string | null = null;
  private _claimUrl: string | null = null;
  private _status: EphemeralStatus = 'idle';
  private _expiresAt: number | null = null;
  private _timerInterval: ReturnType<typeof setInterval> | null = null;
  private _pollTimeout: ReturnType<typeof setTimeout> | null = null;

  get scopes(): string { return this.getAttribute('scopes') || 'access'; }
  get ttl(): string { return this.getAttribute('ttl') || '30m'; }
  get maxUses(): number { return parseInt(this.getAttribute('max-uses') || '1', 10); }
  get deviceBinding(): boolean { return this.hasAttribute('device-binding'); }
  get display(): string { return this.getAttribute('display') || 'inline'; }

  // ---- Lifecycle -----------------------------------------------------------

  override disconnectedCallback(): void {
    super.disconnectedCallback();
    this._clearTimers();
  }

  // ---- Render --------------------------------------------------------------

  protected render(): void {
    if (this.display === 'button') {
      this._renderButton();
    } else {
      this._renderInline();
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

      <button class="btn" id="open-btn" aria-label="Get access QR code">
        <span class="btn-icon">${SHIELD_SVG}</span>
        Get Access QR
      </button>

      <div class="overlay hidden" id="overlay" role="dialog" aria-modal="true" aria-label="QRAuth ephemeral access">
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
      <button class="start-btn" id="start-btn" aria-label="Get access QR code">
        <span class="btn-icon">${SHIELD_SVG}</span>
        Get Access QR
      </button>
    `;
  }

  // ---- Shared modal HTML ---------------------------------------------------

  private _modalContent(): string {
    return `
      <button class="close-btn" id="close-btn" aria-label="Close">&times;</button>
      <div id="modal-body">
        ${this._bodyForStatus('idle')}
      </div>
    `;
  }

  private _bodyForStatus(status: EphemeralStatus, data?: {
    claimUrl?: string;
    timerHtml?: string;
    errorMessage?: string;
    useCount?: number;
    maxUses?: number;
  }): string {
    switch (status) {
      case 'idle':
        return `
          <div class="state-header">
            <div class="brand-icon">${SHIELD_SVG}</div>
            <h3>Ephemeral Access</h3>
            <p>Scan to claim temporary access</p>
          </div>
        `;

      case 'loading':
        return `
          <div class="state-loading">
            <div class="spinner-wrap">${SPINNER_SVG}</div>
            <p class="status-text">Generating access QR...</p>
          </div>
        `;

      case 'active': {
        const qrImageUrl = data?.claimUrl
          ? `https://api.qrserver.com/v1/create-qr-code/?size=440x440&data=${encodeURIComponent(data.claimUrl)}`
          : '';

        const useCount = data?.useCount ?? 0;
        const maxUses = data?.maxUses ?? 1;
        const isMultiUse = maxUses > 1;
        const useBadge = isMultiUse
          ? `<div class="use-badge">${useCount}/${maxUses} claimed</div>`
          : '';

        return `
          <h3>Scan to Access</h3>
          <p class="subtitle">Present this QR code to gain entry</p>
          <div class="qr-frame">
            <img src="${qrImageUrl}" alt="Ephemeral access QR code" width="220" height="220" loading="lazy"/>
            <div class="qr-badge">${SHIELD_SVG}</div>
          </div>
          ${useBadge}
          <div class="timer" id="timer">${data?.timerHtml ?? ''}</div>
          <div class="footer">Secured by <a href="https://qrauth.io" target="_blank" rel="noopener">QRAuth</a></div>
        `;
      }

      case 'CLAIMED':
        return `
          <div class="state-claimed">
            <div class="success-icon">${CHECK_SVG}</div>
            <h3>Access granted!</h3>
            <p class="subtitle">The QR code has been claimed successfully</p>
          </div>
        `;

      case 'EXPIRED':
        return `
          <div class="state-expired">
            <div class="expired-icon">&#8987;</div>
            <h3>Access expired</h3>
            <p class="subtitle">This QR code has timed out.</p>
            <button class="retry-btn" id="retry-btn">Generate new QR</button>
          </div>
        `;

      case 'REVOKED':
        return `
          <div class="state-revoked">
            <div class="error-icon">&#128683;</div>
            <h3>Access revoked</h3>
            <p class="subtitle">This ephemeral session has been revoked.</p>
          </div>
        `;

      case 'error':
        return `
          <div class="state-error">
            <div class="error-icon">&#9888;</div>
            <h3>Something went wrong</h3>
            <p class="subtitle">${data?.errorMessage ?? 'Failed to create ephemeral session.'}</p>
            <button class="retry-btn" id="retry-btn">Try again</button>
          </div>
        `;

      default:
        return '';
    }
  }

  // ---- Shared CSS for modal content ----------------------------------------

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

      /* Multi-use badge */
      .use-badge {
        display: inline-block;
        background: var(--_surface);
        border: 1px solid var(--_border);
        border-radius: 20px;
        padding: 4px 12px;
        font-size: 12px;
        font-weight: 600;
        color: var(--_text-muted);
        margin-bottom: 8px;
      }

      /* Status text */
      .status-text {
        font-size: 13px;
        color: var(--_text-muted);
        min-height: 20px;
      }

      /* Timer */
      .timer {
        font-size: 12px;
        color: var(--_disabled);
        margin-top: 8px;
        font-variant-numeric: tabular-nums;
        min-height: 18px;
      }

      /* Claimed / success state */
      .state-claimed {
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

      /* Expired / revoked / error states */
      .state-expired, .state-revoked, .state-error {
        padding: 20px 0 8px;
      }
      .error-icon, .expired-icon {
        font-size: 48px;
        margin-bottom: 12px;
        line-height: 1;
        display: block;
      }
      .state-revoked .error-icon { color: var(--_error); }
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

  // ---- Event binding -------------------------------------------------------

  private _bindButtonEvents(): void {
    const openBtn = this.shadow.getElementById('open-btn');
    openBtn?.addEventListener('click', () => {
      this._openModal();
      this._startSession();
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
      this._startSession();
    });
  }

  private _bindModalButtons(): void {
    this.shadow.getElementById('close-btn')?.addEventListener('click', () => this._closeModal());
    this.shadow.getElementById('retry-btn')?.addEventListener('click', () => this._retry());
  }

  // ---- Modal open / close (button display mode) ----------------------------

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
    this._claimUrl = null;
    this._status = 'idle';
    this._expiresAt = null;
  }

  // ---- Session flow --------------------------------------------------------

  private async _startSession(): Promise<void> {
    this._status = 'loading';
    this._updateBody(this._bodyForStatus('loading'));

    try {
      const res = await fetch(`${this.baseUrl}/api/v1/ephemeral`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Client-Id': this.tenant,
        },
        body: JSON.stringify({
          scopes: this.scopes.split(/\s+/).filter(Boolean),
          ttl: this.ttl,
          maxUses: this.maxUses,
          deviceBinding: this.deviceBinding,
        }),
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({ message: 'Failed to create session' }));
        throw new Error((err as { message?: string }).message ?? 'Failed to create session');
      }

      const session = await res.json() as EphemeralSession;
      this._sessionId = session.sessionId;
      this._claimUrl = session.claimUrl;
      this._expiresAt = new Date(session.expiresAt).getTime();
      this._status = 'active';

      this._updateBody(this._bodyForStatus('active', {
        claimUrl: session.claimUrl,
        timerHtml: this._formatTimer(),
        useCount: 0,
        maxUses: session.maxUses,
      }));
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
    this._claimUrl = null;
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
      this._startSession();
    }
  }

  // ---- Polling -------------------------------------------------------------

  private _beginPolling(sessionId: string): void {
    let interval = 2000;
    const maxInterval = 5000;
    let errorCount = 0;
    const maxErrors = 20;

    const poll = async () => {
      if (!this._sessionId) return; // component was reset

      try {
        const res = await fetch(`${this.baseUrl}/api/v1/ephemeral/${sessionId}`, {
          headers: { 'X-Client-Id': this.tenant },
        });
        const data = await res.json() as PollResponse;
        errorCount = 0;
        interval = 2000;

        this._handleStatusChange(data.status, data);

        if (['CLAIMED', 'EXPIRED', 'REVOKED'].includes(data.status)) {
          // For multi-use sessions that are only partially claimed, stay active
          if (data.status === 'CLAIMED' && data.useCount < data.maxUses) {
            // Partial claim — update badge and keep polling
            this._updateBody(this._bodyForStatus('active', {
              claimUrl: this._claimUrl ?? undefined,
              timerHtml: this._formatTimer(),
              useCount: data.useCount,
              maxUses: data.maxUses,
            }));
            this._bindModalButtons();
            this._pollTimeout = setTimeout(poll, interval);
            return;
          }
          return; // stop polling for terminal states
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

  private _handleStatusChange(status: string, data?: PollResponse): void {
    switch (status) {
      case 'CLAIMED': {
        // Full claim (useCount >= maxUses)
        this._clearTimers();
        this._status = 'CLAIMED';
        this._updateBody(this._bodyForStatus('CLAIMED'));
        this._bindModalButtons();
        this.emit('qrauth:claimed', {
          sessionId: data?.sessionId,
          status: data?.status,
          scopes: data?.scopes,
          metadata: data?.metadata,
          useCount: data?.useCount,
          maxUses: data?.maxUses,
        });

        if (this.display === 'button') {
          setTimeout(() => this._closeModal(), 2200);
        }
        break;
      }

      case 'EXPIRED':
        this._clearTimers();
        this._status = 'EXPIRED';
        this._updateBody(this._bodyForStatus('EXPIRED'));
        this._bindModalButtons();
        this.emit('qrauth:expired');
        break;

      case 'REVOKED':
        this._clearTimers();
        this._status = 'REVOKED';
        this._updateBody(this._bodyForStatus('REVOKED'));
        this._bindModalButtons();
        this.emit('qrauth:revoked');
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
        if (this._status === 'active') {
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

customElements.define('qrauth-ephemeral', QRAuthEphemeral);
