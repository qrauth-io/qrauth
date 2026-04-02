/**
 * vQR Auth SDK — QR-based authentication for any website
 * https://vqr.io
 *
 * Usage:
 *   <div id="vqr-auth"></div>
 *   <script src="https://qrauth.io/sdk/vqr-auth.js"></script>
 *   <script>
 *     const auth = new VQRAuth({
 *       clientId: 'vqr_app_xxx',
 *       clientSecret: 'vqr_secret_xxx',
 *       element: '#vqr-auth',
 *       onSuccess: (result) => console.log('Authenticated!', result),
 *       onError: (error) => console.error('Auth failed:', error),
 *     });
 *   </script>
 */
(function (global) {
  'use strict';

  var API_BASE = 'https://qrauth.io';

  // ---- QR Code Generator (minimal QR encoder, sufficient for URLs) ----
  // We use a <img> tag pointing to a QR API to avoid bundling a full QR lib
  // But we also generate a nice styled container

  function VQRAuth(options) {
    if (!options.clientId || !options.clientSecret) {
      throw new Error('VQRAuth: clientId and clientSecret are required');
    }

    this.clientId = options.clientId;
    this.clientSecret = options.clientSecret;
    this.baseUrl = options.baseUrl || API_BASE;
    this.scopes = options.scopes || ['identity', 'email'];
    this.onSuccess = options.onSuccess || function () {};
    this.onError = options.onError || function () {};
    this.onScan = options.onScan || function () {};
    this.onExpire = options.onExpire || function () {};
    this.onDeny = options.onDeny || function () {};

    this._session = null;
    this._sse = null;
    this._pollInterval = null;
    this._container = null;

    // Auto-render if element is provided
    if (options.element) {
      var el = typeof options.element === 'string'
        ? document.querySelector(options.element)
        : options.element;
      if (el) {
        this._container = el;
        this.render();
      }
    }
  }

  // ---- Styles (injected once) ----
  var stylesInjected = false;
  function injectStyles() {
    if (stylesInjected) return;
    stylesInjected = true;
    var css = [
      '.vqr-auth-widget { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; text-align: center; }',
      '.vqr-auth-btn { display: inline-flex; align-items: center; gap: 10px; padding: 12px 28px; background: #1B2A4A; color: #fff; border: none; border-radius: 10px; font-size: 15px; font-weight: 600; cursor: pointer; transition: all 0.2s; }',
      '.vqr-auth-btn:hover { background: #263B66; transform: translateY(-1px); box-shadow: 0 4px 12px rgba(27,42,74,0.3); }',
      '.vqr-auth-btn svg { width: 22px; height: 22px; }',
      '.vqr-auth-modal-overlay { position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.5); z-index: 99999; display: flex; align-items: center; justify-content: center; animation: vqr-fade-in 0.2s ease; }',
      '@keyframes vqr-fade-in { from { opacity: 0; } to { opacity: 1; } }',
      '.vqr-auth-modal { background: #fff; border-radius: 16px; padding: 32px; max-width: 380px; width: 90%; box-shadow: 0 24px 48px rgba(0,0,0,0.15); text-align: center; animation: vqr-slide-up 0.3s ease; }',
      '@keyframes vqr-slide-up { from { transform: translateY(20px); opacity: 0; } to { transform: translateY(0); opacity: 1; } }',
      '.vqr-auth-modal h3 { margin: 0 0 4px; font-size: 18px; color: #1B2A4A; }',
      '.vqr-auth-modal p { margin: 0 0 20px; font-size: 13px; color: #637381; }',
      '.vqr-qr-frame { display: inline-block; padding: 16px; background: #fff; border: 2px solid #e0e0e0; border-radius: 12px; margin-bottom: 16px; position: relative; }',
      '.vqr-qr-frame img { display: block; width: 220px; height: 220px; }',
      '.vqr-qr-badge { position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); width: 52px; height: 52px; background: #fff; border-radius: 8px; padding: 4px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }',
      '.vqr-qr-badge svg { width: 100%; height: 100%; }',
      '.vqr-status { font-size: 13px; color: #637381; margin-top: 12px; }',
      '.vqr-status-scanned { color: #00A76F; font-weight: 600; }',
      '.vqr-status-approved { color: #00A76F; font-weight: 700; font-size: 16px; }',
      '.vqr-status-denied { color: #FF5630; font-weight: 600; }',
      '.vqr-status-expired { color: #919eab; }',
      '.vqr-timer { font-size: 12px; color: #919eab; margin-top: 8px; font-variant-numeric: tabular-nums; }',
      '.vqr-close-btn { position: absolute; top: 12px; right: 12px; background: none; border: none; cursor: pointer; color: #919eab; font-size: 20px; line-height: 1; padding: 4px; }',
      '.vqr-close-btn:hover { color: #212b36; }',
      '.vqr-footer { margin-top: 16px; font-size: 10px; color: #c4cdd5; }',
      '.vqr-footer a { color: #919eab; text-decoration: none; }',
      '.vqr-success-icon { font-size: 48px; margin-bottom: 12px; }',
      '.vqr-retry-btn { margin-top: 12px; padding: 8px 20px; background: #f5f5f5; border: 1px solid #e0e0e0; border-radius: 8px; font-size: 13px; cursor: pointer; color: #637381; }',
      '.vqr-retry-btn:hover { background: #eeeeee; }',
    ].join('\n');
    var style = document.createElement('style');
    style.textContent = css;
    document.head.appendChild(style);
  }

  var SHIELD_SVG = '<svg viewBox="0 0 120 120" fill="none" xmlns="http://www.w3.org/2000/svg">' +
    '<path d="M60 8L16 28v32c0 28 18.7 54.2 44 60 25.3-5.8 44-32 44-60V28L60 8z" fill="#1B2A4A"/>' +
    '<path d="M60 16L24 33v25c0 23.5 15.3 45.5 36 50.4 20.7-4.9 36-26.9 36-50.4V33L60 16z" fill="#263B66"/>' +
    '<circle cx="60" cy="56" r="24" fill="#00A76F"/>' +
    '<path d="M50 56l7 7 13-14" stroke="#fff" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/>' +
    '<text x="60" y="100" text-anchor="middle" font-family="Arial,sans-serif" font-weight="800" font-size="16" fill="#fff" letter-spacing="1">vQR</text>' +
    '</svg>';

  // ---- Render button ----
  VQRAuth.prototype.render = function () {
    injectStyles();
    var self = this;
    var container = this._container;
    if (!container) return;

    container.innerHTML = '';
    container.className = 'vqr-auth-widget';

    var btn = document.createElement('button');
    btn.className = 'vqr-auth-btn';
    btn.innerHTML = SHIELD_SVG + ' Sign in with vQR';
    btn.onclick = function () { self.start(); };
    container.appendChild(btn);
  };

  // ---- Start auth session ----
  VQRAuth.prototype.start = function () {
    var self = this;
    injectStyles();

    // Create session via API
    var credentials = btoa(this.clientId + ':' + this.clientSecret);

    fetch(this.baseUrl + '/api/v1/auth-sessions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Basic ' + credentials,
      },
      body: JSON.stringify({ scopes: this.scopes }),
    })
      .then(function (res) {
        if (!res.ok) return res.json().then(function (e) { throw new Error(e.message || 'Failed to create session'); });
        return res.json();
      })
      .then(function (data) {
        self._session = data;
        self._showModal(data);
        self._startPolling(data.sessionId);
      })
      .catch(function (err) {
        self.onError(err);
      });
  };

  // ---- Show QR modal ----
  VQRAuth.prototype._showModal = function (session) {
    var self = this;

    // Build QR image URL (using public API — no dependency needed)
    var qrImageUrl = 'https://api.qrserver.com/v1/create-qr-code/?size=440x440&data=' +
      encodeURIComponent(session.qrUrl);

    // Calculate expiry countdown
    var expiresAt = new Date(session.expiresAt).getTime();

    var overlay = document.createElement('div');
    overlay.className = 'vqr-auth-modal-overlay';
    overlay.onclick = function (e) {
      if (e.target === overlay) self.close();
    };

    var modal = document.createElement('div');
    modal.className = 'vqr-auth-modal';
    modal.style.position = 'relative';

    modal.innerHTML =
      '<button class="vqr-close-btn" id="vqr-close">&times;</button>' +
      '<h3>Sign in with vQR</h3>' +
      '<p>Scan this QR code with your phone camera</p>' +
      '<div class="vqr-qr-frame">' +
        '<img src="' + qrImageUrl + '" alt="QR Code" />' +
        '<div class="vqr-qr-badge">' + SHIELD_SVG + '</div>' +
      '</div>' +
      '<div class="vqr-status" id="vqr-status">Waiting for scan...</div>' +
      '<div class="vqr-timer" id="vqr-timer"></div>' +
      '<div class="vqr-footer">Secured by <a href="https://qrauth.io" target="_blank"><strong>vQR</strong></a></div>';

    overlay.appendChild(modal);
    document.body.appendChild(overlay);
    this._overlay = overlay;

    // Close button
    modal.querySelector('#vqr-close').onclick = function () { self.close(); };

    // Countdown timer
    this._timerInterval = setInterval(function () {
      var remaining = Math.max(0, Math.floor((expiresAt - Date.now()) / 1000));
      var mins = Math.floor(remaining / 60);
      var secs = remaining % 60;
      var el = document.getElementById('vqr-timer');
      if (el) {
        el.textContent = 'Expires in ' + mins + ':' + (secs < 10 ? '0' : '') + secs;
      }
      if (remaining <= 0) {
        clearInterval(self._timerInterval);
        self._updateStatus('expired');
      }
    }, 1000);
  };

  // ---- Update modal status ----
  VQRAuth.prototype._updateStatus = function (status, data) {
    var el = document.getElementById('vqr-status');
    if (!el) return;

    switch (status) {
      case 'SCANNED':
      case 'scanned':
        el.className = 'vqr-status vqr-status-scanned';
        el.innerHTML = '&#10003; QR code scanned — waiting for approval...';
        this.onScan(data);
        break;

      case 'APPROVED':
      case 'approved':
        el.className = 'vqr-status vqr-status-approved';
        el.innerHTML = '&#10003; Identity verified!';
        clearInterval(this._timerInterval);
        var timer = document.getElementById('vqr-timer');
        if (timer) timer.style.display = 'none';
        this.onSuccess(data);
        // Auto-close after 2 seconds
        var self = this;
        setTimeout(function () { self.close(); }, 2000);
        break;

      case 'DENIED':
      case 'denied':
        el.className = 'vqr-status vqr-status-denied';
        el.innerHTML = '&#10007; Authentication denied';
        clearInterval(this._timerInterval);
        this.onDeny(data);
        break;

      case 'EXPIRED':
      case 'expired':
        el.className = 'vqr-status vqr-status-expired';
        el.innerHTML = 'Session expired';
        clearInterval(this._timerInterval);
        // Add retry button
        el.innerHTML += '<br><button class="vqr-retry-btn" id="vqr-retry">Try Again</button>';
        var self2 = this;
        setTimeout(function () {
          var retryBtn = document.getElementById('vqr-retry');
          if (retryBtn) retryBtn.onclick = function () { self2.close(); self2.start(); };
        }, 0);
        this.onExpire();
        break;
    }
  };

  // ---- Poll for status (fallback if SSE fails) ----
  VQRAuth.prototype._startPolling = function (sessionId) {
    var self = this;
    var credentials = btoa(this.clientId + ':' + this.clientSecret);

    // Try SSE first
    try {
      var sseUrl = this.baseUrl + '/api/v1/auth-sessions/' + sessionId + '/sse';
      // SSE doesn't support custom headers, so we fall back to polling
      // (Basic auth in SSE URL is not standard)
      this._startPollFallback(sessionId, credentials);
    } catch (e) {
      this._startPollFallback(sessionId, credentials);
    }
  };

  VQRAuth.prototype._startPollFallback = function (sessionId, credentials) {
    var self = this;
    var lastStatus = 'PENDING';

    this._pollInterval = setInterval(function () {
      fetch(self.baseUrl + '/api/v1/auth-sessions/' + sessionId, {
        headers: { 'Authorization': 'Basic ' + credentials },
      })
        .then(function (res) { return res.json(); })
        .then(function (data) {
          if (data.status !== lastStatus) {
            lastStatus = data.status;
            self._updateStatus(data.status, data);

            // Stop polling on terminal states
            if (['APPROVED', 'DENIED', 'EXPIRED'].indexOf(data.status) !== -1) {
              clearInterval(self._pollInterval);
            }
          }
        })
        .catch(function () {
          // Silently retry on next interval
        });
    }, 1500); // Poll every 1.5 seconds
  };

  // ---- Close modal ----
  VQRAuth.prototype.close = function () {
    if (this._overlay) {
      document.body.removeChild(this._overlay);
      this._overlay = null;
    }
    if (this._pollInterval) {
      clearInterval(this._pollInterval);
      this._pollInterval = null;
    }
    if (this._timerInterval) {
      clearInterval(this._timerInterval);
      this._timerInterval = null;
    }
    if (this._sse) {
      this._sse.close();
      this._sse = null;
    }
  };

  // ---- Destroy ----
  VQRAuth.prototype.destroy = function () {
    this.close();
    if (this._container) {
      this._container.innerHTML = '';
    }
  };

  // Export
  global.VQRAuth = VQRAuth;

})(typeof window !== 'undefined' ? window : this);
