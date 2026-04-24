/**
 * QRAuth SDK — QR-based authentication for any website
 * https://qrauth.io
 *
 * Usage (PKCE — recommended for browser):
 *   <div id="qrauth-auth"></div>
 *   <script src="https://qrauth.io/sdk/qrauth-auth.js"></script>
 *   <script>
 *     const auth = new QRAuth({
 *       clientId: 'qrauth_app_xxx',
 *       element: '#qrauth-auth',
 *       onSuccess: (result) => console.log('Authenticated!', result),
 *       onError: (error) => console.error('Auth failed:', error),
 *     });
 *   </script>
 *
 * Legacy usage (server-side with clientSecret — still supported):
 *   const auth = new QRAuth({
 *     clientId: 'qrauth_app_xxx',
 *     clientSecret: 'qrauth_secret_xxx',  // Server-side only!
 *     ...
 *   });
 */
(function (global) {
  'use strict';

  var API_BASE = 'https://qrauth.io';

  // ---- PKCE helpers ----
  function generateCodeVerifier() {
    var array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return base64UrlEncode(array);
  }

  function computeCodeChallenge(verifier) {
    var encoder = new TextEncoder();
    var data = encoder.encode(verifier);
    return crypto.subtle.digest('SHA-256', data).then(function (hash) {
      return base64UrlEncode(new Uint8Array(hash));
    });
  }

  function base64UrlEncode(buffer) {
    var str = '';
    for (var i = 0; i < buffer.length; i++) {
      str += String.fromCharCode(buffer[i]);
    }
    return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function QRAuth(options) {
    if (!options.clientId) {
      throw new Error('QRAuth: clientId is required');
    }

    this.clientId = options.clientId;
    this.clientSecret = options.clientSecret || null; // Optional — only for server-side
    this.baseUrl = options.baseUrl !== undefined ? options.baseUrl : API_BASE;
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
    this._codeVerifier = null;

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
      '.qrauth-auth-widget { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; text-align: center; }',
      '.qrauth-auth-btn { display: inline-flex; align-items: center; gap: 10px; padding: 12px 28px; background: #1B2A4A; color: #fff; border: none; border-radius: 10px; font-size: 15px; font-weight: 600; cursor: pointer; transition: all 0.2s; }',
      '.qrauth-auth-btn:hover { background: #263B66; transform: translateY(-1px); box-shadow: 0 4px 12px rgba(27,42,74,0.3); }',
      '.qrauth-auth-btn svg { width: 22px; height: 22px; }',
      '.qrauth-auth-modal-overlay { position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.5); z-index: 99999; display: flex; align-items: center; justify-content: center; animation: qrauth-fade-in 0.2s ease; }',
      '@keyframes qrauth-fade-in { from { opacity: 0; } to { opacity: 1; } }',
      '.qrauth-auth-modal { background: #fff; border-radius: 16px; padding: 32px; max-width: 380px; width: 90%; box-shadow: 0 24px 48px rgba(0,0,0,0.15); text-align: center; animation: qrauth-slide-up 0.3s ease; }',
      '@keyframes qrauth-slide-up { from { transform: translateY(20px); opacity: 0; } to { transform: translateY(0); opacity: 1; } }',
      '.qrauth-auth-modal h3 { margin: 0 0 4px; font-size: 18px; color: #1B2A4A; }',
      '.qrauth-auth-modal p { margin: 0 0 20px; font-size: 13px; color: #637381; }',
      '.qrauth-qr-frame { display: inline-block; padding: 16px; background: #fff; border: 2px solid #e0e0e0; border-radius: 12px; margin-bottom: 16px; position: relative; }',
      '.qrauth-qr-frame img { display: block; width: 220px; height: 220px; }',
      '.qrauth-qr-badge { position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); width: 52px; height: 52px; background: #fff; border-radius: 8px; padding: 4px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }',
      '.qrauth-qr-badge svg { width: 100%; height: 100%; }',
      '.qrauth-status { font-size: 13px; color: #637381; margin-top: 12px; }',
      '.qrauth-status-scanned { color: #00A76F; font-weight: 600; }',
      '.qrauth-status-approved { color: #00A76F; font-weight: 700; font-size: 16px; }',
      '.qrauth-status-denied { color: #FF5630; font-weight: 600; }',
      '.qrauth-status-expired { color: #919eab; }',
      '.qrauth-timer { font-size: 12px; color: #919eab; margin-top: 8px; font-variant-numeric: tabular-nums; }',
      '.qrauth-close-btn { position: absolute; top: 12px; right: 12px; background: none; border: none; cursor: pointer; color: #919eab; font-size: 20px; line-height: 1; padding: 4px; }',
      '.qrauth-close-btn:hover { color: #212b36; }',
      '.qrauth-footer { margin-top: 16px; font-size: 10px; color: #c4cdd5; }',
      '.qrauth-footer a { color: #919eab; text-decoration: none; }',
      '.qrauth-success-icon { font-size: 48px; margin-bottom: 12px; }',
      '.qrauth-retry-btn { margin-top: 12px; padding: 8px 20px; background: #f5f5f5; border: 1px solid #e0e0e0; border-radius: 8px; font-size: 13px; cursor: pointer; color: #637381; }',
      '.qrauth-retry-btn:hover { background: #eeeeee; }',
    ].join('\n');
    var style = document.createElement('style');
    style.textContent = css;
    document.head.appendChild(style);
  }

  var SHIELD_SVG = '<svg viewBox="0 0 200 200" xmlns="http://www.w3.org/2000/svg">' +
    '<path d="M48 24 H152 Q166 24 166 38 V108 Q166 156 100 182 Q34 156 34 108 V38 Q34 24 48 24 Z" fill="none" stroke="#fff" stroke-width="5"/>' +
    '<g fill="#fff" opacity="0.2"><rect x="52" y="40" width="18" height="18" rx="3"/><rect x="78" y="40" width="18" height="18" rx="3"/>' +
    '<rect x="130" y="40" width="18" height="18" rx="3"/><rect x="52" y="66" width="18" height="18" rx="3"/>' +
    '<rect x="104" y="66" width="18" height="18" rx="3"/><rect x="78" y="92" width="18" height="18" rx="3"/>' +
    '<rect x="130" y="92" width="18" height="18" rx="3"/><rect x="52" y="118" width="18" height="18" rx="3"/>' +
    '<rect x="104" y="118" width="18" height="18" rx="3"/></g>' +
    '<path d="M62 104 L88 134 L144 64" fill="none" stroke="#fff" stroke-width="15" stroke-linecap="round" stroke-linejoin="round"/>' +
    '</svg>';

  // ---- Render button ----
  QRAuth.prototype.render = function () {
    injectStyles();
    var self = this;
    var container = this._container;
    if (!container) return;

    container.innerHTML = '';
    container.className = 'qrauth-auth-widget';

    var btn = document.createElement('button');
    btn.className = 'qrauth-auth-btn';
    btn.innerHTML = SHIELD_SVG + ' Sign in with QRAuth';
    btn.onclick = function () { self.start(); };
    container.appendChild(btn);
  };

  // ---- Build auth headers ----
  QRAuth.prototype._getAuthHeaders = function () {
    if (this.clientSecret) {
      // Legacy: server-side with secret
      return { 'Authorization': 'Basic ' + btoa(this.clientId + ':' + this.clientSecret) };
    }
    // PKCE: public client, clientId only
    return { 'X-Client-Id': this.clientId };
  };

  // ---- Start auth session ----
  QRAuth.prototype.start = function () {
    var self = this;
    injectStyles();

    if (this.clientSecret) {
      // Legacy flow: use Basic auth directly
      this._createSession({});
      return;
    }

    // PKCE flow: generate code_verifier + code_challenge
    this._codeVerifier = generateCodeVerifier();
    computeCodeChallenge(this._codeVerifier).then(function (challenge) {
      self._createSession({
        codeChallenge: challenge,
        codeChallengeMethod: 'S256',
      });
    }).catch(function (err) {
      self.onError(new Error('Failed to generate PKCE challenge: ' + err.message));
    });
  };

  QRAuth.prototype._createSession = function (pkceParams) {
    var self = this;
    var headers = this._getAuthHeaders();
    headers['Content-Type'] = 'application/json';

    var body = { scopes: this.scopes };
    if (pkceParams.codeChallenge) {
      body.codeChallenge = pkceParams.codeChallenge;
      body.codeChallengeMethod = pkceParams.codeChallengeMethod;
    }

    fetch(this.baseUrl + '/api/v1/auth-sessions', {
      method: 'POST',
      headers: headers,
      body: JSON.stringify(body),
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
  QRAuth.prototype._showModal = function (session) {
    var self = this;

    // Build QR image URL (using public API — no dependency needed)
    var qrImageUrl = 'https://api.qrserver.com/v1/create-qr-code/?size=440x440&data=' +
      encodeURIComponent(session.qrUrl);

    // Calculate expiry countdown
    var expiresAt = new Date(session.expiresAt).getTime();

    var overlay = document.createElement('div');
    overlay.className = 'qrauth-auth-modal-overlay';
    overlay.onclick = function (e) {
      if (e.target === overlay) self.close();
    };

    var modal = document.createElement('div');
    modal.className = 'qrauth-auth-modal';
    modal.style.position = 'relative';

    modal.innerHTML =
      '<button class="qrauth-close-btn" id="qrauth-close">&times;</button>' +
      '<h3>Sign in with QRAuth</h3>' +
      '<p>Scan this QR code with your phone camera</p>' +
      '<div class="qrauth-qr-frame">' +
        '<img src="' + qrImageUrl + '" alt="QR Code" />' +
      '</div>' +
      '<div class="qrauth-status" id="qrauth-status">Waiting for scan...</div>' +
      '<div class="qrauth-timer" id="qrauth-timer"></div>' +
      '<div class="qrauth-footer">Secured by <a href="https://qrauth.io" target="_blank"><strong>QRAuth</strong></a></div>';

    overlay.appendChild(modal);
    document.body.appendChild(overlay);
    this._overlay = overlay;

    // Close button
    modal.querySelector('#qrauth-close').onclick = function () { self.close(); };

    // Countdown timer
    this._timerInterval = setInterval(function () {
      var remaining = Math.max(0, Math.floor((expiresAt - Date.now()) / 1000));
      var mins = Math.floor(remaining / 60);
      var secs = remaining % 60;
      var el = document.getElementById('qrauth-timer');
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
  QRAuth.prototype._updateStatus = function (status, data) {
    var el = document.getElementById('qrauth-status');
    if (!el) return;

    switch (status) {
      case 'SCANNED':
      case 'scanned':
        el.className = 'qrauth-status qrauth-status-scanned';
        el.innerHTML = '&#10003; QR code scanned — waiting for approval...';
        this.onScan(data);
        break;

      case 'APPROVED':
      case 'approved':
        el.className = 'qrauth-status qrauth-status-approved';
        el.innerHTML = '&#10003; Identity verified!';
        clearInterval(this._timerInterval);
        var timer = document.getElementById('qrauth-timer');
        if (timer) timer.style.display = 'none';
        this.onSuccess(data);
        // Auto-close after 2 seconds
        var self = this;
        setTimeout(function () { self.close(); }, 2000);
        break;

      case 'DENIED':
      case 'denied':
        el.className = 'qrauth-status qrauth-status-denied';
        el.innerHTML = '&#10007; Authentication denied';
        clearInterval(this._timerInterval);
        this.onDeny(data);
        break;

      case 'EXPIRED':
      case 'expired':
        el.className = 'qrauth-status qrauth-status-expired';
        el.innerHTML = 'Session expired';
        clearInterval(this._timerInterval);
        // Add retry button
        el.innerHTML += '<br><button class="qrauth-retry-btn" id="qrauth-retry">Try Again</button>';
        var self2 = this;
        setTimeout(function () {
          var retryBtn = document.getElementById('qrauth-retry');
          if (retryBtn) retryBtn.onclick = function () { self2.close(); self2.start(); };
        }, 0);
        this.onExpire();
        break;
    }
  };

  // ---- Poll for status ----
  QRAuth.prototype._startPolling = function (sessionId) {
    this._startPollFallback(sessionId);
  };

  QRAuth.prototype._startPollFallback = function (sessionId) {
    var self = this;
    var lastStatus = 'PENDING';
    var interval = 2000;
    var maxInterval = 5000;
    var errorCount = 0;
    var maxErrors = 20;
    var headers = this._getAuthHeaders();

    function poll() {
      // Build URL with code_verifier for PKCE sessions
      var url = self.baseUrl + '/api/v1/auth-sessions/' + sessionId;
      if (self._codeVerifier) {
        url += '?code_verifier=' + encodeURIComponent(self._codeVerifier);
      }

      fetch(url, { headers: headers })
        .then(function (res) { return res.json(); })
        .then(function (data) {
          errorCount = 0;
          interval = 2000;

          if (data.status !== lastStatus) {
            lastStatus = data.status;
            self._updateStatus(data.status, data);

            if (['APPROVED', 'DENIED', 'EXPIRED'].indexOf(data.status) !== -1) {
              return;
            }
          }
          self._pollTimeout = setTimeout(poll, interval);
        })
        .catch(function () {
          errorCount++;
          if (errorCount >= maxErrors) {
            self._updateStatus('expired');
            return;
          }
          interval = Math.min(interval * 1.5, maxInterval);
          self._pollTimeout = setTimeout(poll, interval);
        });
    }

    self._pollTimeout = setTimeout(poll, interval);
  };

  // ---- Close modal ----
  QRAuth.prototype.close = function () {
    if (this._overlay) {
      this._overlay.remove();
      this._overlay = null;
    }
    if (this._pollInterval) {
      clearInterval(this._pollInterval);
      this._pollInterval = null;
    }
    if (this._pollTimeout) {
      clearTimeout(this._pollTimeout);
      this._pollTimeout = null;
    }
    if (this._timerInterval) {
      clearInterval(this._timerInterval);
      this._timerInterval = null;
    }
    if (this._sse) {
      this._sse.close();
      this._sse = null;
    }
    // Clear PKCE verifier
    this._codeVerifier = null;
  };

  // ---- Destroy ----
  QRAuth.prototype.destroy = function () {
    this.close();
    if (this._container) {
      this._container.innerHTML = '';
    }
  };

  // Export
  global.QRAuth = QRAuth;

})(typeof window !== 'undefined' ? window : this);
