import type { FastifyInstance } from 'fastify';
import { AuthSessionService } from '../services/auth-session.js';
import { hashString } from '../lib/crypto.js';
import { AUTH_SESSION_EXPIRY_SECONDS } from '@vqr/shared';
import { getEnabledProviderNames } from '../lib/oauth.js';

export default async function approvalRoutes(fastify: FastifyInstance): Promise<void> {
  const sessionService = new AuthSessionService(fastify.prisma);

  // GET /a/:token — Approval page (HTML)
  fastify.get('/:token', async (request, reply) => {
    const { token } = request.params as { token: string };

    const session = await sessionService.getSessionByToken(token);

    // Mark as scanned
    if (session && session.status === 'PENDING') {
      const ipHash = hashString(request.ip || 'unknown');
      await sessionService.markScanned(session.id, request.headers['user-agent'], ipHash);
    }

    const scopeLabels: Record<string, string> = {
      identity: 'Your name',
      email: 'Your email address',
      organization: 'Your organization details',
    };

    const enabledProviders = getEnabledProviderNames();

    const expired = !session || session.status === 'EXPIRED' || new Date() > session.expiresAt;
    const alreadyResolved = session && ['APPROVED', 'DENIED'].includes(session.status);

    reply.type('text/html').send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>vQR Auth — Verify Your Identity</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: #f5f5f5;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }
    .card {
      background: white;
      border-radius: 16px;
      box-shadow: 0 4px 24px rgba(0,0,0,0.08);
      padding: 40px 32px;
      max-width: 400px;
      width: 100%;
      text-align: center;
    }
    .shield {
      width: 64px;
      height: 64px;
      margin: 0 auto 20px;
    }
    .app-name {
      font-size: 20px;
      font-weight: 700;
      color: #1B2A4A;
      margin-bottom: 4px;
    }
    .subtitle {
      color: #637381;
      font-size: 14px;
      margin-bottom: 24px;
    }
    .scopes {
      background: #f8f9fa;
      border-radius: 8px;
      padding: 16px;
      margin-bottom: 24px;
      text-align: left;
    }
    .scopes-title {
      font-size: 12px;
      font-weight: 600;
      text-transform: uppercase;
      color: #919eab;
      letter-spacing: 0.5px;
      margin-bottom: 8px;
    }
    .scope-item {
      display: flex;
      align-items: center;
      gap: 8px;
      padding: 6px 0;
      font-size: 14px;
      color: #212b36;
    }
    .scope-icon { color: #00A76F; }
    .btn {
      display: block;
      width: 100%;
      padding: 14px;
      border: none;
      border-radius: 10px;
      font-size: 16px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.2s;
      margin-bottom: 10px;
    }
    .btn-approve {
      background: #00A76F;
      color: white;
    }
    .btn-approve:hover { background: #007B55; }
    .btn-approve:disabled { background: #919eab; cursor: not-allowed; }
    .btn-deny {
      background: transparent;
      color: #637381;
      border: 1px solid #dfe3e8;
    }
    .btn-deny:hover { background: #f5f5f5; }
    .footer {
      margin-top: 20px;
      font-size: 11px;
      color: #919eab;
    }
    .footer a { color: #637381; }
    .status-badge {
      display: inline-block;
      padding: 6px 16px;
      border-radius: 20px;
      font-size: 14px;
      font-weight: 600;
      margin-bottom: 16px;
    }
    .status-approved { background: #E8F5E9; color: #1B5E20; }
    .status-denied { background: #FFEBEE; color: #C62828; }
    .status-expired { background: #FFF3E0; color: #E65100; }
    .error-icon { font-size: 48px; margin-bottom: 16px; }
    #result { display: none; }
    .auth-input {
      display: block; width: 100%; padding: 10px 14px; margin-bottom: 10px;
      border: 1px solid #dfe3e8; border-radius: 8px; font-size: 14px;
      font-family: inherit; box-sizing: border-box;
    }
    .auth-input:focus { outline: none; border-color: #00A76F; }
    .tab-btn {
      flex: 1; padding: 8px; border: 1px solid #dfe3e8; background: #fff;
      border-radius: 8px; font-size: 13px; font-weight: 600; cursor: pointer;
      color: #637381; transition: all 0.2s;
    }
    .tab-btn.active { background: #1B2A4A; color: #fff; border-color: #1B2A4A; }
    .oauth-btn { transition: background 0.2s !important; }
    .oauth-btn:hover { background: #f5f5f5 !important; }
  </style>
</head>
<body>
  <div class="card">
    <svg class="shield" viewBox="0 0 120 120" fill="none" xmlns="http://www.w3.org/2000/svg">
      <path d="M60 8L16 28v32c0 28 18.7 54.2 44 60 25.3-5.8 44-32 44-60V28L60 8z" fill="#1B2A4A"/>
      <path d="M60 16L24 33v25c0 23.5 15.3 45.5 36 50.4 20.7-4.9 36-26.9 36-50.4V33L60 16z" fill="#263B66"/>
      <circle cx="60" cy="56" r="24" fill="#00A76F"/>
      <path d="M50 56l7 7 13-14" stroke="#fff" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/>
      <text x="60" y="100" text-anchor="middle" font-family="Arial,sans-serif" font-weight="800" font-size="16" fill="#fff" letter-spacing="1">vQR</text>
    </svg>

    ${expired ? `
      <div class="error-icon">&#x23F1;</div>
      <div class="app-name">Session Expired</div>
      <p class="subtitle">This authentication request has expired. Please ask the application to generate a new QR code.</p>
    ` : alreadyResolved ? `
      <div class="status-badge status-${session!.status.toLowerCase()}">${session!.status}</div>
      <div class="app-name">${session!.status === 'APPROVED' ? 'Identity Verified' : 'Request Denied'}</div>
      <p class="subtitle">This authentication request has already been ${session!.status.toLowerCase()}.</p>
    ` : `
      <div class="app-name">${escapeHtml(session!.app.name)}</div>
      <p class="subtitle">wants to verify your identity</p>

      <div class="scopes">
        <div class="scopes-title">This app will receive</div>
        ${session!.scopes.map((s: string) => `
          <div class="scope-item">
            <span class="scope-icon">&#10003;</span>
            ${escapeHtml(scopeLabels[s] || s)}
          </div>
        `).join('')}
      </div>

      <div id="auth-section"></div>
      <div id="actions" style="display:none">
        <div id="user-info" style="padding:12px 16px;background:#f8f9fa;border-radius:8px;margin-bottom:16px;font-size:13px;color:#212b36;display:none;">
          Authenticating as <strong id="user-email"></strong>
        </div>
        <button class="btn btn-approve" id="approveBtn" onclick="handleApprove()">
          Approve
        </button>
        <button class="btn btn-deny" id="denyBtn" onclick="handleDeny()">
          Deny
        </button>
      </div>

      <div id="result"></div>

      <script>
        var TOKEN = '${token}';
        var JWT_KEY = 'jwt_access_token';
        var API = '';
        var PROVIDERS = ${JSON.stringify(enabledProviders)};
        var AUTH_SESSION_TOKEN = '${token}';

        function init() {
          // Check for JWT in URL fragment (from OAuth redirect)
          var hash = window.location.hash;
          if (hash && hash.indexOf('jwt=') !== -1) {
            var jwtFromHash = hash.split('jwt=')[1];
            if (jwtFromHash) {
              sessionStorage.setItem(JWT_KEY, jwtFromHash);
              // Clean the hash from URL
              history.replaceState(null, '', window.location.pathname + window.location.search);
            }
          }
          var jwt = sessionStorage.getItem(JWT_KEY);
          if (jwt) {
            showActions(jwt);
          } else {
            showAuthForm();
          }
        }

        function showActions(jwt) {
          document.getElementById('auth-section').style.display = 'none';
          document.getElementById('actions').style.display = 'block';
          // Decode JWT to show email
          try {
            var payload = JSON.parse(atob(jwt.split('.')[1]));
            if (payload.email) {
              document.getElementById('user-email').textContent = payload.email;
              document.getElementById('user-info').style.display = 'block';
            }
          } catch(e) {}
        }

        function showAuthForm() {
          document.getElementById('actions').style.display = 'none';
          var oauthHtml = '';
          if (PROVIDERS.length > 0) {
            var icons = {
              google: '<svg viewBox="0 0 24 24" width="18" height="18"><path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92a5.06 5.06 0 01-2.2 3.32v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.1z"/><path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/><path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/><path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/></svg>',
              github: '<svg viewBox="0 0 24 24" width="18" height="18"><path fill="#333" d="M12 .3a12 12 0 00-3.8 23.38c.6.12.83-.26.83-.57v-2.2c-3.34.73-4.03-1.41-4.03-1.41-.55-1.39-1.33-1.76-1.33-1.76-1.09-.74.08-.73.08-.73 1.2.09 1.84 1.24 1.84 1.24 1.07 1.83 2.8 1.3 3.49 1 .1-.78.42-1.3.76-1.6-2.67-.31-5.47-1.34-5.47-5.93 0-1.31.47-2.38 1.24-3.22-.14-.3-.54-1.52.1-3.18 0 0 1-.32 3.3 1.23a11.5 11.5 0 016.02 0c2.28-1.55 3.29-1.23 3.29-1.23.64 1.66.24 2.88.12 3.18a4.65 4.65 0 011.23 3.22c0 4.61-2.81 5.62-5.48 5.92.42.36.81 1.1.81 2.22v3.29c0 .31.21.69.82.57A12 12 0 0012 .3z"/></svg>',
              microsoft: '<svg viewBox="0 0 24 24" width="18" height="18"><rect fill="#F25022" x="1" y="1" width="10" height="10"/><rect fill="#7FBA00" x="13" y="1" width="10" height="10"/><rect fill="#00A4EF" x="1" y="13" width="10" height="10"/><rect fill="#FFB900" x="13" y="13" width="10" height="10"/></svg>',
              apple: '<svg viewBox="0 0 24 24" width="18" height="18"><path fill="#000" d="M17.05 20.28c-.98.95-2.05.88-3.08.4-1.09-.5-2.08-.48-3.24 0-1.44.62-2.2.44-3.06-.4C2.79 15.25 3.51 7.59 9.05 7.31c1.35.07 2.29.74 3.08.8 1.18-.24 2.31-.93 3.57-.84 1.51.12 2.65.72 3.4 1.8-3.12 1.87-2.38 5.98.48 7.13-.57 1.5-1.31 2.99-2.54 4.09zM12.03 7.25c-.15-2.23 1.66-4.07 3.74-4.25.32 2.32-2.12 4.53-3.74 4.25z"/></svg>'
            };
            var labels = { google: 'Google', github: 'GitHub', microsoft: 'Microsoft', apple: 'Apple' };
            oauthHtml = '<div style="margin-bottom:16px;">';
            PROVIDERS.forEach(function(p) {
              oauthHtml += '<button class="btn oauth-btn" data-provider="' + p + '" style="background:#fff;color:#212b36;border:1px solid #dfe3e8;display:flex;align-items:center;justify-content:center;gap:8px;font-size:14px;">' + (icons[p] || '') + ' Continue with ' + (labels[p] || p) + '</button>';
            });
            oauthHtml += '<div style="display:flex;align-items:center;gap:12px;margin:16px 0;"><hr style="flex:1;border:none;border-top:1px solid #e0e0e0;"><span style="font-size:12px;color:#919eab;">or</span><hr style="flex:1;border:none;border-top:1px solid #e0e0e0;"></div>';
            oauthHtml += '</div>';
          }
          var html = '<div style="text-align:left">' +
            oauthHtml +
            '<div style="display:flex;gap:8px;margin-bottom:16px;">' +
              '<button class="tab-btn active" id="tab-signin" data-tab="signin">Sign In</button>' +
              '<button class="tab-btn" id="tab-signup" data-tab="signup">Sign Up</button>' +
            '</div>' +
            '<div id="signin-form">' +
              '<input type="email" id="si-email" placeholder="Email" class="auth-input" />' +
              '<input type="password" id="si-password" placeholder="Password" class="auth-input" />' +
              '<button class="btn btn-approve" onclick="doSignIn()" id="si-btn">Sign In</button>' +
            '</div>' +
            '<div id="signup-form" style="display:none">' +
              '<input type="text" id="su-name" placeholder="Full Name" class="auth-input" />' +
              '<input type="email" id="su-email" placeholder="Email" class="auth-input" />' +
              '<input type="password" id="su-password" placeholder="Password (min 8 chars)" class="auth-input" />' +
              '<input type="text" id="su-org" placeholder="Organization Name" class="auth-input" />' +
              '<button class="btn btn-approve" onclick="doSignUp()" id="su-btn">Create Account & Approve</button>' +
            '</div>' +
            '<div id="auth-error" style="display:none;color:#FF5630;font-size:13px;margin-top:8px;"></div>' +
          '</div>';
          document.getElementById('auth-section').innerHTML = html;
          document.getElementById('auth-section').style.display = 'block';
          document.getElementById('tab-signin').addEventListener('click', function() { switchTab('signin'); });
          document.getElementById('tab-signup').addEventListener('click', function() { switchTab('signup'); });
          document.querySelectorAll('.oauth-btn').forEach(function(btn) {
            btn.addEventListener('click', function() { doOAuth(this.getAttribute('data-provider')); });
          });
        }

        function switchTab(tab) {
          document.getElementById('signin-form').style.display = tab === 'signin' ? 'block' : 'none';
          document.getElementById('signup-form').style.display = tab === 'signup' ? 'block' : 'none';
          document.getElementById('tab-signin').className = 'tab-btn' + (tab === 'signin' ? ' active' : '');
          document.getElementById('tab-signup').className = 'tab-btn' + (tab === 'signup' ? ' active' : '');
          document.getElementById('auth-error').style.display = 'none';
        }

        function doOAuth(provider) {
          var url = API + '/api/v1/auth/oauth/' + provider + '?authSessionToken=' + AUTH_SESSION_TOKEN;
          window.location.href = url;
        }

        function showError(msg) {
          var el = document.getElementById('auth-error');
          el.textContent = msg;
          el.style.display = 'block';
        }

        async function doSignIn() {
          var email = document.getElementById('si-email').value;
          var password = document.getElementById('si-password').value;
          if (!email || !password) { showError('Email and password required'); return; }
          var btn = document.getElementById('si-btn');
          btn.disabled = true; btn.textContent = 'Signing in...';
          try {
            var res = await fetch(API + '/api/v1/auth/login', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ email: email, password: password })
            });
            if (!res.ok) { var e = await res.json(); throw new Error(e.message || 'Invalid credentials'); }
            var data = await res.json();
            sessionStorage.setItem(JWT_KEY, data.token);
            showActions(data.token);
          } catch(e) {
            showError(e.message);
            btn.disabled = false; btn.textContent = 'Sign In';
          }
        }

        async function doSignUp() {
          var name = document.getElementById('su-name').value;
          var email = document.getElementById('su-email').value;
          var password = document.getElementById('su-password').value;
          var org = document.getElementById('su-org').value;
          if (!name || !email || !password || !org) { showError('All fields required'); return; }
          if (password.length < 8) { showError('Password must be at least 8 characters'); return; }
          var btn = document.getElementById('su-btn');
          btn.disabled = true; btn.textContent = 'Creating account...';
          try {
            var res = await fetch(API + '/api/v1/auth/signup', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ name: name, email: email, password: password, organizationName: org })
            });
            if (!res.ok) { var e = await res.json(); throw new Error(e.message || 'Signup failed'); }
            var data = await res.json();
            sessionStorage.setItem(JWT_KEY, data.token);
            showActions(data.token);
          } catch(e) {
            showError(e.message);
            btn.disabled = false; btn.textContent = 'Create Account & Approve';
          }
        }

        async function handleApprove() {
          var btn = document.getElementById('approveBtn');
          btn.disabled = true; btn.textContent = 'Verifying...';
          var jwt = sessionStorage.getItem(JWT_KEY);
          if (!jwt) { showAuthForm(); return; }

          try {
            var res = await fetch(API + '/api/v1/auth-sessions/' + TOKEN + '/approve', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + jwt },
              body: JSON.stringify({ fingerprint: DEVICE_FINGERPRINT })
            });
            if (res.ok) {
              document.getElementById('actions').style.display = 'none';
              var result = document.getElementById('result');
              result.style.display = 'block';
              result.innerHTML = '<div class="status-badge status-approved">APPROVED</div><p class="subtitle">Your identity has been verified. You can close this page.</p>';
            } else {
              var err = await res.json();
              btn.disabled = false; btn.textContent = 'Approve';
              if (err.statusCode === 401) { sessionStorage.removeItem(JWT_KEY); showAuthForm(); }
              else showError(err.message || 'Verification failed');
            }
          } catch(e) {
            btn.disabled = false; btn.textContent = 'Approve';
            showError('Network error. Please try again.');
          }
        }

        async function handleDeny() {
          var jwt = sessionStorage.getItem(JWT_KEY);
          if (!jwt) { showAuthForm(); return; }
          try {
            await fetch(API + '/api/v1/auth-sessions/' + TOKEN + '/deny', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + jwt }
            });
          } catch(e) {}
          document.getElementById('actions').style.display = 'none';
          var result = document.getElementById('result');
          result.style.display = 'block';
          result.innerHTML = '<div class="status-badge status-denied">DENIED</div><p class="subtitle">Request denied. You can close this page.</p>';
        }

        // Lightweight device fingerprinting
        function getFingerprint() {
          var components = [
            navigator.userAgent,
            navigator.language,
            screen.width + 'x' + screen.height,
            screen.colorDepth,
            new Date().getTimezoneOffset(),
            navigator.hardwareConcurrency || 'unknown',
            navigator.platform,
          ];
          // Simple hash
          var str = components.join('|');
          var hash = 0;
          for (var i = 0; i < str.length; i++) {
            var char = str.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash; // Convert to 32-bit integer
          }
          return 'fp_' + Math.abs(hash).toString(36);
        }
        var DEVICE_FINGERPRINT = getFingerprint();

        setTimeout(function() {
          document.getElementById('actions').style.display = 'none';
          document.getElementById('auth-section').style.display = 'none';
          var result = document.getElementById('result');
          if (!result.innerHTML) {
            result.style.display = 'block';
            result.innerHTML = '<div class="status-badge status-expired">EXPIRED</div><p class="subtitle">This request has expired.</p>';
          }
        }, ${AUTH_SESSION_EXPIRY_SECONDS * 1000});

        init();
      </script>
    `}

    <div class="footer">
      Secured by <a href="https://qrauth.io">vQR</a> &mdash; Verified QR Code Security Platform
    </div>
  </div>
</body>
</html>`);
  });
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
