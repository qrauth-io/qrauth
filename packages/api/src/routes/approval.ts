import type { FastifyInstance } from 'fastify';
import { AuthSessionService } from '../services/auth-session.js';
import { hashString } from '../lib/crypto.js';
import { AUTH_SESSION_EXPIRY_SECONDS } from '@vqr/shared';

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
            <span class="scope-icon">&#x2713;</span>
            ${escapeHtml(scopeLabels[s] || s)}
          </div>
        `).join('')}
      </div>

      <div id="actions">
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
        var API_BASE = '';

        async function handleApprove() {
          var btn = document.getElementById('approveBtn');
          btn.disabled = true;
          btn.textContent = 'Verifying...';

          var geoLat, geoLng;
          try {
            var pos = await new Promise(function(resolve, reject) {
              navigator.geolocation.getCurrentPosition(resolve, reject, { timeout: 3000 });
            });
            geoLat = pos.coords.latitude;
            geoLng = pos.coords.longitude;
          } catch (e) {}

          var jwt = sessionStorage.getItem('jwt_access_token');
          if (!jwt) {
            window.location.href = '/auth/jwt/sign-in?returnTo=' + encodeURIComponent(window.location.href);
            return;
          }

          try {
            var res = await fetch(API_BASE + '/api/v1/auth-sessions/' + TOKEN + '/approve', {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + jwt,
              },
              body: JSON.stringify({ geoLat: geoLat, geoLng: geoLng }),
            });

            if (res.ok) {
              document.getElementById('actions').style.display = 'none';
              var result = document.getElementById('result');
              result.style.display = 'block';
              result.innerHTML = '<div class="status-badge status-approved">APPROVED</div><p class="subtitle">Your identity has been verified. You can close this page.</p>';
            } else {
              var err = await res.json();
              btn.disabled = false;
              btn.textContent = 'Approve';
              alert(err.message || 'Verification failed');
            }
          } catch (e) {
            btn.disabled = false;
            btn.textContent = 'Approve';
            alert('Network error. Please try again.');
          }
        }

        async function handleDeny() {
          var jwt = sessionStorage.getItem('jwt_access_token');
          if (!jwt) {
            window.location.href = '/auth/jwt/sign-in?returnTo=' + encodeURIComponent(window.location.href);
            return;
          }

          try {
            await fetch(API_BASE + '/api/v1/auth-sessions/' + TOKEN + '/deny', {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + jwt,
              },
            });
          } catch (e) {}

          document.getElementById('actions').style.display = 'none';
          var result = document.getElementById('result');
          result.style.display = 'block';
          result.innerHTML = '<div class="status-badge status-denied">DENIED</div><p class="subtitle">Request denied. You can close this page.</p>';
        }

        setTimeout(function() {
          var btn = document.getElementById('approveBtn');
          if (btn && !btn.disabled) {
            document.getElementById('actions').style.display = 'none';
            var result = document.getElementById('result');
            result.style.display = 'block';
            result.innerHTML = '<div class="status-badge status-expired">EXPIRED</div><p class="subtitle">This request has expired.</p>';
          }
        }, ${AUTH_SESSION_EXPIRY_SECONDS * 1000});
      </script>
    `}

    <div class="footer">
      Secured by <a href="https://vqr.io">vQR</a> &mdash; Verified QR Code Security Platform
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
