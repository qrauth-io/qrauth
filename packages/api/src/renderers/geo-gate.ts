import { randomBytes } from 'node:crypto';
import { esc } from './utils.js';

export interface GeoGateRenderResult {
  html: string;
  nonce: string;
}

export type GeoBlockReason = 'GEO_PROXIMITY_REQUIRED' | 'GEO_OUT_OF_FENCE';

interface GeoGatePageInput {
  token: string;
  orgName: string;
  scannedAt: string;
}

interface GeoBlockPageInput {
  token: string;
  orgName: string;
  reason: GeoBlockReason;
  scannedAt: string;
  /** Distance to the registered location in metres. Only present for out-of-fence blocks. */
  distanceM?: number;
  /** Fence radius the QR is bound to. */
  radiusM?: number;
}

/**
 * GPS-request interstitial served on the first hit of a geo-bound QR when the
 * scanner has not supplied coords. Asks the browser for location and reloads
 * with `?clientLat=…&clientLng=…` so the verify handler can run the proximity
 * check. On denial / timeout we re-render this page in deny mode so the user
 * sees a clear explanation and a retry button.
 *
 * Caller must set CSP with the returned nonce — see verify.ts cspOverride.
 */
export function renderGeoGatePage(input: GeoGatePageInput): GeoGateRenderResult {
  const nonce = randomBytes(16).toString('base64');
  const { token, orgName, scannedAt } = input;

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Location check — QRAuth</title>
  <style nonce="${nonce}">
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: #0c2461;
      color: #F8FAFC;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }
    .card {
      max-width: 420px;
      width: 100%;
      background: rgba(255,255,255,0.04);
      border: 1px solid rgba(255,255,255,0.08);
      border-radius: 18px;
      padding: 32px 24px;
      text-align: center;
    }
    .pin {
      width: 80px;
      height: 80px;
      margin: 0 auto 20px;
      border-radius: 50%;
      background: rgba(96, 165, 250, 0.15);
      display: flex;
      align-items: center;
      justify-content: center;
      animation: pulse 1.8s ease-in-out infinite;
    }
    @keyframes pulse {
      0%, 100% { transform: scale(1); opacity: 1; }
      50% { transform: scale(1.06); opacity: 0.85; }
    }
    h1 {
      font-size: 22px;
      font-weight: 700;
      margin-bottom: 10px;
    }
    p {
      font-size: 14px;
      color: rgba(248, 250, 252, 0.6);
      line-height: 1.55;
      margin-bottom: 20px;
    }
    .org {
      font-size: 12px;
      color: rgba(248, 250, 252, 0.4);
      margin-bottom: 24px;
    }
    .org strong { color: #F8FAFC; }
    button {
      display: block;
      width: 100%;
      padding: 14px 18px;
      background: #00A76F;
      color: #fff;
      border: none;
      border-radius: 10px;
      font-size: 15px;
      font-weight: 600;
      cursor: pointer;
      transition: opacity 0.2s, background 0.2s;
    }
    button:hover { background: #007B55; }
    button:disabled { opacity: 0.5; cursor: not-allowed; }
    .deny-card { display: none; }
    .deny-card .pin {
      background: rgba(255, 171, 0, 0.18);
      animation: none;
    }
    .deny-card h1 { color: #FFAB00; }
    .footer {
      margin-top: 20px;
      font-size: 11px;
      color: rgba(248, 250, 252, 0.25);
    }
    .footer a { color: rgba(248, 250, 252, 0.4); text-decoration: none; }
    .token {
      margin-top: 6px;
      font-family: 'JetBrains Mono', monospace;
      font-size: 10px;
      color: rgba(248, 250, 252, 0.25);
    }
  </style>
</head>
<body>
  <div class="card" id="gate-card">
    <div class="pin">
      <svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="#60A5FA" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 1 1 18 0z"/>
        <circle cx="12" cy="10" r="3"/>
      </svg>
    </div>
    <h1>Verifying location</h1>
    <p>This QR code is registered to a physical location. We need to check that you're nearby before we can show you the destination.</p>
    <div class="org">Issued by <strong>${esc(orgName)}</strong></div>
    <button id="grant-btn" type="button">Share my location</button>
    <div class="footer">
      Secured by <a href="https://qrauth.io">QRAuth</a>
      <div class="token">${esc(token)} · ${esc(scannedAt)}</div>
    </div>
  </div>

  <div class="card deny-card" id="deny-card">
    <div class="pin">
      <svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="#FFAB00" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 1 1 18 0z"/>
        <line x1="9" y1="9" x2="15" y2="15"/>
        <line x1="15" y1="9" x2="9" y2="15"/>
      </svg>
    </div>
    <h1>Location required</h1>
    <p id="deny-message">This QR code requires GPS access to verify. Your browser blocked the location request. Re-enable location access for this site and try again.</p>
    <div class="org">Issued by <strong>${esc(orgName)}</strong></div>
    <button id="retry-btn" type="button">Try again</button>
    <div class="footer">
      Secured by <a href="https://qrauth.io">QRAuth</a>
      <div class="token">${esc(token)} · ${esc(scannedAt)}</div>
    </div>
  </div>

  <script nonce="${nonce}">
    (function () {
      var gateCard = document.getElementById('gate-card');
      var denyCard = document.getElementById('deny-card');
      var denyMessage = document.getElementById('deny-message');
      var grantBtn = document.getElementById('grant-btn');
      var retryBtn = document.getElementById('retry-btn');

      function showDeny(msg) {
        if (msg) denyMessage.textContent = msg;
        gateCard.style.display = 'none';
        denyCard.style.display = 'block';
      }

      function requestPosition() {
        gateCard.style.display = 'block';
        denyCard.style.display = 'none';
        grantBtn.disabled = true;
        grantBtn.textContent = 'Waiting for GPS…';

        if (!navigator.geolocation) {
          showDeny('Your browser does not support location services. Use a modern browser to verify this QR code.');
          return;
        }

        navigator.geolocation.getCurrentPosition(
          function (pos) {
            var lat = pos.coords.latitude.toFixed(6);
            var lng = pos.coords.longitude.toFixed(6);
            var qs = new URLSearchParams(window.location.search);
            qs.set('clientLat', lat);
            qs.set('clientLng', lng);
            window.location.replace(window.location.pathname + '?' + qs.toString());
          },
          function (err) {
            grantBtn.disabled = false;
            grantBtn.textContent = 'Share my location';
            if (err && err.code === 1) {
              showDeny('Location access was denied. Re-enable location for this site in your browser settings and try again.');
            } else if (err && err.code === 3) {
              showDeny('GPS request timed out. Move outside or near a window and try again.');
            } else {
              showDeny('GPS unavailable on this device. Try again from a device with location services.');
            }
          },
          { timeout: 10000, maximumAge: 60000, enableHighAccuracy: true }
        );
      }

      grantBtn.addEventListener('click', requestPosition);
      retryBtn.addEventListener('click', requestPosition);

      // Auto-request on load — most users will grant immediately. If the
      // browser shows a permission prompt the button stays as a fallback.
      requestPosition();
    })();
  </script>
</body>
</html>`;

  return { html, nonce };
}

/**
 * Final deny page served when verification fails on geo-fence enforcement and
 * the issue cannot be resolved by re-requesting GPS. Used for out-of-fence
 * scans where coords were supplied but landed outside the radius.
 *
 * To avoid leaking the fence boundary, the distance is shown only when the
 * scanner is clearly outside (>= 2× radius). Closer scans get a generic
 * "outside the registered area" message so an attacker who has the QR cannot
 * use the page as a boundary oracle.
 */
export function renderGeoBlockPage(input: GeoBlockPageInput): GeoGateRenderResult {
  const nonce = randomBytes(16).toString('base64');
  const { token, orgName, reason, scannedAt, distanceM, radiusM } = input;

  const showDistance =
    reason === 'GEO_OUT_OF_FENCE' &&
    typeof distanceM === 'number' &&
    typeof radiusM === 'number' &&
    distanceM >= radiusM * 2;

  const distanceLabel =
    showDistance && typeof distanceM === 'number'
      ? distanceM >= 1000
        ? `${(distanceM / 1000).toFixed(1)} km`
        : `${Math.round(distanceM)} m`
      : null;

  const title =
    reason === 'GEO_PROXIMITY_REQUIRED'
      ? 'Location required'
      : 'Outside registered area';

  const body =
    reason === 'GEO_PROXIMITY_REQUIRED'
      ? 'This QR code is bound to a physical location. We were unable to confirm your location, so verification cannot proceed.'
      : distanceLabel
        ? `This QR code is registered to a specific location. You are <strong>${distanceLabel}</strong> away — too far for this code to be honored.`
        : 'This QR code is registered to a specific location and you appear to be outside the allowed area. Verification cannot proceed.';

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${esc(title)} — QRAuth</title>
  <style nonce="${nonce}">
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: #0c2461;
      color: #F8FAFC;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }
    .card {
      max-width: 420px;
      width: 100%;
      background: rgba(255,255,255,0.04);
      border: 1px solid rgba(255, 86, 48, 0.25);
      border-radius: 18px;
      padding: 32px 24px;
      text-align: center;
    }
    .pin {
      width: 80px;
      height: 80px;
      margin: 0 auto 20px;
      border-radius: 50%;
      background: rgba(255, 86, 48, 0.15);
      display: flex;
      align-items: center;
      justify-content: center;
    }
    h1 {
      font-size: 22px;
      font-weight: 800;
      color: #FF5630;
      margin-bottom: 10px;
    }
    p {
      font-size: 14px;
      color: rgba(248, 250, 252, 0.65);
      line-height: 1.55;
      margin-bottom: 20px;
    }
    p strong { color: #F8FAFC; }
    .org {
      font-size: 12px;
      color: rgba(248, 250, 252, 0.4);
      margin-bottom: 6px;
    }
    .org strong { color: #F8FAFC; }
    .footer {
      margin-top: 20px;
      font-size: 11px;
      color: rgba(248, 250, 252, 0.25);
    }
    .footer a { color: rgba(248, 250, 252, 0.4); text-decoration: none; }
    .token {
      margin-top: 6px;
      font-family: 'JetBrains Mono', monospace;
      font-size: 10px;
      color: rgba(248, 250, 252, 0.25);
    }
  </style>
</head>
<body>
  <div class="card">
    <div class="pin">
      <svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="#FF5630" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <circle cx="12" cy="12" r="10"/>
        <line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/>
      </svg>
    </div>
    <h1>${esc(title)}</h1>
    <p>${body}</p>
    <div class="org">Issued by <strong>${esc(orgName)}</strong></div>
    <div class="footer">
      Secured by <a href="https://qrauth.io">QRAuth</a>
      <div class="token">${esc(token)} · ${esc(scannedAt)}</div>
    </div>
  </div>
</body>
</html>`;

  return { html, nonce };
}
