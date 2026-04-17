import type { RenderContext } from './index.js';
import { esc } from './utils.js';
import { generateVisualFingerprint } from './visual-fingerprint.js';

export function renderShell(ctx: RenderContext, contentBody: string, visualFingerprintSeed?: string): string {
  const { verified, organization: org, security: sec, ephemeralProof, domainWarning, scannedAt } = ctx;

  const trustColor = sec.trustScore >= 80 ? '#00A76F' : sec.trustScore >= 50 ? '#FFAB00' : '#FF5630';

  // Visual fingerprint — unique crystalline pattern derived from the HMAC seed
  const fingerprintSvg = visualFingerprintSeed ? generateVisualFingerprint(visualFingerprintSeed) : '';

  // Shield SVG for the Trust Reveal overlay (80x80 viewport)
  const revealShield = verified
    ? `<svg viewBox="0 0 200 200" xmlns="http://www.w3.org/2000/svg">
        <path d="M48 24 H152 Q166 24 166 38 V108 Q166 156 100 182 Q34 156 34 108 V38 Q34 24 48 24 Z" fill="none" stroke="rgba(0,167,111,0.6)" stroke-width="5"/>
        <path d="M48 24 H152 Q166 24 166 38 V108 Q166 156 100 182 Q34 156 34 108 V38 Q34 24 48 24 Z" fill="rgba(0,167,111,0.12)"/>
        <path d="M62 104 L88 134 L144 64" fill="none" stroke="#00A76F" stroke-width="14" stroke-linecap="round" stroke-linejoin="round"/>
      </svg>`
    : `<svg viewBox="0 0 200 200" xmlns="http://www.w3.org/2000/svg">
        <path d="M48 24 H152 Q166 24 166 38 V108 Q166 156 100 182 Q34 156 34 108 V38 Q34 24 48 24 Z" fill="none" stroke="rgba(255,86,48,0.6)" stroke-width="5"/>
        <path d="M48 24 H152 Q166 24 166 38 V108 Q166 156 100 182 Q34 156 34 108 V38 Q34 24 48 24 Z" fill="rgba(255,86,48,0.12)"/>
        <path d="M70 80 L130 140 M130 80 L70 140" fill="none" stroke="#FF5630" stroke-width="14" stroke-linecap="round" stroke-linejoin="round"/>
      </svg>`;

  const statusIcon = verified
    ? '<svg width="32" height="32" viewBox="0 0 24 24" fill="none"><circle cx="12" cy="12" r="10" fill="#00A76F"/><path d="M8 12.5l2.5 2.5 5-5" stroke="#fff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>'
    : '<svg width="32" height="32" viewBox="0 0 24 24" fill="none"><circle cx="12" cy="12" r="10" fill="#FF5630"/><path d="M15 9l-6 6M9 9l6 6" stroke="#fff" stroke-width="2" stroke-linecap="round"/></svg>';

  const statusText = verified ? 'Verified' : 'Not Verified';
  const statusSub = verified
    ? `Issued by <strong>${esc(org.name)}</strong>`
    : 'This QR code could not be verified';

  // Trust level config — visual hierarchy
  const isGov = org.trustLevel === 'GOVERNMENT';
  const isBiz = org.trustLevel === 'BUSINESS';
  const isKycVerified = org.kycStatus === 'VERIFIED';
  const isKycPending = org.kycStatus === 'UNDER_REVIEW';
  const hasDomain = !!org.domainVerified;

  // Compute issuer trust tier (for visual treatment)
  // Tier A: Government + KYC verified + domain → highest trust
  // Tier B: Business + KYC verified → high trust
  // Tier C: Any with domain verified → moderate trust
  // Tier D: Unverified individual → low trust, show warning
  const isHighTrust = (isGov || isBiz) && isKycVerified;
  const isModerateTrust = hasDomain || isKycPending;
  const isLowTrust = !isHighTrust && !isModerateTrust;

  const orgType = isGov ? 'Government' : isBiz ? 'Business' : 'Individual';
  const orgTypeColor = isGov ? '#60A5FA' : isBiz ? '#C084FC' : '#94A3B8';
  const orgTypeIcon = isGov ? '&#127963;' : isBiz ? '&#127970;' : '&#128100;';
  const orgTypeBg = isGov ? 'rgba(59,130,246,0.12)' : isBiz ? 'rgba(192,132,252,0.12)' : 'rgba(148,163,184,0.08)';

  // Card border color based on trust
  const cardBorder = isHighTrust ? 'rgba(0,167,111,0.25)' : isLowTrust ? 'rgba(255,171,0,0.2)' : 'rgba(255,255,255,0.06)';

  // KYC status display
  const kycHtml = isKycVerified
    ? '<span class="org-tag tag-kyc">&#10003; Identity Verified</span>'
    : isKycPending
      ? '<span class="org-tag tag-pending">&#9203; Verification Pending</span>'
      : '<span class="org-tag tag-unverified">Not Verified</span>';

  // Domain display
  const domainHtml = hasDomain
    ? '<span class="org-tag tag-kyc">&#10003; Domain Verified</span>'
    : '';

  // Low trust warning
  const lowTrustWarning = isLowTrust && verified ? `
    <div class="trust-notice">
      <span class="trust-notice-icon">&#9432;</span>
      <span>This QR code was issued by an <strong>unverified individual account</strong>. Exercise caution before entering personal information or making payments.</span>
    </div>` : '';

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${verified ? 'Verified' : 'Warning'} \u2014 ${esc(org.name)} | QRAuth</title>

  <!-- Open Graph -->
  <meta property="og:type" content="article" />
  <meta property="og:site_name" content="QRAuth" />
  <meta property="og:title" content="${verified ? 'Verified' : 'Unverified'} QR Code \u2014 ${esc(org.name)}" />
  <meta property="og:description" content="${verified ? `Cryptographically verified QR code issued by ${esc(org.name)}. Trust Score: ${sec.trustScore}/100.` : `This QR code could not be verified. Exercise caution.`}" />
  <meta property="og:image" content="https://qrauth.io/og-image.png" />
  <meta property="og:image:width" content="1200" />
  <meta property="og:image:height" content="630" />

  <!-- Twitter Card -->
  <meta name="twitter:card" content="summary" />
  <meta name="twitter:title" content="${verified ? 'Verified' : 'Unverified'} QR Code \u2014 ${esc(org.name)} | QRAuth" />
  <meta name="twitter:description" content="${verified ? `Trust Score: ${sec.trustScore}/100. Issued by ${esc(org.name)}.` : `This QR code could not be verified.`}" />
  <meta name="twitter:image" content="https://qrauth.io/og-image.png" />

  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
      background: #081b4c;
      min-height: 100vh;
      display: flex;
      justify-content: center;
    }
    .page {
      width: 100%;
      max-width: 440px;
      min-height: 100vh;
      background: #0c2461;
      color: #F8FAFC;
      position: relative;
      overflow: hidden;
    }

    /* Status header */
    .status-header {
      padding: 32px 24px 24px;
      text-align: center;
      position: relative;
    }
    .status-header::after {
      content: '';
      position: absolute;
      bottom: 0;
      left: 24px;
      right: 24px;
      height: 1px;
      background: rgba(255,255,255,0.08);
    }
    .status-icon { margin-bottom: 12px; }
    .status-text {
      font-size: 24px;
      font-weight: 800;
      letter-spacing: -0.5px;
      color: ${verified ? '#00A76F' : '#FF5630'};
      margin-bottom: 4px;
    }
    .status-sub {
      font-size: 14px;
      color: rgba(248,250,252,0.6);
      line-height: 1.5;
    }
    .status-sub strong { color: #F8FAFC; }

    /* Trust score pill */
    .trust-pill {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      margin-top: 16px;
      padding: 6px 14px;
      background: rgba(255,255,255,0.06);
      border: 1px solid rgba(255,255,255,0.08);
      border-radius: 20px;
      font-size: 12px;
      font-weight: 600;
    }
    .trust-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: ${trustColor};
    }
    .trust-score { color: ${trustColor}; }
    .trust-label { color: rgba(248,250,252,0.5); }

    /* Org card */
    .org-card {
      margin: 20px 16px;
      padding: 16px;
      background: rgba(255,255,255,0.04);
      border: 1px solid rgba(255,255,255,0.06);
      border-radius: 14px;
    }
    .org-row {
      display: flex;
      align-items: center;
      gap: 12px;
    }
    .org-avatar {
      width: 40px;
      height: 40px;
      border-radius: 10px;
      background: rgba(0,167,111,0.15);
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 18px;
      font-weight: 800;
      color: #00A76F;
      flex-shrink: 0;
    }
    .org-name {
      font-size: 15px;
      font-weight: 700;
      color: #F8FAFC;
    }
    .org-tags {
      display: flex;
      gap: 6px;
      margin-top: 3px;
    }
    .org-tag {
      font-size: 10px;
      font-weight: 600;
      padding: 2px 8px;
      border-radius: 6px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    .tag-type { background: ${orgTypeBg}; color: ${orgTypeColor}; }
    .tag-kyc { background: rgba(0,167,111,0.15); color: #00A76F; }
    .tag-pending { background: rgba(255,171,0,0.12); color: #FFAB00; }
    .tag-unverified { background: rgba(148,163,184,0.1); color: #94A3B8; }

    /* Trust notice for unverified issuers */
    .trust-notice {
      margin: 0 16px 12px;
      padding: 12px 16px;
      background: rgba(255,171,0,0.08);
      border: 1px solid rgba(255,171,0,0.15);
      border-radius: 10px;
      font-size: 12px;
      color: rgba(248,250,252,0.6);
      display: flex;
      align-items: flex-start;
      gap: 8px;
      line-height: 1.5;
    }
    .trust-notice strong { color: #FFAB00; }
    .trust-notice-icon { color: #FFAB00; flex-shrink: 0; font-size: 14px; }

    /* Warning banner */
    .warn-banner {
      margin: 0 16px 12px;
      padding: 12px 16px;
      background: rgba(255,86,48,0.1);
      border: 1px solid rgba(255,86,48,0.2);
      border-radius: 10px;
      font-size: 13px;
      color: #FF8A65;
      display: flex;
      align-items: flex-start;
      gap: 8px;
      line-height: 1.5;
    }
    .warn-icon { flex-shrink: 0; margin-top: 1px; }

    /* Content area */
    .content-body {
      padding: 0 16px 16px;
    }
    /* Override content styles for dark theme */
    .content-body a {
      color: #60A5FA;
      text-decoration: none;
    }

    /* Location result */
    #location-result {
      display: none;
      margin: 0 16px 12px;
      padding: 12px 16px;
      border-radius: 10px;
      font-size: 13px;
      font-weight: 500;
    }
    .loc-match { background: rgba(0,167,111,0.1); border: 1px solid rgba(0,167,111,0.15); color: #00A76F; }
    .loc-far { background: rgba(255,171,0,0.1); border: 1px solid rgba(255,171,0,0.15); color: #FFAB00; }

    /* Ephemeral proof */
    .proof-card {
      margin: 0 16px 16px;
      padding: 14px 16px;
      background: rgba(255,255,255,0.03);
      border: 1px solid rgba(255,255,255,0.06);
      border-radius: 12px;
    }
    .proof-title {
      font-size: 10px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 1px;
      color: rgba(248,250,252,0.35);
      margin-bottom: 10px;
    }
    .proof-row {
      display: flex;
      justify-content: space-between;
      padding: 4px 0;
    }
    .proof-label { font-size: 12px; color: rgba(248,250,252,0.4); }
    .proof-value { font-size: 12px; font-weight: 600; color: rgba(248,250,252,0.85); }
    .proof-id { font-family: 'JetBrains Mono', monospace; color: #00A76F; }
    .proof-hint {
      font-size: 10px;
      color: rgba(248,250,252,0.2);
      margin-top: 8px;
      line-height: 1.4;
    }

    /* Origin warning */
    #origin-warning {
      display: none;
      margin: 12px 16px;
      padding: 12px 16px;
      background: rgba(255,86,48,0.15);
      border: 1px solid rgba(255,86,48,0.3);
      border-radius: 10px;
      color: #FF5630;
      font-size: 13px;
      font-weight: 600;
    }

    /* Footer */
    .footer {
      padding: 20px 16px;
      text-align: center;
      font-size: 11px;
      color: rgba(248,250,252,0.2);
      border-top: 1px solid rgba(255,255,255,0.04);
    }
    .footer a { color: rgba(248,250,252,0.4); text-decoration: none; }
    .footer a:hover { color: #00A76F; }
    .footer strong { color: rgba(248,250,252,0.35); }

    /* ------------------------------------------------------------------ */
    /* Trust Reveal overlay                                                 */
    /* ------------------------------------------------------------------ */
    .trust-reveal {
      position: fixed;
      inset: 0;
      z-index: 9999;
      display: flex;
      align-items: center;
      justify-content: center;
      flex-direction: column;
      background: #0c2461;
      animation: reveal-sweep 3s ease-out forwards;
      pointer-events: auto;
    }
    .trust-reveal.trust-failed {
      animation: reveal-fail 3s ease-out forwards;
    }

    @keyframes reveal-sweep {
      0%   { background: #0c2461; opacity: 1; pointer-events: auto; }
      25%  { background: ${trustColor}22; opacity: 1; }
      75%  { background: ${trustColor}22; opacity: 1; }
      99%  { opacity: 0; }
      100% { opacity: 0; pointer-events: none; }
    }

    @keyframes reveal-fail {
      0%   { background: #0c2461; opacity: 1; pointer-events: auto; }
      15%  { background: #3d0a00; opacity: 1; }
      40%  { background: #5c1100; opacity: 1; }
      60%  { background: #8B0000; opacity: 1; }
      85%  { background: #8B0000; opacity: 1; }
      99%  { opacity: 0; }
      100% { opacity: 0; pointer-events: none; }
    }

    .trust-reveal-inner {
      text-align: center;
      animation: reveal-content 2.8s ease-out forwards;
    }

    @keyframes reveal-content {
      0%   { transform: scale(0.8); opacity: 0; }
      20%  { transform: scale(1.02); opacity: 1; }
      30%  { transform: scale(1); opacity: 1; }
      75%  { opacity: 1; }
      99%  { opacity: 0; }
      100% { opacity: 0; }
    }

    .reveal-shield {
      width: 80px;
      height: 80px;
      margin: 0 auto 20px;
      animation: reveal-shield-in 0.6s cubic-bezier(0.175, 0.885, 0.32, 1.275) forwards;
    }
    .reveal-shield svg { width: 100%; height: 100%; }

    @keyframes reveal-shield-in {
      from { transform: scale(0) rotate(-15deg); opacity: 0; }
      to   { transform: scale(1) rotate(0deg);  opacity: 1; }
    }

    .reveal-status {
      font-size: 28px;
      font-weight: 800;
      color: #fff;
      margin-bottom: 8px;
      opacity: 0;
      animation: reveal-fade-up 0.5s ease-out 0.4s forwards;
    }

    .reveal-org {
      font-size: 16px;
      color: rgba(255,255,255,0.7);
      margin-bottom: 24px;
      opacity: 0;
      animation: reveal-fade-up 0.5s ease-out 0.6s forwards;
    }

    .reveal-fingerprint {
      opacity: 0;
      border-radius: 12px;
      overflow: hidden;
      animation: reveal-fade-up 0.5s ease-out 0.8s forwards;
    }

    @keyframes reveal-fade-up {
      from { transform: translateY(10px); opacity: 0; }
      to   { transform: translateY(0);    opacity: 1; }
    }

    .trust-failed .reveal-status { color: #FF5630; }

    .reveal-alarm {
      color: #FF5630;
      font-size: 20px;
      font-weight: 800;
      text-transform: uppercase;
      letter-spacing: 2px;
      opacity: 0;
      animation: reveal-alarm-pulse 0.3s ease-out 0.5s forwards;
    }
    .reveal-alarm small {
      font-size: 13px;
      font-weight: 600;
      letter-spacing: 1px;
      display: block;
      margin-top: 8px;
      color: rgba(255,255,255,0.55);
    }

    @keyframes reveal-alarm-pulse {
      from { transform: scale(0.9); opacity: 0; }
      to   { transform: scale(1);   opacity: 1; }
    }
  </style>
</head>
<body>
  <!-- Trust Reveal overlay — animates in, then fades away revealing the page -->
  <div id="trust-reveal" class="trust-reveal${verified ? '' : ' trust-failed'}">
    <div class="trust-reveal-inner">
      <div class="reveal-shield">${revealShield}</div>
      <div class="reveal-status">${verified ? 'Verified' : 'Not Verified'}</div>
      <div class="reveal-org">${esc(org.name)}</div>
      ${!verified ? '<div class="reveal-alarm">Fraudulent Code Detected<br><small>Do not proceed</small></div>' : ''}
      ${fingerprintSvg ? `<div class="reveal-fingerprint">${fingerprintSvg}</div>` : ''}
    </div>
  </div>

  <div class="page">
    <!-- Status header -->
    <div class="status-header">
      <div class="status-icon">${statusIcon}</div>
      <div class="status-text">${statusText}</div>
      <div class="status-sub">${statusSub}</div>
      <div class="trust-pill">
        <span class="trust-dot"></span>
        <span class="trust-label">Trust Score</span>
        <span class="trust-score">${sec.trustScore}/100</span>
      </div>
    </div>

    <!-- Organization card -->
    <div class="org-card" style="border-color:${cardBorder};">
      <div class="org-row">
        <div class="org-avatar" style="background:${orgTypeBg};color:${orgTypeColor};">${orgTypeIcon}</div>
        <div>
          <div class="org-name">${esc(org.name)}</div>
          <div class="org-tags">
            <span class="org-tag tag-type">${orgType}</span>
            ${kycHtml}
            ${domainHtml}
          </div>
        </div>
      </div>
    </div>

    ${lowTrustWarning}

    ${domainWarning ? `
    <div class="warn-banner">
      <span class="warn-icon">&#9888;</span>
      <span><strong>Phishing Warning:</strong> ${esc(domainWarning.message)}</span>
    </div>
    ` : ''}

    ${!verified && ctx.reason ? `
    <div class="warn-banner">
      <span class="warn-icon">&#9888;</span>
      <span>${esc(ctx.reason)}</span>
    </div>
    ` : ''}

    <!-- Content -->
    <div class="content-body">
      ${contentBody}
    </div>

    <!-- Location (populated via GPS) -->
    <div id="location-result"></div>

    <!-- Ephemeral proof -->
    ${ephemeralProof ? `
    <div class="proof-card">
      <div class="proof-title">Live Proof \u2014 unique to this scan</div>
      <div class="proof-row"><span class="proof-label">Location</span><span class="proof-value">${esc(ephemeralProof.city)}</span></div>
      <div class="proof-row"><span class="proof-label">Device</span><span class="proof-value">${esc(ephemeralProof.device)}</span></div>
      <div class="proof-row"><span class="proof-label">Time</span><span class="proof-value">${esc(new Date(ephemeralProof.timestamp).toLocaleString('en-GB', { dateStyle: 'medium', timeStyle: 'short' }))}</span></div>
      <div class="proof-row"><span class="proof-label">Proof ID</span><span class="proof-value proof-id">${esc(ephemeralProof.fingerprint)}</span></div>
      <div class="proof-hint">This proof is generated live for your device. A cloned page cannot reproduce it.</div>
    </div>
    ` : ''}

    <div id="origin-warning">
      &#9888; This page is not served from an official QRAuth domain. It may be a phishing attempt.
    </div>

    <!-- Footer -->
    <div class="footer">
      Secured by <a href="https://qrauth.io"><strong>QRAuth</strong></a>
    </div>
  </div>

  <script>
    (function() {
      // Origin integrity check
      var h = ['qrauth.io', 'localhost'];
      if (!h.some(function(d) { return location.hostname === d || location.hostname.endsWith('.' + d); })) {
        document.getElementById('origin-warning').style.display = 'block';
      }

      // Request GPS only if QR code has a registered location
      var hasLocation = ${ctx.qrCode.latitude != null && ctx.qrCode.longitude != null ? 'true' : 'false'};
      if (hasLocation && navigator.geolocation && !new URLSearchParams(window.location.search).has('clientLat')) {
        navigator.geolocation.getCurrentPosition(function(pos) {
          var lat = pos.coords.latitude.toFixed(6);
          var lng = pos.coords.longitude.toFixed(6);
          fetch(window.location.pathname + '?clientLat=' + lat + '&clientLng=' + lng, {
            headers: { 'Accept': 'application/json' }
          })
          .then(function(r) { return r.json(); })
          .then(function(data) {
            var loc = data.location_match;
            if (loc && loc.distanceM !== null) {
              var el = document.getElementById('location-result');
              if (el) {
                el.style.display = 'block';
                el.className = loc.matched ? 'loc-match' : 'loc-far';
                var dist = loc.distanceM >= 1000
                  ? (loc.distanceM / 1000).toFixed(1) + 'km'
                  : loc.distanceM + 'm';
                el.innerHTML = loc.matched
                  ? '&#10003; Within registered area (' + dist + ')'
                  : '&#128205; ' + dist + ' from registered location';
              }
            }
          })
          .catch(function() {});
        }, function() {}, { timeout: 5000, maximumAge: 60000 });
      }
    })();
  </script>
</body>
</html>`;
}
