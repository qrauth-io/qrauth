import type { RenderContext } from './index.js';
import { esc } from './utils.js';

export function renderShell(ctx: RenderContext, contentBody: string): string {
  const { verified, organization: org, security: sec, ephemeralProof, domainWarning, scannedAt } = ctx;

  const trustColor = sec.trustScore >= 80 ? '#00A76F' : sec.trustScore >= 50 ? '#FFAB00' : '#FF5630';

  const kycBadge = org.kycStatus === 'VERIFIED'
    ? '<span class="badge badge-green">KYC Verified</span>'
    : org.kycStatus === 'UNDER_REVIEW'
      ? '<span class="badge badge-yellow">KYC Pending</span>'
      : '<span class="badge badge-gray">Unverified</span>';

  const trustLevelBadge = org.trustLevel === 'GOVERNMENT'
    ? '<span class="badge badge-blue">Government</span>'
    : org.trustLevel === 'BUSINESS'
      ? '<span class="badge badge-blue">Business</span>'
      : '<span class="badge badge-gray">Individual</span>';

  const domainBadge = org.domainVerified
    ? '<span class="badge badge-green">Domain Verified</span>'
    : '<span class="badge badge-gray">Domain Unverified</span>';

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>vQR \u2014 ${esc(org.name)}</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; min-height: 100vh; }
    .page { max-width: 480px; margin: 0 auto; min-height: 100vh; background: white; box-shadow: 0 0 24px rgba(0,0,0,0.06); }
    .verify-bar { padding: 12px 20px; display: flex; align-items: center; gap: 10px; color: white; font-size: 13px; font-weight: 600; }
    .verify-bar.verified { background: #00A76F; }
    .verify-bar.unverified { background: #FF5630; }
    .verify-bar svg { width: 20px; height: 20px; flex-shrink: 0; }
    .org-bar { padding: 12px 20px; background: #f8f9fa; border-bottom: 1px solid #f0f0f0; }
    .org-name { font-size: 14px; font-weight: 700; color: #212b36; }
    .badges { display: flex; gap: 4px; flex-wrap: wrap; margin-top: 4px; }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 10px; font-weight: 600; }
    .badge-green { background: #E8F5E9; color: #1B5E20; }
    .badge-yellow { background: #FFF8E1; color: #F57F17; }
    .badge-blue { background: #E3F2FD; color: #0D47A1; }
    .badge-gray { background: #F5F5F5; color: #616161; }
    .badge-red { background: #FFEBEE; color: #C62828; }
    .content-body { padding: 24px 20px; }
    .warn-banner { padding: 12px 16px; background: #FFF3E0; border-radius: 8px; font-size: 13px; color: #E65100; margin-bottom: 16px; display: flex; align-items: center; gap: 8px; }
    .trust-bar-mini { height: 4px; border-radius: 2px; background: #f0f0f0; margin-top: 8px; }
    .trust-fill-mini { height: 100%; border-radius: 2px; background: ${trustColor}; width: ${sec.trustScore}%; }
    .ephemeral { padding: 12px 16px; background: #f8f9fa; border-radius: 8px; font-size: 12px; margin-top: 16px; }
    .ephemeral-row { display: flex; justify-content: space-between; padding: 3px 0; }
    .ephemeral-label { color: #919eab; }
    .ephemeral-value { font-weight: 600; color: #212b36; }
    .footer { padding: 16px 20px; text-align: center; font-size: 11px; color: #919eab; border-top: 1px solid #f0f0f0; }
    .footer a { color: #637381; text-decoration: none; }
    #origin-warning { display: none; margin: 12px 20px; padding: 12px 16px; background: #FFEBEE; border-radius: 8px; border-left: 4px solid #C62828; color: #C62828; font-size: 13px; }
  </style>
</head>
<body>
  <div class="page">
    <!-- Verification status bar -->
    <div class="verify-bar ${verified ? 'verified' : 'unverified'}">
      ${verified
        ? '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z"/></svg> Verified by vQR'
        : '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 2C6.47 2 2 6.47 2 12s4.47 10 10 10 10-4.47 10-10S17.53 2 12 2zm5 13.59L15.59 17 12 13.41 8.41 17 7 15.59 10.59 12 7 8.41 8.41 7 12 10.59 15.59 7 17 8.41 13.41 12 17 15.59z"/></svg> Verification Failed'
      }
      <div style="margin-left:auto;font-size:11px;opacity:0.8;">${sec.trustScore}/100</div>
    </div>

    <!-- Org identity bar -->
    <div class="org-bar">
      <div class="org-name">${esc(org.name)}</div>
      <div class="badges">${trustLevelBadge} ${kycBadge} ${domainBadge}</div>
      <div class="trust-bar-mini"><div class="trust-fill-mini"></div></div>
    </div>

    ${domainWarning ? `
    <div class="warn-banner" style="margin:12px 20px;background:#FFEBEE;color:#C62828;border-left:4px solid #C62828;">
      <strong>&#9888; Phishing Warning:</strong> ${esc(domainWarning.message)}
    </div>
    ` : ''}

    ${!verified && ctx.reason ? `<div class="warn-banner" style="margin:12px 20px;">&#9888; ${esc(ctx.reason)}</div>` : ''}

    <!-- Content body (type-specific) -->
    <div class="content-body">
      ${contentBody}
    </div>

    <!-- Ephemeral proof -->
    ${ephemeralProof ? `
    <div class="ephemeral" style="margin:0 20px 16px;">
      <div style="font-size:10px;font-weight:600;text-transform:uppercase;color:#919eab;margin-bottom:6px;">Ephemeral Proof \u2014 personalized to you</div>
      <div class="ephemeral-row"><span class="ephemeral-label">Location</span><span class="ephemeral-value">${esc(ephemeralProof.city)}</span></div>
      <div class="ephemeral-row"><span class="ephemeral-label">Device</span><span class="ephemeral-value">${esc(ephemeralProof.device)}</span></div>
      <div class="ephemeral-row"><span class="ephemeral-label">Time</span><span class="ephemeral-value">${esc(ephemeralProof.timestamp)}</span></div>
      <div class="ephemeral-row"><span class="ephemeral-label">Proof ID</span><span class="ephemeral-value" style="color:#00A76F;font-family:monospace;">${esc(ephemeralProof.fingerprint)}</span></div>
      <div style="font-size:10px;color:#c4cdd5;margin-top:4px;">If this doesn't match your device and location, this page may be cloned.</div>
    </div>
    ` : ''}

    <div id="origin-warning">
      <strong>&#9888; WARNING:</strong> This page is not served from an official vQR domain. This may be a cloned phishing page.
    </div>

    <!-- Footer -->
    <div class="footer">
      Secured by <a href="https://vqr.progressnet.io"><strong>vQR</strong></a> &middot; Token: ${esc(ctx.qrCode.token)} &middot; ${esc(scannedAt)}
    </div>
  </div>

  <script>
    (function() {
      // Origin integrity check
      var h = ['vqr.io', 'vqr.progressnet.io', 'localhost'];
      if (!h.some(function(d) { return location.hostname === d || location.hostname.endsWith('.' + d); })) {
        document.getElementById('origin-warning').style.display = 'block';
      }

      // Request GPS and re-verify with location for proximity check
      if (navigator.geolocation) {
        navigator.geolocation.getCurrentPosition(function(pos) {
          var lat = pos.coords.latitude;
          var lng = pos.coords.longitude;
          // Reload with coordinates to get location match
          var url = new URL(window.location.href);
          if (!url.searchParams.has('clientLat')) {
            url.searchParams.set('clientLat', lat.toFixed(6));
            url.searchParams.set('clientLng', lng.toFixed(6));
            window.location.replace(url.toString());
          }
        }, function() {}, { timeout: 5000, maximumAge: 60000 });
      }
    })();
  </script>
</body>
</html>`;
}
