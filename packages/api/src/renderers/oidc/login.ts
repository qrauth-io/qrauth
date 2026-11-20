import { esc } from '../utils.js';
import { THEME_CSS } from '../_shared/theme.js';

/**
 * OP login page (ADR-0003 Slice 3b.3) — the public face of "Sign in with
 * QRAuth", on-brand with the homepage design system. Replaces the bare-bones
 * 3b.2 version; the functional shape is identical (server-rendered QR + a
 * minimal inline poller against /login/status that follows the approved
 * redirect). No framework, no CDN; CSP: style-src/script-src 'self'
 * 'unsafe-inline', img-src 'self' data: (set by nginx + the route header).
 *
 * Two load-bearing scrape points are preserved for the E2E
 * (oidc-auth-code-flow.spec.ts): the `${WEBAUTHN_ORIGIN}/a/<token>` scan URL
 * appears as a visible fallback link, and the poller id is emitted as
 * `var id = "<loginAttemptId>"`.
 *
 * Same-device sign-in: "Approve on this device" opens the approval page in
 * this tab with `?dr=1`. After Approve it returns to /login/resume, which
 * finishes the sign-in in this browser (routes/oidc-login.ts).
 *
 * On a phone the QR is hidden: nobody can scan a code shown on their own
 * screen. The phone view offers one action ("Continue with QRAuth") and keeps
 * the QR behind a "Use another device" toggle for the rare case where a second
 * device approves. The markup is the same for every viewport; CSS picks the
 * layout, so the E2E scrape points above are always in the HTML.
 */
export function renderOpLoginPage(args: {
  qrImageDataUrl: string;
  loginAttemptId: string;
  scanUrl: string;
  /**
   * The application being signed in to and the host the browser returns to;
   * null when the request does not identify a registered client.
   */
  destination?: { clientName: string; redirectHost: string } | null;
}): string {
  const { qrImageDataUrl, loginAttemptId, scanUrl, destination } = args;
  const sameDeviceUrl = `${scanUrl}?dr=1`;
  const target = destination
    ? `<span class="qr-grad-text">${esc(destination.clientName)}</span>`
    : '<span class="qr-grad-text">QRAuth</span>';
  // Desktop asks for a scan; a phone cannot scan its own screen.
  const heading = destination
    ? `<span class="h-desktop">Scan to sign in to </span><span class="h-phone">Sign in to </span>${target}`
    : `Sign in with ${target}`;
  // The name is whatever the client's owner typed; the host is where the
  // sign-in actually goes, so it is shown for every client.
  const hostLine = destination ? `\n  <p class="rp-host">${esc(destination.redirectHost)}</p>` : '';
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Sign in with QRAuth</title>
<style>
${THEME_CSS}
body { min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: var(--sp-5);
  background: radial-gradient(1100px 520px at 50% -15%, var(--bg-violet), transparent 60%), var(--bg); }
.card { width: 100%; max-width: 400px; background: var(--bg); border: 1px solid var(--line);
  border-radius: var(--r-xl); box-shadow: var(--shadow-lg); padding: var(--sp-6) var(--sp-5); text-align: center; }
.brand { display: inline-flex; align-items: center; gap: var(--sp-2); font-weight: var(--fw-bold);
  font-size: var(--fs-sm); letter-spacing: -0.01em; color: var(--ink); }
.brand .dot { width: 10px; height: 10px; border-radius: var(--r-pill); background: var(--grad-primary); }
h1 { margin-top: var(--sp-4); font-size: var(--fs-h1); font-weight: var(--fw-extrabold); letter-spacing: -0.02em; overflow-wrap: anywhere; }
.rp-host { margin-top: var(--sp-1); color: var(--ink-4); font-size: var(--fs-xs); overflow-wrap: anywhere; }
.sub { margin-top: var(--sp-2); color: var(--ink-3); font-size: var(--fs-sm); }
.qr-frame { position: relative; margin: var(--sp-5) auto 0; width: 264px; max-width: 100%;
  background: #fff; border: 1px solid var(--line); border-radius: var(--r-lg); padding: var(--sp-4); box-shadow: var(--shadow-sm); }
.qr-frame img { display: block; width: 232px; height: 232px; max-width: 100%; }
.qr-frame.is-done { opacity: 0.35; filter: grayscale(0.4); transition: opacity .4s ease, filter .4s ease; }
.qr-pulse { position: absolute; inset: -1px; border-radius: var(--r-lg); pointer-events: none;
  box-shadow: 0 0 0 0 rgba(79,70,229,0.35); animation: qr-pulse 2s ease-out infinite; }
@keyframes qr-pulse { 0% { box-shadow: 0 0 0 0 rgba(79,70,229,0.30); } 70% { box-shadow: 0 0 0 14px rgba(79,70,229,0); } 100% { box-shadow: 0 0 0 0 rgba(79,70,229,0); } }
.status { margin-top: var(--sp-5); display: flex; align-items: center; justify-content: center; gap: var(--sp-2);
  font-size: var(--fs-sm); font-weight: var(--fw-medium); color: var(--ink-3); min-height: 1.5em; }
.status .ring { width: 16px; height: 16px; border-radius: var(--r-pill); border: 2px solid var(--line);
  border-top-color: var(--indigo); animation: spin .8s linear infinite; }
@keyframes spin { to { transform: rotate(360deg); } }
.status[data-state="approved"] { color: var(--emerald); }
.status[data-state="denied"], .status[data-state="expired"] { color: var(--rose); }
.status[data-state="approved"] .ring, .status[data-state="denied"] .ring, .status[data-state="expired"] .ring { display: none; }
.status .mark { display: none; font-weight: var(--fw-bold); }
.status[data-state="approved"] .mark, .status[data-state="denied"] .mark, .status[data-state="expired"] .mark { display: inline; }
.retry { margin-top: var(--sp-4); }
.card { display: flex; flex-direction: column; align-items: center; }
.card > * { width: 100%; }
.card > .brand { width: auto; }
.qr-frame { width: 264px; }
.same-device { margin-top: var(--sp-4); }
.same-device .qr-btn { width: 100%; justify-content: center; }
.same-device .hint { margin-top: var(--sp-2); color: var(--ink-4); font-size: var(--fs-xs); }
.same-device .lead { margin-bottom: var(--sp-2); color: var(--ink-4); font-size: var(--fs-xs); }
.sub-phone, .sub-scan, .same-device .grad { display: none; }
.scan-block { width: 100%; }
/* Phones: the QR is hidden behind a toggle; approving here is the path. */
.h-phone, .scan-toggle { display: none; }
.scan-toggle { margin-top: var(--sp-5); background: none; border: 0; padding: var(--sp-2);
  color: var(--ink-3); font: inherit; font-size: var(--fs-xs); text-decoration: underline; cursor: pointer; }
@media (max-width: 640px), (hover: none) and (pointer: coarse) and (max-height: 500px) {
  .h-desktop, .sub-desktop, .same-device .lead, .same-device .outline, .fallback { display: none; }
  .h-phone, .sub-phone { display: inline; }
  .sub-phone { display: block; }
  .same-device { order: 1; margin-top: var(--sp-5); }
  .same-device .grad { display: inline-flex; }
  .scan-toggle { display: inline-block; order: 2; width: auto; }
  .scan-block { display: none; order: 3; }
  .card.show-scan .scan-block { display: block; }
  .card.show-scan .sub-scan { display: block; margin-top: var(--sp-3); color: var(--ink-4); font-size: var(--fs-xs); }
  .qr-frame { width: 200px; margin-top: var(--sp-2); }
  .qr-frame img { width: 168px; height: 168px; }
  .retry { order: 4; }
}
.fallback { margin-top: var(--sp-5); padding-top: var(--sp-4); border-top: 1px solid var(--line-soft);
  font-size: var(--fs-xs); color: var(--ink-4); }
.fallback a { color: var(--ink-3); word-break: break-all; }
@media (prefers-reduced-motion: reduce) { .qr-pulse, .status .ring { animation: none; } }
</style>
</head>
<body>
<main class="card">
  <span class="brand"><span class="dot" aria-hidden="true"></span>QRAuth</span>
  <h1>${heading}</h1>${hostLine}
  <p class="sub sub-desktop">Scan with your phone's camera to sign in.</p>
  <p class="sub sub-phone">Confirm it's you with QRAuth, right here on this phone.</p>
  <div class="scan-block" id="scan-block">
  <p class="sub-scan">Scan this code with the camera of another phone or tablet.</p>
  <div class="qr-frame" id="qr-frame">
    <span class="qr-pulse" aria-hidden="true"></span>
    <img src="${esc(qrImageDataUrl)}" alt="QR code to sign in with QRAuth" width="232" height="232">
  </div>
  <p class="status" id="status" data-state="pending" role="status" aria-live="polite">
    <span class="ring" aria-hidden="true"></span>
    <span class="mark" aria-hidden="true"></span>
    <span class="label">Waiting for scan…</span>
  </p>
  </div>
  <div class="retry" id="retry" hidden><a class="qr-btn qr-btn--grad" href="">Try again</a></div>
  <div class="same-device">
    <p class="lead">Signed in to QRAuth on this device?</p>
    <a class="qr-btn qr-btn--grad grad" id="same-device" href="${esc(sameDeviceUrl)}">Approve on this device</a>
    <a class="qr-btn qr-btn--outline outline" href="${esc(sameDeviceUrl)}">Approve on this device</a>
    <p class="hint">Opens QRAuth here and brings you back when you approve.</p>
  </div>
  <button type="button" class="scan-toggle" id="scan-toggle" aria-controls="scan-block" aria-expanded="false">Use another device</button>
  <p class="fallback">Can't scan? Open <a href="${esc(scanUrl)}">${esc(scanUrl)}</a></p>
</main>
<script>
(function () {
  var id = "${loginAttemptId}";
  var statusEl = document.getElementById('status');
  var labelEl = statusEl.querySelector('.label');
  var markEl = statusEl.querySelector('.mark');
  var retryEl = document.getElementById('retry');
  var frameEl = document.getElementById('qr-frame');
  var cardEl = document.querySelector('.card');
  var toggleEl = document.getElementById('scan-toggle');
  toggleEl.addEventListener('click', function () {
    var open = cardEl.classList.toggle('show-scan');
    toggleEl.setAttribute('aria-expanded', open ? 'true' : 'false');
    toggleEl.textContent = open ? 'Hide QR code' : 'Use another device';
  });
  var labels = {
    pending: 'Waiting for scan…',
    scanned: 'Scanned — confirm on your device…',
    approved: 'Approved. Redirecting…',
    denied: 'Sign-in was declined on your device.',
    expired: 'This sign-in request expired.'
  };
  var marks = { approved: '✓', denied: '✕', expired: '✕' };
  function setState(s) {
    statusEl.setAttribute('data-state', s);
    labelEl.textContent = labels[s] || labels.pending;
    markEl.textContent = marks[s] || '';
    if (s === 'approved' || s === 'denied' || s === 'expired') { frameEl.classList.add('is-done'); }
    if (s === 'denied' || s === 'expired') {
      var a = retryEl.querySelector('a');
      a.setAttribute('href', window.location.href);
      retryEl.hidden = false;
    }
  }
  var stopped = false;
  function poll() {
    if (stopped) return;
    fetch('/login/status?id=' + encodeURIComponent(id), { credentials: 'same-origin' })
      .then(function (r) { return r.ok ? r.json() : { status: 'expired' }; })
      .then(function (data) {
        var s = data && data.status ? data.status : 'pending';
        setState(s);
        if (s === 'approved' && data.redirectUrl) { stopped = true; window.location.assign(data.redirectUrl); return; }
        if (s === 'denied' || s === 'expired') { stopped = true; return; }
        setTimeout(poll, 1500);
      })
      .catch(function () { setTimeout(poll, 2000); });
  }
  setTimeout(poll, 1000);
})();
</script>
</body>
</html>`;
}

export type OpResumeState = 'waiting' | 'other_browser' | 'denied' | 'expired';

const RESUME_COPY: Record<OpResumeState, { title: string; body: string }> = {
  waiting: {
    title: 'Finishing sign-in…',
    body: 'Waiting for the approval to arrive. This page refreshes on its own.',
  },
  other_browser: {
    title: 'Return to your original window',
    body: 'This page was opened in a different browser from the one where you started signing in. Go back to that window: it continues on its own once you approve.',
  },
  denied: {
    title: 'Sign-in declined',
    body: 'The request was declined. Go back to the app and start again.',
  },
  expired: {
    title: 'This sign-in request expired',
    body: 'Go back to the app and start signing in again.',
  },
};

/**
 * /login/resume page, shown only when the resume cannot continue straight to
 * /authorize. No script: the waiting state refreshes with a meta tag.
 */
export function renderOpResumePage(state: OpResumeState): string {
  const { title, body } = RESUME_COPY[state];
  const refresh = state === 'waiting' ? '\n<meta http-equiv="refresh" content="2">' : '';
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">${refresh}
<title>Sign in with QRAuth</title>
<style>
${THEME_CSS}
body { min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: var(--sp-5);
  background: radial-gradient(1100px 520px at 50% -15%, var(--bg-violet), transparent 60%), var(--bg); }
.card { width: 100%; max-width: 400px; background: var(--bg); border: 1px solid var(--line);
  border-radius: var(--r-xl); box-shadow: var(--shadow-lg); padding: var(--sp-6) var(--sp-5); text-align: center; }
.brand { display: inline-flex; align-items: center; gap: var(--sp-2); font-weight: var(--fw-bold);
  font-size: var(--fs-sm); color: var(--ink); }
.brand .dot { width: 10px; height: 10px; border-radius: var(--r-pill); background: var(--grad-primary); }
h1 { margin-top: var(--sp-4); font-size: var(--fs-h2, 1.5rem); font-weight: var(--fw-extrabold); letter-spacing: -0.02em; }
p { margin-top: var(--sp-2); color: var(--ink-3); font-size: var(--fs-sm); }
</style>
</head>
<body>
<main class="card" data-state="${state}">
  <span class="brand"><span class="dot" aria-hidden="true"></span>QRAuth</span>
  <h1>${esc(title)}</h1>
  <p>${esc(body)}</p>
</main>
</body>
</html>`;
}
