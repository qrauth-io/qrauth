import { esc } from '../utils.js';
import { THEME_CSS } from '../_shared/theme.js';

/**
 * OP sign-out pages (audit 2026-10 FINDING-011, RP-Initiated Logout 1.0).
 * Script-free; the style block carries the per-response CSP nonce.
 */

const PAGE_CSS = `
body { min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: var(--sp-5);
  background: radial-gradient(1100px 520px at 50% -15%, var(--bg-violet), transparent 60%), var(--bg); }
.card { width: 100%; max-width: 420px; background: var(--bg); border: 1px solid var(--line);
  border-radius: var(--r-xl); box-shadow: var(--shadow-lg); padding: var(--sp-6) var(--sp-5); text-align: center; }
h1 { font-size: var(--fs-h1); font-weight: var(--fw-extrabold); letter-spacing: -0.02em; }
p { margin-top: var(--sp-3); color: var(--ink-3); font-size: var(--fs-sm); }
.actions { margin-top: var(--sp-5); }
.actions button { cursor: pointer; font: inherit; }
`;

function page(nonce: string, title: string, body: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>${esc(title)} — QRAuth</title>
<style nonce="${esc(nonce)}">
${THEME_CSS}
${PAGE_CSS}
</style>
</head>
<body>
<main class="card">
${body}
</main>
</body>
</html>`;
}

/**
 * Asks before ending the session. Shown when the request did not prove which
 * session it means (no valid `id_token_hint` for the signed-in user), so a
 * link on another site cannot sign the user out by itself. The hidden fields
 * are re-validated on the POST exactly as they were on the GET.
 */
export function renderLogoutConfirmPage(args: {
  nonce: string;
  clientId?: string;
  postLogoutRedirectUri?: string;
  state?: string;
}): string {
  const hidden = [
    ['client_id', args.clientId],
    ['post_logout_redirect_uri', args.postLogoutRedirectUri],
    ['state', args.state],
  ]
    .filter((field): field is [string, string] => typeof field[1] === 'string' && field[1].length > 0)
    .map(([name, value]) => `    <input type="hidden" name="${name}" value="${esc(value)}">`)
    .join('\n');

  return page(args.nonce, 'Sign out', `  <h1>Sign out of QRAuth?</h1>
  <p>You will need to scan a QR code again the next time a website signs you in with QRAuth.</p>
  <form method="post" action="/logout" class="actions">
    <input type="hidden" name="confirm" value="yes">
${hidden}
    <button class="qr-btn qr-btn--grad" type="submit">Sign out</button>
  </form>`);
}

export function renderSignedOutPage(nonce: string): string {
  return page(nonce, 'Signed out', `  <h1>You are signed out</h1>
  <p>You can close this window.</p>`);
}
