import { esc } from '../utils.js';
import { THEME_CSS } from '../_shared/theme.js';

/**
 * OP consent page (audit 2026-10 FINDING-002). Shown by /authorize when a
 * CUSTOMER-tier client asks for scopes the signed-in user has not approved.
 *
 * A plain HTML form: no script at all, and the single `<style>` block carries
 * the per-response CSP nonce (same mechanism as renderers/shell.ts). The only
 * state in the form is the single-use consent token; the request it stands
 * for lives server-side (lib/oidc-consent.ts). Every value that came from a
 * client registration or the user row is escaped.
 */
export interface ConsentPageArgs {
  /** Per-response CSP nonce for the style block. */
  nonce: string;
  clientName: string;
  organizationName: string;
  /** Host the user is sent back to (from the validated redirect URI). */
  redirectHost: string;
  /** Plain-language line per requested scope. */
  scopeDescriptions: readonly string[];
  /** The account that is signed in to the OP. */
  accountEmail: string;
  consentToken: string;
}

export function renderConsentPage(args: ConsentPageArgs): string {
  const scopeItems = args.scopeDescriptions.map((line) => `    <li>${esc(line)}</li>`).join('\n');
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Allow access — QRAuth</title>
<style nonce="${esc(args.nonce)}">
${THEME_CSS}
body { min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: var(--sp-5);
  background: radial-gradient(1100px 520px at 50% -15%, var(--bg-violet), transparent 60%), var(--bg); }
.card { width: 100%; max-width: 440px; background: var(--bg); border: 1px solid var(--line);
  border-radius: var(--r-xl); box-shadow: var(--shadow-lg); padding: var(--sp-6) var(--sp-5); }
.brand { display: inline-flex; align-items: center; gap: var(--sp-2); font-weight: var(--fw-bold);
  font-size: var(--fs-sm); letter-spacing: -0.01em; color: var(--ink); }
.brand .dot { width: 10px; height: 10px; border-radius: var(--r-pill); background: var(--grad-primary); }
h1 { margin-top: var(--sp-4); font-size: var(--fs-h1); font-weight: var(--fw-extrabold); letter-spacing: -0.02em;
  word-break: break-word; }
.who { margin-top: var(--sp-2); color: var(--ink-3); font-size: var(--fs-sm); word-break: break-word; }
.who strong { color: var(--ink-2); }
h2 { margin-top: var(--sp-5); font-size: var(--fs-sm); font-weight: var(--fw-semibold); color: var(--ink-2); }
ul { margin-top: var(--sp-3); padding-left: var(--sp-5); color: var(--ink-2); font-size: var(--fs-sm); }
li { margin-top: var(--sp-2); }
.account { margin-top: var(--sp-5); padding: var(--sp-3) var(--sp-4); background: var(--bg-warm);
  border: 1px solid var(--line-soft); border-radius: var(--r-md); font-size: var(--fs-xs); color: var(--ink-3);
  word-break: break-word; }
.actions { margin-top: var(--sp-5); display: flex; gap: var(--sp-3); }
.actions button { flex: 1; cursor: pointer; font: inherit; }
.note { margin-top: var(--sp-4); font-size: var(--fs-xs); color: var(--ink-4); }
</style>
</head>
<body>
<main class="card">
  <span class="brand"><span class="dot" aria-hidden="true"></span>QRAuth</span>
  <h1>${esc(args.clientName)} wants to sign you in</h1>
  <p class="who">Run by <strong>${esc(args.organizationName)}</strong>. You will be sent back to
    <strong>${esc(args.redirectHost)}</strong>.</p>
  <h2>If you allow this, it will receive:</h2>
  <ul>
${scopeItems}
  </ul>
  <p class="account">Signed in as ${esc(args.accountEmail)}</p>
  <form method="post" action="/authorize/consent" class="actions">
    <input type="hidden" name="consent_token" value="${esc(args.consentToken)}">
    <button class="qr-btn qr-btn--outline" type="submit" name="decision" value="deny">Deny</button>
    <button class="qr-btn qr-btn--grad" type="submit" name="decision" value="approve">Allow</button>
  </form>
  <p class="note">QRAuth has not checked this app's name; its owner chose it. Make sure
    <strong>${esc(args.redirectHost)}</strong> is the website you meant to sign in to.</p>
  <p class="note">You can remove this app's access at any time from your QRAuth account.</p>
</main>
</body>
</html>`;
}

/** Shown when a consent form cannot be honoured (expired, replayed, wrong browser). */
export function renderConsentExpiredPage(nonce: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Request expired — QRAuth</title>
<style nonce="${esc(nonce)}">
${THEME_CSS}
body { min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: var(--sp-5); background: var(--bg); }
.card { width: 100%; max-width: 440px; background: var(--bg); border: 1px solid var(--line);
  border-radius: var(--r-xl); box-shadow: var(--shadow-lg); padding: var(--sp-6) var(--sp-5); }
h1 { font-size: var(--fs-h1); font-weight: var(--fw-extrabold); letter-spacing: -0.02em; }
p { margin-top: var(--sp-3); color: var(--ink-3); font-size: var(--fs-sm); }
</style>
</head>
<body>
<main class="card">
  <h1>This request can no longer be answered</h1>
  <p>It expired, was already answered, or was opened in a different browser.
    Go back to the website you were signing in to and start again.</p>
</main>
</body>
</html>`;
}
