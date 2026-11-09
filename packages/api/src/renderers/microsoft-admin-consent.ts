import { esc } from './utils.js';
import { THEME_CSS } from './_shared/theme.js';

const GUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const MAX_ERROR_CODE_LENGTH = 80;
const MAX_ERROR_DESCRIPTION_LENGTH = 300;
const ENTRA_GUIDE_URL = 'https://docs.qrauth.io/guide/microsoft-entra.html';

export type MicrosoftAdminConsentResult =
  | { kind: 'approved'; tenantId?: string }
  | { kind: 'error'; errorCode: string; errorDescription?: string };

/**
 * Read Microsoft's admin-consent return (`admin_consent=True&tenant=...`, or
 * `error`/`error_description`). Nothing here is trusted: the result only picks
 * which static page to show. Returns null when the query carries neither, i.e.
 * the page was opened directly.
 */
export function parseMicrosoftAdminConsent(
  query: Record<string, unknown>,
): MicrosoftAdminConsentResult | null {
  const text = (value: unknown): string => (typeof value === 'string' ? value.trim() : '');

  const errorCode = text(query.error);
  if (errorCode) {
    const errorDescription = text(query.error_description).slice(0, MAX_ERROR_DESCRIPTION_LENGTH);
    return {
      kind: 'error',
      errorCode: errorCode.slice(0, MAX_ERROR_CODE_LENGTH),
      ...(errorDescription ? { errorDescription } : {}),
    };
  }

  if (text(query.admin_consent).toLowerCase() !== 'true') return null;

  const tenantId = text(query.tenant);
  return { kind: 'approved', ...(GUID_RE.test(tenantId) ? { tenantId } : {}) };
}

const CHECK_ICON = '<path d="M20 6 9 17l-5-5"/>';
const WARNING_ICON =
  '<path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>' +
  '<line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>';

function approvedBody(tenantId?: string): string {
  return `<h1>QRAuth is approved</h1>
  <p>QRAuth is now approved for your organisation. Your users can sign in with Microsoft.</p>
  <p>You can close this page. Nobody was signed in to QRAuth by this step.</p>
  ${tenantId ? `<details><summary>Technical details</summary><code>Tenant: ${esc(tenantId)}</code></details>` : ''}`;
}

function errorBody(errorCode: string, errorDescription?: string): string {
  return `<h1>QRAuth was not approved</h1>
  <p>Microsoft did not record an approval for your organisation, so nothing has changed.
    If you cancelled or declined, you can open the admin consent link again when you are ready.</p>
  <p>Error code: <code class="code">${esc(errorCode)}</code></p>
  ${errorDescription ? `<details><summary>Technical details</summary><code>${esc(errorDescription)}</code></details>` : ''}`;
}

/**
 * Landing page for Microsoft's admin-consent redirect. Static HTML, no script,
 * same light theme as the id.qrauth.io pages. `result` null = opened directly.
 */
export function renderMicrosoftAdminConsentPage(result: MicrosoftAdminConsentResult | null): string {
  const approved = result?.kind === 'approved';
  const body = result?.kind === 'approved'
    ? approvedBody(result.tenantId)
    : errorBody(result?.errorCode ?? 'missing_result', result?.errorDescription);

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>${approved ? 'QRAuth approved for your organisation' : 'QRAuth was not approved'} — QRAuth</title>
<style>
${THEME_CSS}
body { min-height: 100vh; display: flex; flex-direction: column; align-items: center; justify-content: center;
  gap: var(--sp-5); padding: var(--sp-5);
  background: radial-gradient(1000px 500px at 50% -15%, var(--bg-violet), transparent 60%), var(--bg); }
.brand { display: inline-flex; align-items: center; gap: var(--sp-2); font-weight: var(--fw-bold);
  font-size: var(--fs-h3); letter-spacing: -0.02em; color: var(--ink); text-decoration: none; }
.brand .dot { width: 12px; height: 12px; border-radius: var(--r-pill); background: var(--grad-primary); box-shadow: 0 0 0 4px var(--bg-violet); }
.card { width: 100%; max-width: 460px; background: var(--bg); border: 1px solid var(--line);
  border-radius: var(--r-xl); box-shadow: var(--shadow-lg); padding: var(--sp-6) var(--sp-5); }
.icon { width: 48px; height: 48px; border-radius: var(--r-pill); display: flex; align-items: center; justify-content: center;
  margin-bottom: var(--sp-4); }
.icon--ok { background: var(--bg-violet); color: var(--indigo); }
.icon--error { background: var(--bg-cream); color: var(--amber); }
.icon svg { width: 26px; height: 26px; }
h1 { font-size: var(--fs-h1); font-weight: var(--fw-extrabold); letter-spacing: -0.02em; }
p { margin-top: var(--sp-3); color: var(--ink-3); font-size: var(--fs-sm); }
.code { font-family: var(--mono); color: var(--ink-2); word-break: break-word; }
details { margin-top: var(--sp-5); background: var(--bg-warm); border: 1px solid var(--line-soft);
  border-radius: var(--r-md); padding: var(--sp-3) var(--sp-4); }
summary { cursor: pointer; font-size: var(--fs-xs); font-weight: var(--fw-semibold); color: var(--ink-4); }
details code { display: block; margin-top: var(--sp-3); font-family: var(--mono); font-size: var(--fs-xs);
  color: var(--ink-2); word-break: break-word; }
.actions { margin-top: var(--sp-6); }
</style>
</head>
<body>
<a class="brand" href="https://qrauth.io"><span class="dot" aria-hidden="true"></span>QRAuth</a>
<main class="card">
  <div class="icon ${approved ? 'icon--ok' : 'icon--error'}" aria-hidden="true">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${approved ? CHECK_ICON : WARNING_ICON}</svg>
  </div>
  ${body}
  <div class="actions">
    <a class="qr-btn qr-btn--outline" href="${ENTRA_GUIDE_URL}">Microsoft Entra ID admin guide</a>
  </div>
</main>
</body>
</html>`;
}
