import { esc } from '../utils.js';
import { THEME_CSS } from '../_shared/theme.js';

/**
 * /authorize error page (ADR-0003 Slice 3b.3). Shown for browser requests when
 * client_id / redirect_uri validation fails — we can't safely redirect to an
 * unverified RP URI, so we render here instead of bouncing. JSON clients
 * (Accept: application/json) still get the machine-readable body; this is the
 * HTML branch. Friendly, non-technical, with the raw error tucked into a
 * <details> for diagnostics. HTTP 400.
 */
export function renderAuthorizeErrorPage(args: { error: string; description: string }): string {
  const { error, description } = args;
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Sign-in link problem — QRAuth</title>
<style>
${THEME_CSS}
body { min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: var(--sp-5);
  background: radial-gradient(1000px 500px at 50% -15%, var(--bg-cream), transparent 60%), var(--bg); }
.card { width: 100%; max-width: 460px; background: var(--bg); border: 1px solid var(--line);
  border-radius: var(--r-xl); box-shadow: var(--shadow-lg); padding: var(--sp-6) var(--sp-5); }
.icon { width: 48px; height: 48px; border-radius: var(--r-pill); display: flex; align-items: center; justify-content: center;
  background: var(--bg-cream); color: var(--amber); margin-bottom: var(--sp-4); }
.icon svg { width: 26px; height: 26px; }
h1 { font-size: var(--fs-h1); font-weight: var(--fw-extrabold); letter-spacing: -0.02em; }
p { margin-top: var(--sp-3); color: var(--ink-3); font-size: var(--fs-sm); }
details { margin-top: var(--sp-5); background: var(--bg-warm); border: 1px solid var(--line-soft);
  border-radius: var(--r-md); padding: var(--sp-3) var(--sp-4); }
summary { cursor: pointer; font-size: var(--fs-xs); font-weight: var(--fw-semibold); color: var(--ink-4); }
details code { display: block; margin-top: var(--sp-3); font-family: var(--mono); font-size: var(--fs-xs);
  color: var(--ink-2); word-break: break-word; }
.actions { margin-top: var(--sp-6); }
</style>
</head>
<body>
<main class="card">
  <div class="icon" aria-hidden="true">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
      <line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
    </svg>
  </div>
  <h1>This sign-in link looks wrong</h1>
  <p>The website that sent you here didn't set up &ldquo;Sign in with QRAuth&rdquo;
    correctly, so we can't continue safely. This isn't something you did.</p>
  <p>Please go back to that website and, if it keeps happening, contact its support.</p>
  <details>
    <summary>Technical details</summary>
    <code>${esc(error)}: ${esc(description)}</code>
  </details>
  <div class="actions">
    <a class="qr-btn qr-btn--outline" href="https://id.qrauth.io/">About id.qrauth.io</a>
  </div>
</main>
</body>
</html>`;
}
