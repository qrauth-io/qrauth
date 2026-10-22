import { esc } from '../utils.js';
import { THEME_CSS } from '../_shared/theme.js';

/**
 * Sends the browser back to the relying party after a form POST (consent
 * Allow / Deny, sign-out confirmation). Navigation is a meta refresh (see
 * routes/oidc-html.ts for why it is not a redirect); the link is the fallback if the browser does not follow it.
 */
export function renderReturnPage(args: { nonce: string; targetUrl: string; targetHost: string }): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<meta name="referrer" content="no-referrer">
<meta http-equiv="refresh" content="0;url=${esc(args.targetUrl)}">
<title>Returning — QRAuth</title>
<style nonce="${esc(args.nonce)}">
${THEME_CSS}
body { min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: var(--sp-5); background: var(--bg); }
p { color: var(--ink-3); font-size: var(--fs-sm); text-align: center; word-break: break-word; }
</style>
</head>
<body>
<main>
  <p>Returning you to ${esc(args.targetHost)}…</p>
  <p><a href="${esc(args.targetUrl)}" rel="noreferrer">Continue</a></p>
</main>
</body>
</html>`;
}
