import { THEME_CSS } from '../_shared/theme.js';

/**
 * id.qrauth.io landing page (ADR-0003 Slice 3b.3) — replaces the bare 404 at
 * `/`. Explains that this host is QRAuth's OpenID Provider (not the main
 * dashboard) and points visitors back to qrauth.io. No JS; on-brand,
 * responsive, WCAG AA. Inlines the shared design tokens (nonce-based CSP).
 */
export function renderLandingPage(): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>QRAuth — Identity Provider</title>
<meta name="description" content="id.qrauth.io is QRAuth's OpenID Connect provider.">
<style>
${THEME_CSS}
body { display: flex; flex-direction: column; min-height: 100vh; background:
  radial-gradient(1200px 600px at 50% -10%, var(--bg-violet), transparent 60%), var(--bg); }
.wrap { flex: 1; width: 100%; max-width: 760px; margin: 0 auto; padding: var(--sp-7) var(--sp-5); }
.brand { display: inline-flex; align-items: center; gap: var(--sp-2); font-weight: var(--fw-bold);
  font-size: var(--fs-h3); letter-spacing: -0.02em; color: var(--ink); text-decoration: none; }
.brand .dot { width: 12px; height: 12px; border-radius: var(--r-pill); background: var(--grad-primary); box-shadow: 0 0 0 4px var(--bg-violet); }
.hero { margin-top: var(--sp-7); }
.eyebrow { display: inline-block; font-size: var(--fs-xs); font-weight: var(--fw-semibold);
  letter-spacing: 0.06em; text-transform: uppercase; color: var(--indigo);
  background: var(--bg-violet); padding: 4px 12px; border-radius: var(--r-pill); }
h1 { margin-top: var(--sp-4); font-size: var(--fs-display); font-weight: var(--fw-extrabold); letter-spacing: -0.03em; }
.lede { margin-top: var(--sp-4); font-size: var(--fs-h3); color: var(--ink-3); max-width: 56ch; }
.cards { margin-top: var(--sp-7); display: grid; gap: var(--sp-4); grid-template-columns: 1fr; }
@media (min-width: 680px) { .cards { grid-template-columns: 1fr 1fr; } }
.card { background: var(--bg); border: 1px solid var(--line); border-radius: var(--r-lg);
  padding: var(--sp-5); box-shadow: var(--shadow-sm); }
.card h2 { font-size: var(--fs-h2); font-weight: var(--fw-bold); }
.card p { margin-top: var(--sp-2); color: var(--ink-3); font-size: var(--fs-sm); }
.card code { font-family: var(--mono); font-size: var(--fs-xs); background: var(--bg-warm);
  border: 1px solid var(--line-soft); border-radius: var(--r-sm); padding: 2px 6px; color: var(--ink-2); word-break: break-all; }
.actions { margin-top: var(--sp-6); display: flex; flex-wrap: wrap; gap: var(--sp-3); }
footer { border-top: 1px solid var(--line-soft); padding: var(--sp-5); text-align: center; color: var(--ink-4); font-size: var(--fs-xs); }
footer a { color: var(--ink-3); }
</style>
</head>
<body>
<main class="wrap">
  <a class="brand" href="https://qrauth.io"><span class="dot" aria-hidden="true"></span>QRAuth</a>
  <section class="hero">
    <span class="eyebrow">Identity Provider</span>
    <h1>This is QRAuth's <span class="qr-grad-text">identity provider</span>.</h1>
    <p class="lede">id.qrauth.io issues OpenID Connect sign-ins for apps that let you
      &ldquo;Sign in with QRAuth&rdquo;. It isn't the QRAuth dashboard.</p>
    <div class="actions">
      <a class="qr-btn qr-btn--grad" href="https://qrauth.io">Go to QRAuth</a>
      <a class="qr-btn qr-btn--outline" href="https://id.qrauth.io/.well-known/openid-configuration">OIDC discovery</a>
    </div>
  </section>
  <section class="cards">
    <article class="card">
      <h2>Why am I here?</h2>
      <p>An app sent you here to sign in with QRAuth. You'll see a QR code to scan
        with a device where you're already signed in — that's the whole flow.</p>
    </article>
    <article class="card">
      <h2>Looking for QRAuth?</h2>
      <p>The dashboard, your QR codes, and your account live at
        <a href="https://qrauth.io">qrauth.io</a>. Head there to manage everything.</p>
    </article>
    <article class="card">
      <h2>For developers</h2>
      <p>Standard OIDC. Point your client at <code>https://id.qrauth.io</code> and
        read the metadata at <code>/.well-known/openid-configuration</code>.</p>
    </article>
    <article class="card">
      <h2>Privacy by design</h2>
      <p>Each app you sign in to receives a distinct, pairwise identifier — so
        services can't correlate you across the web by your subject id.</p>
    </article>
  </section>
</main>
<footer>
  &copy; QRAuth · <a href="https://qrauth.io">qrauth.io</a>
</footer>
</body>
</html>`;
}
