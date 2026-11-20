/**
 * Shared design tokens for all server-rendered HTML surfaces (ADR-0003
 * Slice 3b.3). Single source of truth for the visual language, mirroring the
 * marketing/homepage design system in
 * `packages/web/src/layouts/marketing/marketing-layout.tsx` (light theme,
 * indigo→cyan brand gradient, Satoshi/system-ui type, the shared shadow
 * scale).
 *
 * The renderer architecture inlines CSS inside a `<style nonce>` block (strict
 * nonce-based CSP, no external stylesheet), so this is exported as a CSS
 * string rather than a served `.css` file: every new page and every
 * retrofitted renderer inlines `THEME_CSS` at the top of its style block, then
 * layers page-specific rules referencing these tokens.
 */

/** `:root` design tokens + an accessible base/reset layer. */
export const THEME_CSS = `
:root {
  /* Surfaces */
  --bg: #FFFFFF;
  --bg-warm: #FAFAF9;
  --bg-cream: #FFFBF5;
  --bg-mint: #F0FDF4;
  --bg-violet: #F5F3FF;
  --bg-sky: #F0F9FF;
  /* Text */
  --ink: #0A0A0A;
  --ink-2: #262626;
  --ink-3: #525252;
  --ink-4: #737373;
  --ink-5: #A3A3A3;
  --line: #E5E5E5;
  --line-soft: #F0F0F0;
  /* Brand + semantic */
  --indigo: #4F46E5;
  --indigo-deep: #3730A3;
  --cyan: #06B6D4;
  --emerald: #059669;
  --emerald-soft: #10B981;
  --amber: #F59E0B;
  --rose: #F43F5E;
  --orange: #EA580C;
  --success: #059669;
  --warning: #F59E0B;
  --error: #F43F5E;
  --info: #06B6D4;
  --grad-primary: linear-gradient(135deg, #4F46E5 0%, #06B6D4 100%);
  --grad-warm: linear-gradient(135deg, #F59E0B 0%, #F43F5E 60%, #4F46E5 100%);
  --grad-mint: linear-gradient(135deg, #059669 0%, #06B6D4 100%);
  /* Type */
  --sans: 'Satoshi', system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif;
  --mono: 'JetBrains Mono', ui-monospace, 'SF Mono', Menlo, monospace;
  --fw-regular: 400;
  --fw-medium: 500;
  --fw-semibold: 600;
  --fw-bold: 700;
  --fw-extrabold: 800;
  /* Type scale */
  --fs-display: clamp(1.75rem, 4vw, 2.5rem);
  --fs-h1: clamp(1.5rem, 3vw, 2rem);
  --fs-h2: 1.25rem;
  --fs-h3: 1.0625rem;
  --fs-body: 1rem;
  --fs-sm: 0.9375rem;
  --fs-xs: 0.8125rem;
  --lh-tight: 1.2;
  --lh-body: 1.55;
  /* Spacing (4px base) */
  --sp-1: 4px;
  --sp-2: 8px;
  --sp-3: 12px;
  --sp-4: 16px;
  --sp-5: 24px;
  --sp-6: 32px;
  --sp-7: 48px;
  --sp-8: 64px;
  /* Radii */
  --r-sm: 8px;
  --r-md: 12px;
  --r-lg: 16px;
  --r-xl: 24px;
  --r-pill: 999px;
  /* Shadows */
  --shadow-sm: 0 1px 2px rgba(15,15,15,0.04), 0 1px 3px rgba(15,15,15,0.04);
  --shadow-md: 0 4px 6px -1px rgba(15,15,15,0.04), 0 2px 4px -2px rgba(15,15,15,0.04), 0 0 0 1px rgba(15,15,15,0.05);
  --shadow-lg: 0 10px 30px -3px rgba(15,15,15,0.08), 0 4px 12px -2px rgba(15,15,15,0.06), 0 0 0 1px rgba(15,15,15,0.04);
  --shadow-xl: 0 25px 50px -12px rgba(15,15,15,0.12), 0 10px 20px -5px rgba(15,15,15,0.06), 0 0 0 1px rgba(15,15,15,0.04);
}

*, *::before, *::after { box-sizing: border-box; }
html { -webkit-text-size-adjust: 100%; }
body {
  margin: 0;
  font-family: var(--sans);
  font-size: var(--fs-body);
  line-height: var(--lh-body);
  color: var(--ink-2);
  background: var(--bg);
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  text-rendering: optimizeLegibility;
}
h1, h2, h3 { color: var(--ink); line-height: var(--lh-tight); margin: 0; }
p { margin: 0; }
a { color: var(--indigo); }
:focus-visible { outline: 2px solid var(--indigo); outline-offset: 2px; border-radius: 4px; }
img { max-width: 100%; height: auto; }

/* Shared brand atoms reused across pages */
.qr-grad-text {
  background: var(--grad-primary);
  -webkit-background-clip: text;
  background-clip: text;
  -webkit-text-fill-color: transparent;
  color: transparent;
}
.qr-btn {
  display: inline-flex; align-items: center; justify-content: center; gap: var(--sp-2);
  font-family: var(--sans); font-weight: var(--fw-semibold); font-size: var(--fs-sm);
  padding: 10px 18px; border-radius: var(--r-pill); border: 1px solid transparent;
  text-decoration: none; cursor: pointer; transition: transform .15s ease, box-shadow .15s ease, background .15s ease;
}
.qr-btn--grad { background: var(--grad-primary); color: #fff; }
.qr-btn--grad:hover { box-shadow: var(--shadow-lg); transform: translateY(-1px); }
.qr-btn--outline { background: var(--bg); color: var(--ink); border-color: var(--line); }
.qr-btn--outline:hover { border-color: rgba(15,15,15,0.18); box-shadow: var(--shadow-md); transform: translateY(-1px); }
`;
