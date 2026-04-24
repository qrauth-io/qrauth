---
title: Web Components
description: Drop-in custom elements for QR auth. Mobile-aware, framework-free, ~11 KB gzipped.
---

# Web Components

The `@qrauth/web-components` package ships three custom elements that drop into any HTML page with zero framework dependencies. Each one runs in a Shadow DOM, polls the QRAuth API, and fires standard DOM events that bubble across shadow boundaries.

This page is the **integration guide** — recipes, framework patterns, the mobile flow deep-dive, and the production gotchas. For the bare API reference, see the [Web Components SDK](/sdk/web-components) page.

| Component | What it does | Bundle line-of-sight |
|---|---|---|
| [`<qrauth-login>`](#qrauth-login) | Passwordless QR sign-in with mobile-aware fallback | ~11 KB gzipped (all three combined) |
| [`<qrauth-2fa>`](#qrauth-2fa) | Drop-in second-factor verification | included |
| [`<qrauth-ephemeral>`](#qrauth-ephemeral) | Time-limited access QRs | included |

## Installation

::: code-group

```html [CDN — pinned (recommended)]
<!--
  Pin a version + SRI hash for cache-safe, tamper-evident loads.
  Current versions and hashes: https://cdn.qrauth.io/v1/latest.json
-->
<script
  src="https://cdn.qrauth.io/v1/components-0.4.0.js"
  integrity="sha384-ZsvnpXBK9tghmz/PCtZUtR+7qTF7XhR35/SGNfJuJgLOBxnIRi3JYhRt1oFxNtU6"
  crossorigin="anonymous"
></script>
```

```html [CDN — rolling pointer]
<!-- Always-latest. ~60s edge TTL, no SRI. Fine for prototyping. -->
<script src="https://cdn.qrauth.io/v1/components.js"></script>
```

```bash [npm]
npm install @qrauth/web-components
```

```js [ESM import (after npm install)]
import '@qrauth/web-components';
```

:::

::: tip Get your tenant ID
The `tenant` attribute is the App's **client ID** (`qrauth_app_…`). Find it in the QRAuth dashboard under **Apps → your app → Client ID**.
:::

## CORS reality

Before integration patterns, the one infrastructure detail that shapes how you wire `base-url`:

**The QRAuth API is closed to cross-origin browser requests.** Its responses do not carry `Access-Control-Allow-Origin` and the page's CSP scopes `connect-src` to `'self'`. A browser at `https://yourapp.com` cannot directly `fetch('https://qrauth.io/api/v1/auth-sessions')` — the preflight will 404.

This means **you must run a small backend proxy** that forwards `/api/v1/auth-sessions*` requests to `https://qrauth.io/api/v1/auth-sessions*` with your server-side credentials. The web component's `base-url` then points at **your** origin, not `qrauth.io`.

Minimal Fastify proxy:

```ts
// Mounted under /api/v1
app.post('/auth-sessions', async (request, reply) => {
  const res = await fetch('https://qrauth.io/api/v1/auth-sessions', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: 'Basic ' +
        Buffer.from(`${env.QRAUTH_CLIENT_ID}:${env.QRAUTH_CLIENT_SECRET}`).toString('base64'),
    },
    body: JSON.stringify(request.body),
  });
  reply.status(res.status).send(await res.json());
});

app.get('/auth-sessions/:id', async (request, reply) => {
  const url = new URL(`https://qrauth.io/api/v1/auth-sessions/${request.params.id}`);
  for (const [k, v] of Object.entries(request.query as Record<string, string>)) {
    url.searchParams.set(k, v);
  }
  const res = await fetch(url, {
    headers: {
      Authorization: 'Basic ' +
        Buffer.from(`${env.QRAUTH_CLIENT_ID}:${env.QRAUTH_CLIENT_SECRET}`).toString('base64'),
    },
  });
  reply.status(res.status).send(await res.json());
});
```

Then on the page:

```html
<qrauth-login
  tenant="qrauth_app_xxx"
  base-url="https://yourapp.com"
></qrauth-login>
```

Why we don't open CORS on `qrauth.io`: it would expose the auth-session endpoint to any origin globally, including phishing pages. Restricting it to authenticated server-to-server traffic keeps the attack surface narrow. We may add per-app origin allowlists in a future release.

## `<qrauth-login>`

Drop-in QR authentication. Defaults to a button that opens a modal; switches to inline mode for embedded login pages.

### Quick start

```html
<qrauth-login
  tenant="qrauth_app_xxx"
  base-url="https://yourapp.com"
></qrauth-login>

<script>
  document.querySelector('qrauth-login')
    .addEventListener('qrauth:authenticated', async (e) => {
      const { sessionId, signature } = e.detail;
      // Send to your backend; verify against QRAuth; mint your own session.
      await fetch('/api/auth/qrauth-callback', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sessionId, signature }),
      });
      window.location.href = '/dashboard';
    });
</script>
```

### Display modes

`button` (default) renders a "Sign in with QRAuth" button that opens a modal:

```html
<qrauth-login tenant="qrauth_app_xxx"></qrauth-login>
```

`inline` mounts the flow directly inside the host element — no modal:

```html
<qrauth-login tenant="qrauth_app_xxx" display="inline"></qrauth-login>
```

### The mobile flow

This is the most important section if your users will sign in on phones.

**Problem.** A QR code on a phone is a dead-end — the user IS the phone they would use to scan. Showing a big "scan this QR with your phone camera" message on mobile is a UX trap.

**What the component does.** On coarse-pointer devices (`(pointer: coarse) and (hover: none)` matchMedia, with a UA-sniff fallback), the pending-state body switches: the QR is demoted to a `▸ Use another device` expander, and the primary CTA becomes a full-width **Continue with QRAuth** button. Tapping it opens (or navigates to — see below) the QRAuth hosted approval page, where the user signs in and approves on the same device.

After Approve, the hosted page navigates back to your registered `redirect-uri` with two query params appended:

```
https://yourapp.com/dashboard/?qrauth_session_id=cmoxxx&qrauth_signature=base64sig
```

Your app reads those params, exchanges them via your backend's QRAuth-callback proxy for your own session token, scrubs the URL, and renders the destination page. **No dependency on the original tab being alive** — works whether the new tab is a fresh tab, a same-tab navigation, or a tab that survived an OS suspension.

### Setting `redirect-uri`

```html
<qrauth-login
  tenant="qrauth_app_xxx"
  base-url="https://yourapp.com"
  redirect-uri="https://yourapp.com/dashboard/"
></qrauth-login>
```

Two requirements:

1. The URL must match an entry in your app's `redirectUrls` allowlist (set in the QRAuth dashboard under **Apps → your app → Redirect URLs**, or via `PATCH /apps/:id`). The server-side comparison normalises trailing slashes and ignores query string + fragment, so `/dashboard` matches `/dashboard/?from=qrauth`.
2. Your app's auth bootstrap must read `qrauth_session_id` + `qrauth_signature` query params on landing and complete the sign-in. Pattern:

```ts
// Run on every route mount (e.g. inside your AuthProvider's useEffect):
async function completeFromUrlIfPresent() {
  const url = new URL(window.location.href);
  const sessionId = url.searchParams.get('qrauth_session_id');
  const signature = url.searchParams.get('qrauth_signature');
  if (!sessionId || !signature) return;

  await fetch('/api/auth/qrauth-callback', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ sessionId, signature }),
  });

  // Scrub the params so a refresh can't replay the (already-consumed) signature.
  url.searchParams.delete('qrauth_session_id');
  url.searchParams.delete('qrauth_signature');
  window.history.replaceState({}, '', url.pathname + url.search + url.hash);
}
```

**Backend `/api/auth/qrauth-callback`** posts to `https://qrauth.io/api/v1/auth-sessions/verify-result` with the sessionId + signature, gets back a verified user payload, mints your own session JWT, returns it. The signature is one-time-use (consumed at `/verify-result`), so URL exposure carries the same risk profile as an OAuth `code`.

::: tip Without `redirect-uri`
The mobile CTA still works, but the hosted page lands on a "your identity has been verified — you can close this page" message after Approve. The user has to manually switch back to the original tab. Acceptable for desktop-first apps; not great on mobile.
:::

### Routing `/a/:token` to the redirect

The mobile CTA does `window.open(${baseUrl}/a/${token}, '_blank')`. Since `base-url` points at your origin (per the [CORS reality](#cors-reality) above), `${baseUrl}/a/<token>` lands on your server — but that path doesn't exist.

Add a redirect to the hosted page on QRAuth. With Next.js:

```ts
// next.config.ts
async redirects() {
  return [
    { source: '/a/:token', destination: 'https://qrauth.io/a/:token', permanent: false },
  ];
}
```

With nginx:

```nginx
location ~ ^/a/(.+)$ {
  return 307 https://qrauth.io/a/$1;
}
```

With Express:

```ts
app.get('/a/:token', (req, res) => {
  res.redirect(307, `https://qrauth.io/a/${encodeURIComponent(req.params.token)}`);
});
```

### Force-mode and opt-out

```html
<!-- Force the mobile body for screenshots / demos -->
<qrauth-login tenant="…" force-mode="mobile"></qrauth-login>

<!-- Force the desktop QR body even on mobile -->
<qrauth-login tenant="…" force-mode="desktop"></qrauth-login>

<!-- Opt out of mobile-aware UX entirely (legacy behaviour) -->
<qrauth-login tenant="…" mobile-fallback-only></qrauth-login>
```

`mobile-fallback-only` is the right choice when your page already provides a same-device login path (password, OAuth, magic link) and the QRAuth modal is purely the cross-device option.

### Events

| Event | `detail` | When |
|---|---|---|
| `qrauth:authenticated` | `{ sessionId, user, signature }` | User completed Approve. **Verify `signature` server-side**. |
| `qrauth:scanned` | session payload | QR was scanned (PENDING → SCANNED). |
| `qrauth:denied` | — | User declined on their device. |
| `qrauth:expired` | — | Session timed out. |
| `qrauth:error` | `{ message }` | Network or server-side error. |

All events bubble across the Shadow DOM (`composed: true`) so any framework can listen with `addEventListener`.

## `<qrauth-2fa>`

Step-up verification with the same session model. Use it when a user is already logged in and you need a fresh second-factor confirmation for a sensitive action.

```html
<qrauth-2fa
  tenant="qrauth_app_xxx"
  session-token="<your-app-jwt>"
  redirect-uri="https://yourapp.com/dashboard/"
  auto-start
></qrauth-2fa>

<script>
  document.querySelector('qrauth-2fa')
    .addEventListener('qrauth:verified', async (e) => {
      const { signature } = e.detail;
      // Verify server-side, then unlock the action.
      await unlockHighValueAction(signature);
    });
</script>
```

The mobile-aware UX, `redirect-uri` semantics, `force-mode` / `mobile-fallback-only` toggles, and `/a/:token` routing requirements are identical to `<qrauth-login>` — re-read those sections.

The `qrauth:verified` event fires in place of `qrauth:authenticated`, with the same detail shape (`sessionId`, `user`, `signature`).

## `<qrauth-ephemeral>`

Time-limited access QRs for kiosk pickup, hotel rooms, event check-in, and similar scenarios. The component generates the session itself when mounted — you don't pre-create it server-side.

```html
<qrauth-ephemeral
  tenant="qrauth_app_xxx"
  scopes="open:room-247"
  ttl="12h"
  device-binding
></qrauth-ephemeral>
```

| Use case | Pattern |
|---|---|
| Hotel door (one device, one claim) | `device-binding`, `max-uses="1"` |
| Event check-in (multiple staff scanning) | `max-uses="50"`, `ttl="8h"` |
| Locker pickup (single use, short window) | `ttl="15m"`, `max-uses="1"` |

The mobile-aware mode does **not** apply here — the ephemeral flow is "generate QR for another device to scan", which is the correct pattern on every viewport. The `force-mode` and `mobile-fallback-only` attributes are accepted but no-op as of 0.4.0, reserved for forward compatibility.

Listen for `qrauth:claimed`:

```js
document.querySelector('qrauth-ephemeral')
  .addEventListener('qrauth:claimed', (e) => {
    console.log('Granted access. Scopes:', e.detail.scopes);
  });
```

## React integration

`<qrauth-login>` is a Custom Element, not a React component. Two integration knobs:

### 1. JSX intrinsic-element declaration

React 19's new JSX runtime (used by Next.js 15+) reads `IntrinsicElements` from the `react/jsx-runtime` namespace; older React reads it from the global `JSX` namespace. Declare both to be safe:

```ts
// src/types/qrauth-web-components.d.ts
import type { DetailedHTMLProps, HTMLAttributes } from 'react';

type QRAuthLoginAttributes = {
  tenant?: string;
  theme?: 'light' | 'dark';
  'base-url'?: string;
  scopes?: string;
  display?: 'button' | 'inline';
  animated?: boolean | '';
  'redirect-uri'?: string;
  'force-mode'?: 'mobile' | 'desktop' | 'auto';
  'mobile-fallback-only'?: boolean | '';
};

type QRAuthLoginIntrinsic =
  DetailedHTMLProps<HTMLAttributes<HTMLElement>, HTMLElement> & QRAuthLoginAttributes;

declare module 'react' {
  namespace JSX {
    interface IntrinsicElements {
      'qrauth-login': QRAuthLoginIntrinsic;
    }
  }
}

declare global {
  namespace JSX {
    interface IntrinsicElements {
      'qrauth-login': QRAuthLoginIntrinsic;
    }
  }
}

export {};
```

The file must be picked up by your `tsconfig.json` `include` glob (typically `**/*.ts`).

### 2. Event listeners via `useRef` + `useEffect`

React's synthetic event system doesn't bridge Custom Element events. Wire them with `addEventListener`:

```tsx
'use client';
import { useEffect, useRef } from 'react';

export function QRAuthLogin() {
  const ref = useRef<HTMLElement>(null);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;

    const onAuth = async (event: Event) => {
      const { sessionId, signature } = (event as CustomEvent).detail;
      await fetch('/api/auth/qrauth-callback', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sessionId, signature }),
      });
      // …redirect to dashboard
    };
    const onError = (event: Event) => {
      const { message } = (event as CustomEvent).detail;
      console.error('QRAuth error:', message);
    };

    el.addEventListener('qrauth:authenticated', onAuth);
    el.addEventListener('qrauth:error', onError);
    return () => {
      el.removeEventListener('qrauth:authenticated', onAuth);
      el.removeEventListener('qrauth:error', onError);
    };
  }, []);

  return (
    <qrauth-login
      ref={ref as React.Ref<HTMLElement>}
      tenant={process.env.NEXT_PUBLIC_QRAUTH_CLIENT_ID}
      base-url={process.env.NEXT_PUBLIC_BACKEND_URL}
      redirect-uri="https://yourapp.com/dashboard/"
      scopes="identity email"
      display="inline"
    />
  );
}
```

### 3. Loading the bundle

In Next.js 15 (App Router):

```tsx
import Script from 'next/script';

<Script
  src="https://cdn.qrauth.io/v1/components-0.4.0.js"
  integrity="sha384-ZsvnpXBK9tghmz/PCtZUtR+7qTF7XhR35/SGNfJuJgLOBxnIRi3JYhRt1oFxNtU6"
  crossOrigin="anonymous"
  strategy="afterInteractive"
/>
```

In CRA / Vite, add the script tag to your `index.html` (or import from npm — both work). The bundle registers the custom elements as a side effect.

### 4. Server-side rendering caveat

Custom elements **don't render their shadow DOM during SSR** — the initial HTML contains an empty `<qrauth-login></qrauth-login>` tag. Once the bundle loads and hydration finishes, the shadow tree mounts. Plan for ~100-300 ms of unstyled space on first paint, or wrap the component in a placeholder until `customElements.get('qrauth-login')` resolves.

## Theming

All three components expose CSS custom properties on the host. Override on the element itself or globally:

```css
qrauth-login,
qrauth-2fa,
qrauth-ephemeral {
  --qrauth-primary:    #00a76f;
  --qrauth-text:       #1a1a2e;
  --qrauth-text-muted: #637381;
  --qrauth-bg:         #ffffff;
  --qrauth-surface:    #f9fafb;
  --qrauth-border:     #e0e0e0;
  --qrauth-radius:     12px;
  --qrauth-btn-bg:     #1b2a4a;
  --qrauth-btn-hover:  #263b66;
  --qrauth-shadow:     0 24px 48px rgba(0, 0, 0, 0.15);
  --qrauth-font:       'Inter', -apple-system, sans-serif;
}
```

Bundled dark palette:

```html
<qrauth-login tenant="qrauth_app_xxx" theme="dark"></qrauth-login>
```

System preference:

```js
const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
document.querySelector('qrauth-login')
  .setAttribute('theme', prefersDark ? 'dark' : 'light');
```

## Production gotchas

A short list of things that bite real integrations.

| Gotcha | What to do |
|---|---|
| **`window.open` blocked on mobile** falls back to same-tab navigation, original tab unloads, polling stops | Always set `redirect-uri` so URL-callback completes auth without depending on the original tab |
| **Mobile browsers suspend background tabs** while the user is on the qrauth.io approval page | Same — `redirect-uri` makes the new tab self-sufficient |
| **`sessionStorage` for the JWT** is per-tab and breaks the new-tab redirect | Use `localStorage` + a `storage` event listener as a fallback for the rare case where polling completed in another tab |
| **CORS on `qrauth.io`** — direct browser fetches fail | Proxy auth-sessions through your backend; point `base-url` at your origin |
| **`/a/:token` 404s on your origin** when `base-url` is your backend | Add a 307 redirect to `https://qrauth.io/a/:token` (Next.js `redirects()` or nginx `return 307`) |
| **`redirect-uri` rejected as 400** at session-create | Register the URL in your app's `redirectUrls` allowlist via the dashboard |
| **`redirect-uri` allowlist trailing-slash mismatch** | Server normalises both sides — `/dashboard` matches `/dashboard/`. Path beyond that is exact-match. |
| **CDN pointer caches old version** for ~60 s after release | Use the versioned URL with SRI for production; rolling pointer for prototyping |
| **React doesn't bridge Custom Events** | Wire `addEventListener` in `useEffect`, not `onQRAuthAuthenticated`-style props |
| **JSX `IntrinsicElements`** in React 19 lives on `react/jsx-runtime` namespace | Declare both `react/jsx-runtime` and global `JSX` namespaces in your `.d.ts` |
| **SSR shows empty `<qrauth-login>`** then hydrates | Reserve space with CSS or a placeholder until `customElements.get('qrauth-login')` resolves |

## Versioning

Pin a major.minor in production (`components-0.4.0.js` + SRI). The package follows semver — minor bumps add attributes and event detail fields without breaking; majors remove or rename. Watch the [CHANGELOG](https://github.com/qrauth-io/qrauth/blob/main/packages/web-components/CHANGELOG.md) for upgrade notes.

For the bare API reference (attribute table, event detail shapes, framework snippets), see the [Web Components SDK](/sdk/web-components) page.
