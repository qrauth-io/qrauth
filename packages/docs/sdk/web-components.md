---
title: Web Components SDK
description: Drop-in custom elements for QR-based authentication, 2FA, and ephemeral access. Framework-free, ~11 KB gzipped.
---

# Web Components SDK

The `@qrauth/web-components` package ships three Shadow DOM custom elements that handle the full QR auth lifecycle. Drop one script tag into any HTML page — no build step, no framework adapter.

- **`<qrauth-login>`** — passwordless sign-in (button or inline). Mobile-aware.
- **`<qrauth-2fa>`** — drop-in second-factor step.
- **`<qrauth-ephemeral>`** — time-limited access QRs.

For end-to-end recipes, framework integrations, and the mobile flow deep-dive, see the [Web Components guide](/guide/web-components). This page is the API reference.

## Installation

### CDN (recommended)

```html
<script
  src="https://cdn.qrauth.io/v1/components-0.4.0.js"
  integrity="sha384-ZsvnpXBK9tghmz/PCtZUtR+7qTF7XhR35/SGNfJuJgLOBxnIRi3JYhRt1oFxNtU6"
  crossorigin="anonymous"
></script>
```

Current versions and SRI hashes: [`https://cdn.qrauth.io/v1/latest.json`](https://cdn.qrauth.io/v1/latest.json).

A rolling pointer at `https://cdn.qrauth.io/v1/components.js` always serves the latest version with a 60-second TTL — useful for prototyping, but pin a versioned URL with SRI in production.

### npm

```bash
npm install @qrauth/web-components
```

```typescript
import '@qrauth/web-components';
```

The import has the side effect of registering all three custom elements on `customElements`. No additional setup.

---

## `<qrauth-login>`

Passwordless QR sign-in. Mobile-aware: on coarse-pointer devices the pending state renders a "Continue with QRAuth" CTA instead of the full QR.

```html
<qrauth-login tenant="qrauth_app_xxx"></qrauth-login>
```

### Attributes

| Attribute | Type | Default | Description |
|---|---|---|---|
| `tenant` | string | — | **Required.** App client ID (`qrauth_app_…`). Find it in the QRAuth dashboard under **Apps → Client ID**. |
| `theme` | `light` \| `dark` | `light` | Colour palette. |
| `base-url` | URL | `https://qrauth.io` | API host. Set to your own backend if you proxy `/api/v1/auth-sessions*` (required for cross-origin browsers — see [CORS reality](/guide/web-components#cors-reality) in the guide). |
| `scopes` | string | `identity` | Space-separated scopes. Must be a subset of the app's `allowedScopes`. |
| `display` | `button` \| `inline` | `button` | `button` opens a modal; `inline` mounts the flow inside the host element. |
| `animated` | boolean | off | Enables a subtle pulse animation on the QR frame. |
| `redirect-uri` | URL | — | Where the hosted approval page sends the user after **Approve**. Required for the mobile flow to feel complete; without it, the new tab dead-ends on a "you can close this page" message. Must match the app's registered `redirectUrls` (set via dashboard or `PATCH /apps/:id`). |
| `force-mode` | `mobile` \| `desktop` \| `auto` | `auto` | Override the automatic coarse-pointer detection. Useful for screenshots and demos. |
| `mobile-fallback-only` | boolean | off | Disable the mobile-aware UI entirely; keep the QR-first body on every device. Use when your page already provides an alternative same-device login path. |
| `redirect-url` | URL | — | (Legacy) Navigate the **original** tab here on `APPROVED`. Distinct from `redirect-uri` — that one drives the **new** tab on the hosted page. |
| `on-auth` | string | — | Name of a global function to invoke on success, in addition to the `qrauth:authenticated` event. |

### Events

All events bubble across the Shadow DOM (`composed: true`).

| Event | `detail` | When |
|---|---|---|
| `qrauth:authenticated` | `{ sessionId, user, signature }` | User completed Approve. `signature` is a server-issued ECDSA signature; **verify it server-side** before trusting the session. |
| `qrauth:scanned` | `{ sessionId, status, … }` | QR was scanned (PENDING → SCANNED transition). |
| `qrauth:denied` | — | User declined on their device. |
| `qrauth:expired` | — | Session timed out before approval. |
| `qrauth:error` | `{ message }` | Network or server-side error during session create / poll. |

### Minimal example

```html
<qrauth-login tenant="qrauth_app_xxx"></qrauth-login>

<script>
  document.querySelector('qrauth-login')
    .addEventListener('qrauth:authenticated', async (e) => {
      const { sessionId, signature } = e.detail;
      // Verify server-side, exchange for your own session token.
      await fetch('/api/auth/qrauth-callback', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sessionId, signature }),
      });
      window.location.href = '/dashboard';
    });
</script>
```

---

## `<qrauth-2fa>`

Drop-in second-factor verification. Same session model as `<qrauth-login>` — the user approves on a trusted device, the component fires `qrauth:verified`.

```html
<qrauth-2fa
  tenant="qrauth_app_xxx"
  session-token="<your-app-jwt>"
  auto-start
></qrauth-2fa>
```

### Attributes

| Attribute | Type | Default | Description |
|---|---|---|---|
| `tenant` | string | — | **Required.** App client ID. |
| `theme` | `light` \| `dark` | `light` | Colour palette. |
| `base-url` | URL | `https://qrauth.io` | API host. |
| `session-token` | string | — | Your app's primary-auth JWT, forwarded to QRAuth so the 2FA challenge is bound to that session. |
| `scopes` | string | `identity` | Scopes requested from the approving device. |
| `auto-start` | boolean | off | Begin the challenge immediately on mount; otherwise a "Verify your identity" button is shown. |
| `redirect-uri` | URL | — | Same semantics as `<qrauth-login>`. Critical for the mobile flow. |
| `force-mode` | `mobile` \| `desktop` \| `auto` | `auto` | Override automatic mobile detection. |
| `mobile-fallback-only` | boolean | off | Disable the mobile-aware UI. |

### Events

| Event | `detail` | When |
|---|---|---|
| `qrauth:verified` | `{ sessionId, user, signature }` | Step-up verification approved. |
| `qrauth:denied` | — | Verification denied on the device. |
| `qrauth:expired` | — | Challenge timed out. |
| `qrauth:error` | `{ message }` | Network or server error. |

::: warning Always verify server-side
The `signature` in `qrauth:verified` is a server-issued ECDSA signature. Send it to your backend and call `POST /api/v1/auth-sessions/verify-result` (or the equivalent SDK method) before trusting the user's device for the high-value action.
:::

---

## `<qrauth-ephemeral>`

Generates a time-limited access QR with a live TTL countdown. The component creates the ephemeral session itself — you don't pre-create it server-side.

```html
<qrauth-ephemeral
  tenant="qrauth_app_xxx"
  scopes="open:room-247"
  ttl="12h"
  device-binding
></qrauth-ephemeral>
```

### Attributes

| Attribute | Type | Default | Description |
|---|---|---|---|
| `tenant` | string | — | **Required.** App client ID. |
| `theme` | `light` \| `dark` | `light` | Colour palette. |
| `base-url` | URL | `https://qrauth.io` | API host. |
| `scopes` | string | `access` | Space-separated scopes the claimer receives. |
| `ttl` | duration | `30m` | Session lifetime. Format: `30s`, `5m`, `6h`, `7d`. |
| `max-uses` | integer | `1` | Maximum claims. A `n / max` badge is shown when `> 1`. |
| `device-binding` | boolean | off | Pin the session to the first device that claims it; subsequent claims from other devices are rejected. |
| `display` | `inline` \| `button` | `inline` | `inline` mounts the QR directly; `button` shows a "Get Access QR" trigger. |
| `force-mode` | `mobile` \| `desktop` \| `auto` | `auto` | Reserved for future mobile-variant UI. **No-op in 0.4.0** — the ephemeral flow is "generate QR for another device to scan", which is correct on any viewport. |
| `mobile-fallback-only` | boolean | off | Reserved for forward compatibility. No-op in 0.4.0. |

### Events

| Event | `detail` | When |
|---|---|---|
| `qrauth:claimed` | `{ sessionId, status, scopes, metadata, useCount, maxUses }` | A device claimed the session. `useCount` reflects post-claim count. |
| `qrauth:expired` | — | TTL elapsed before all uses claimed. |
| `qrauth:revoked` | — | Session revoked server-side (via dashboard or API). |
| `qrauth:error` | `{ message }` | Network or server error. |

---

## Theming

All three components expose CSS custom properties on the host element. Override on the element itself or on the document root.

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

A bundled dark palette is available via the `theme` attribute:

```html
<qrauth-login tenant="qrauth_app_xxx" theme="dark"></qrauth-login>
```

---

## Framework integration

The components are framework-free Custom Elements v1. They work in React, Vue, Angular, Svelte, and plain HTML.

::: code-group

```tsx [React 19 / Next.js 15]
'use client';
import '@qrauth/web-components';
import { useEffect, useRef } from 'react';

export function LoginButton() {
  const ref = useRef<HTMLElement>(null);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const onAuth = (e: Event) => {
      const { sessionId, signature } = (e as CustomEvent).detail;
      // exchange server-side, then redirect
    };
    el.addEventListener('qrauth:authenticated', onAuth);
    return () => el.removeEventListener('qrauth:authenticated', onAuth);
  }, []);

  return (
    <qrauth-login
      ref={ref as React.Ref<HTMLElement>}
      tenant="qrauth_app_xxx"
      redirect-uri="https://yourapp.com/dashboard/"
    />
  );
}
```

```vue [Vue 3]
<script setup lang="ts">
import '@qrauth/web-components';

function onAuth(e: CustomEvent) {
  const { sessionId, signature } = e.detail;
  // exchange server-side, then route
}
</script>

<template>
  <qrauth-login
    tenant="qrauth_app_xxx"
    redirect-uri="https://yourapp.com/dashboard/"
    @qrauth:authenticated="onAuth"
  />
</template>
```

```html [Vanilla / static HTML]
<qrauth-login tenant="qrauth_app_xxx"></qrauth-login>
<script type="module">
  import 'https://cdn.qrauth.io/v1/components-0.4.0.esm.js';
  document.querySelector('qrauth-login')
    .addEventListener('qrauth:authenticated', (e) => { /* … */ });
</script>
```

:::

For React, the JSX `<qrauth-login>` element needs an `IntrinsicElements` declaration. The exact pattern (which differs between React 18 and React 19's new JSX runtime) is documented in the [Web Components guide → React integration](/guide/web-components#react-integration).

---

## Versioning and changelog

Pin a major.minor in production. The package follows semver — minor bumps add attributes and event detail fields without breaking existing usage; major bumps remove or rename. Current changelog ships in the npm tarball as `CHANGELOG.md` and is mirrored in the [web-components README](https://github.com/qrauth-io/qrauth/blob/main/packages/web-components/CHANGELOG.md).
