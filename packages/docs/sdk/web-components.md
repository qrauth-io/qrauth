---
title: Web Components SDK
description: Drop-in custom elements for QR-based authentication — no build step required.
---

# Web Components SDK

The `@qrauth/web-components` package ships Shadow DOM custom elements that handle the full QR login flow. Drop one script tag into any HTML page and you are ready.

## Installation

### CDN (no build step)

```html
<script
  type="module"
  src="https://qrauth.io/sdk/v1/components.js"
></script>
```

### npm

::: code-group

```bash [npm]
npm install @qrauth/web-components
```

```bash [yarn]
yarn add @qrauth/web-components
```

:::

```typescript
import '@qrauth/web-components'
```

Importing the package registers all custom elements on `customElements`.

---

## Components

### `<qrauth-login>`

The primary authentication element. Renders a login button that opens a QR code modal when clicked. Handles session creation, polling, PKCE, and token exchange.

```html
<qrauth-login
  app-id="app_01HXYZ..."
  redirect-uri="https://yourapp.com/auth/callback"
></qrauth-login>
```

**Attributes:**

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `app-id` | string | Yes | Your QRAuth App ID |
| `redirect-uri` | string | Yes | OAuth2 redirect URI (must match app registration) |
| `scopes` | string | No | Space-separated scopes (default: `openid profile email`) |
| `label` | string | No | Button label text (default: `"Sign in with QRAuth"`) |
| `mode` | string | No | `"button"` (default) or `"inline"` — inline renders the QR directly |
| `theme` | string | No | `"light"` (default) or `"dark"` |

**Events:**

| Event | Detail | Description |
|-------|--------|-------------|
| `qrauth:success` | `{ code, state }` | Auth session approved — code ready to exchange |
| `qrauth:error` | `{ message }` | An error occurred |
| `qrauth:denied` | — | User denied the session on their device |
| `qrauth:expired` | — | Session expired without being scanned |

```javascript
document.querySelector('qrauth-login').addEventListener('qrauth:success', (e) => {
  const { code } = e.detail
  // exchange code on your server
  window.location.href = `/auth/callback?code=${code}`
})
```

**CSS custom properties:**

```css
qrauth-login {
  --qrauth-primary: #1976d2;
  --qrauth-radius: 8px;
  --qrauth-font-family: inherit;
}
```

---

### `<qrauth-2fa>`

Second-factor verification element. Use this when a user is already logged in and you need QR-based confirmation for a sensitive action.

```html
<qrauth-2fa
  app-id="app_01HXYZ..."
  action="delete-account"
></qrauth-2fa>
```

**Attributes:**

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `app-id` | string | Yes | Your QRAuth App ID |
| `action` | string | Yes | Action label shown to the user on their device |
| `user-token` | string | No | Bind the 2FA challenge to a specific authenticated user |

**Events:** Same as `<qrauth-login>` (`qrauth:success`, `qrauth:error`, `qrauth:denied`, `qrauth:expired`).

---

### `<qrauth-ephemeral>`

Renders a QR code for an ephemeral session and emits an event when it is claimed.

```html
<qrauth-ephemeral
  session-id="es_01HXYZ..."
></qrauth-ephemeral>
```

**Attributes:**

| Attribute | Type | Required | Description |
|-----------|------|----------|-------------|
| `session-id` | string | Yes | Ephemeral session ID (create server-side first) |
| `poll-interval` | number | No | Polling interval in milliseconds (default: 2000) |

**Events:**

| Event | Detail | Description |
|-------|--------|-------------|
| `qrauth:claimed` | `{ jwt, scopes }` | Session was claimed — JWT ready |
| `qrauth:expired` | — | Session expired |
| `qrauth:error` | `{ message }` | An error occurred |

```javascript
document.querySelector('qrauth-ephemeral').addEventListener('qrauth:claimed', (e) => {
  const { jwt } = e.detail
  // forward JWT to your backend for resource access
})
```

---

## Framework Integration

The custom elements work in any framework without adapters.

::: code-group

```tsx [React]
import '@qrauth/web-components'
import { useEffect, useRef } from 'react'

export function LoginButton() {
  const ref = useRef<HTMLElement>(null)

  useEffect(() => {
    const el = ref.current
    const handler = (e: Event) => {
      const { code } = (e as CustomEvent).detail
      window.location.href = `/auth/callback?code=${code}`
    }
    el?.addEventListener('qrauth:success', handler)
    return () => el?.removeEventListener('qrauth:success', handler)
  }, [])

  return (
    <qrauth-login
      ref={ref}
      app-id="app_01HXYZ..."
      redirect-uri="https://yourapp.com/auth/callback"
    />
  )
}
```

```vue [Vue]
<script setup lang="ts">
import '@qrauth/web-components'

function onSuccess(e: CustomEvent) {
  window.location.href = `/auth/callback?code=${e.detail.code}`
}
</script>

<template>
  <qrauth-login
    app-id="app_01HXYZ..."
    redirect-uri="https://yourapp.com/auth/callback"
    @qrauth:success="onSuccess"
  />
</template>
```

:::

::: tip Detailed usage
See the [Web Components guide](/guide/web-components) for PKCE setup, theming, dark mode, and the full attribute reference.
:::
