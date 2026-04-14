# Web Components

The `@qrauth/web-components` package ships three custom elements that drop into any HTML page with zero framework dependencies. Each component runs in a Shadow DOM, polls the QRAuth API over SSE/long-poll, and fires standard DOM events that bubble across shadow boundaries.

**Bundle size:** ~10 KB gzipped (IIFE). ~23 KB full with all components.

## Installation

::: code-group

```html [CDN (recommended)]
<!-- Paste before </body>. No npm, no build step. -->
<script src="https://cdn.qrauth.io/v1/components.js"></script>
```

```bash [npm]
npm install @qrauth/web-components
```

:::

::: code-group

```js [ESM import]
// After npm install
import '@qrauth/web-components';
```

:::

::: tip Get your tenant ID
Your **tenant** attribute maps to the App client ID (`qrauth_app_…`) from the QRAuth dashboard under **Apps → Client ID**.
:::

---

## `<qrauth-login>`

Drop-in QR authentication. Displays as a button that opens a modal, or as an always-visible inline widget.

### Attributes

| Attribute | Default | Description |
|---|---|---|
| `tenant` | — | App client ID (required) |
| `theme` | `light` | `light` or `dark` |
| `base-url` | `https://qrauth.io` | API base URL |
| `scopes` | `identity` | Space-separated OAuth scopes |
| `redirect-url` | — | Redirect here after approval |
| `on-auth` | — | Name of a global callback function |
| `display` | `button` | `button` (modal) or `inline` |
| `animated` | absent | Enables subtle QR pulse animation |

### Events

| Event | `detail` | When |
|---|---|---|
| `qrauth:authenticated` | `{ sessionId, user, signature }` | User approved the request |
| `qrauth:scanned` | — | QR was scanned (before approval) |
| `qrauth:expired` | — | Session timed out |
| `qrauth:denied` | — | User denied the request |
| `qrauth:error` | `{ message }` | Network or API error |

### Button mode (default)

```html
<qrauth-login tenant="qrauth_app_xxx"></qrauth-login>

<script>
  document.querySelector('qrauth-login').addEventListener('qrauth:authenticated', (e) => {
    const { user, signature } = e.detail;
    console.log('Logged in as', user.email);
    // Send signature to your backend for server-side verification
  });
</script>
```

### Inline mode

Renders the QR code immediately without a button click, useful for login pages.

```html
<qrauth-login
  tenant="qrauth_app_xxx"
  display="inline"
  theme="dark"
  scopes="identity email"
></qrauth-login>
```

### PKCE flow

For public clients (SPAs, static sites) use PKCE to prevent auth-code interception.

```html
<qrauth-login
  tenant="qrauth_app_xxx"
  redirect-url="https://yourapp.com/auth/callback"
></qrauth-login>
```

The component generates the code challenge automatically. Your callback page receives `?session_id=…&code=…` — exchange the code plus your locally-stored `code_verifier` for the user payload via your backend.

### Global callback

```html
<qrauth-login tenant="qrauth_app_xxx" on-auth="handleQRAuth"></qrauth-login>

<script>
  function handleQRAuth({ sessionId, user, signature }) {
    fetch('/api/session', {
      method: 'POST',
      body: JSON.stringify({ sessionId, signature }),
    });
  }
</script>
```

---

## `<qrauth-2fa>`

Second-factor challenge that appears inline during an existing session. Compact layout — fits in a sidebar or modal without extra wrapping.

### The "trojan horse" strategy

Deploy `<qrauth-2fa>` as a step-up challenge only when risk signals are elevated (new device, high-value action, unusual location). Users who already trust QR codes for login find the familiar UI reassuring. Users who don't can be silently downgraded to TOTP while you measure adoption.

### Attributes

| Attribute | Default | Description |
|---|---|---|
| `tenant` | — | App client ID (required) |
| `theme` | `light` | `light` or `dark` |
| `base-url` | `https://qrauth.io` | API base URL |
| `session-token` | — | Your app's current session JWT (forwarded to QRAuth for binding) |
| `scopes` | `verify` | Scopes requested from the approving device |
| `auto-start` | absent | Begin the challenge immediately on mount |

### Events

| Event | `detail` | When |
|---|---|---|
| `qrauth:verified` | `{ sessionId, signature }` | Challenge approved |
| `qrauth:denied` | — | Challenge rejected |
| `qrauth:expired` | — | QR timed out |
| `qrauth:error` | `{ message }` | Network or API error |

### Usage

```html
<!-- Embed inside your step-up auth modal -->
<qrauth-2fa
  tenant="qrauth_app_xxx"
  session-token="<your-current-jwt>"
  auto-start
></qrauth-2fa>

<script>
  document.querySelector('qrauth-2fa').addEventListener('qrauth:verified', (e) => {
    // Verify e.detail.signature server-side, then unlock the action
    unlockHighValueAction(e.detail.signature);
  });
</script>
```

::: warning Always verify server-side
The `signature` in the event detail is a server-generated ECDSA signature. Send it to your backend and call `POST /api/v1/auth-sessions/:sessionId/verify` before trusting it.
:::

---

## `<qrauth-ephemeral>`

Generates an ephemeral-access QR code with a live TTL countdown. When scanned, the server grants temporary scoped access without requiring an account.

### Attributes

| Attribute | Default | Description |
|---|---|---|
| `tenant` | — | App client ID (required) |
| `theme` | `light` | `light` or `dark` |
| `base-url` | `https://qrauth.io` | API base URL |
| `scopes` | `access` | Space-separated scopes |
| `ttl` | `30m` | Duration string: `30s`, `5m`, `6h`, `7d` |
| `max-uses` | `1` | Max number of claims (multi-use badge shown when > 1) |
| `device-binding` | absent | Lock to the first device that claims it |
| `display` | `inline` | `inline` or `button` |

### Events

| Event | `detail` | When |
|---|---|---|
| `qrauth:claimed` | `{ sessionId, scopes, metadata, useCount, maxUses }` | Session claimed |
| `qrauth:expired` | — | TTL elapsed |
| `qrauth:revoked` | — | Session revoked server-side |
| `qrauth:error` | `{ message }` | Network or API error |

### Single-use (hotel door)

```html
<qrauth-ephemeral
  tenant="qrauth_app_xxx"
  scopes="open:room-247"
  ttl="12h"
  device-binding
></qrauth-ephemeral>

<script>
  document.querySelector('qrauth-ephemeral').addEventListener('qrauth:claimed', (e) => {
    console.log('Room access granted, scopes:', e.detail.scopes);
  });
</script>
```

### Multi-use (event check-in)

```html
<qrauth-ephemeral
  tenant="qrauth_app_xxx"
  scopes="checkin:event-2026"
  ttl="8h"
  max-uses="50"
  display="inline"
></qrauth-ephemeral>
```

The component shows a live `0/50 claimed` badge that increments with each scan.

---

## CSS Theming

All components expose CSS custom properties that pierce the Shadow DOM via `::part` or the host element.

```css
qrauth-login,
qrauth-2fa,
qrauth-ephemeral {
  --qrauth-primary: #0066ff;
  --qrauth-bg: #ffffff;
  --qrauth-surface: #f5f5f5;
  --qrauth-border: #e0e0e0;
  --qrauth-text: #1a1a1a;
  --qrauth-text-muted: #6b7280;
  --qrauth-radius: 12px;
  --qrauth-shadow: 0 4px 24px rgba(0, 0, 0, 0.12);
}
```

### Built-in dark mode

```html
<qrauth-login tenant="qrauth_app_xxx" theme="dark"></qrauth-login>
```

### Match system preference

```js
const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
document.querySelector('qrauth-login')
  .setAttribute('theme', prefersDark ? 'dark' : 'light');
```

---

## Framework notes

The components are standard Custom Elements v1 and work in React, Vue, Angular, and Svelte without adapters. TypeScript types are bundled.

```tsx
// React — suppress unknown element warning
declare global {
  namespace JSX {
    interface IntrinsicElements {
      'qrauth-login': React.HTMLAttributes<HTMLElement> & {
        tenant: string;
        theme?: 'light' | 'dark';
        display?: 'button' | 'inline';
        animated?: boolean;
        scopes?: string;
        'redirect-url'?: string;
        'on-auth'?: string;
        'base-url'?: string;
      };
    }
  }
}
```
