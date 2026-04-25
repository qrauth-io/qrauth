# @qrauth/web-components

Drop-in Web Components for [QRAuth](https://qrauth.io) — passwordless QR authentication, 2FA, and ephemeral delegated access. Shadow DOM, framework-free, ~10 KB gzipped.

- `<qrauth-login>` — passwordless sign-in, button or inline. Mobile-aware pending state (tap-to-continue CTA with QR demoted under a "Use another device" expander).
- `<qrauth-2fa>` — drop-in second-factor step with session-token binding.
- `<qrauth-ephemeral>` — time-limited, device-bound access QRs.

All three components bubble `qrauth:*` events across the Shadow DOM boundary (`composed: true`) so any framework can listen with plain `addEventListener`.

## Install

```bash
npm install @qrauth/web-components
```

Or load the CDN IIFE directly in any HTML page (latest hashes at [`https://cdn.qrauth.io/v1/latest.json`](https://cdn.qrauth.io/v1/latest.json)):

```html
<script
  src="https://cdn.qrauth.io/v1/components-0.4.0.js"
  integrity="sha384-ZsvnpXBK9tghmz/PCtZUtR+7qTF7XhR35/SGNfJuJgLOBxnIRi3JYhRt1oFxNtU6"
  crossorigin="anonymous"
></script>

<qrauth-login tenant="your-app-id"></qrauth-login>
```

## Quickstart

```html
<qrauth-login
  tenant="qrauth_app_xxx"
  theme="light"
  base-url="https://qrauth.io"
></qrauth-login>

<script>
  document.querySelector('qrauth-login').addEventListener('qrauth:authenticated', (e) => {
    const { sessionId, user, signature } = e.detail;
    // Exchange sessionId + signature server-side for your own session.
  });
</script>
```

## Attributes (login)

| Attribute | Values | Default | Purpose |
|---|---|---|---|
| `tenant` | string | — | Your QRAuth App client ID. Required. |
| `theme` | `light` \| `dark` | `light` | Colour scheme. |
| `base-url` | URL | `https://qrauth.io` | API host. Override for staging / local dev. |
| `scopes` | space-separated | `identity` | OAuth-style scopes requested. |
| `redirect-url` | URL | — | Auto-redirect after success. |
| `on-auth` | string | — | Name of a global function to invoke on success. |
| `display` | `button` \| `inline` | `button` | Modal trigger vs. embedded widget. |
| `animated` | boolean | off | Enables the pulse animation on the QR. |
| `force-mode` | `mobile` \| `desktop` \| `auto` | `auto` | Override automatic mobile detection. |
| `mobile-fallback-only` | boolean | off | Keep the QR-first body on every device; disables the mobile CTA path. |
| `redirect-uri` | URL | — | Where the hosted approval page sends the user after Approve. Required for the mobile flow to feel complete. Must match the app's registered `redirectUrls` allowlist. See [docs.qrauth.io/guide/web-components](https://docs.qrauth.io/guide/web-components#the-mobile-flow) for the URL-callback handler your app needs. |

## Events

All events bubble across the Shadow DOM (`composed: true`):

- `qrauth:authenticated` — `detail: { sessionId, user, signature }`
- `qrauth:scanned` — fired on the PENDING → SCANNED transition (pre-approval)
- `qrauth:expired` — session timed out
- `qrauth:denied` — user denied approval on their device
- `qrauth:error` — `detail: { message }`

## Theming

Override any of the following CSS custom properties on the host page or on the element itself:

```css
qrauth-login {
  --qrauth-primary: #00a76f;
  --qrauth-text: #1a1a2e;
  --qrauth-bg: #ffffff;
  --qrauth-surface: #f9fafb;
  --qrauth-border: #e0e0e0;
  --qrauth-radius: 12px;
  --qrauth-btn-bg: #1b2a4a;
  --qrauth-btn-hover: #263b66;
  --qrauth-shadow: 0 24px 48px rgba(0, 0, 0, 0.15);
  --qrauth-font: 'Inter', sans-serif;
}
```

Or flip the bundled dark palette via `theme="dark"`.

## Framework integration

The components are framework-free native Custom Elements. They work in React, Vue, Svelte, Angular, plain HTML — wherever the browser exposes `customElements`. For React, wrap event listeners in `useEffect` because React's synthetic event system doesn't observe custom events directly.

## Links

- [Homepage](https://qrauth.io)
- [Docs](https://docs.qrauth.io)
- [Signing Architecture](https://docs.qrauth.io/guide/signing-architecture) — cryptographic model behind every approved session
- [Issues](https://github.com/qrauth-io/qrauth/issues)

## License

MIT.
