# @qrauth/web-components

Drop-in Web Components for [QRAuth](https://qrauth.io) — passwordless QR authentication, 2FA, and ephemeral delegated access. Shadow DOM, framework-free, 20.8 KB gzipped (0.4.3).

<a href="https://openid.net/certification/certified-openid-providers-profiles/"><img src="https://qrauth.io/assets/certifications/openid-certified.png" alt="OpenID Certified" width="180" /></a>

QRAuth is an **OpenID Certified™** OpenID Provider (Basic OP + Config OP profiles).

- `<qrauth-login>` — passwordless sign-in, button or inline. Mobile-aware pending state (tap-to-continue CTA with QR demoted under a "Use another device" expander).
- `<qrauth-2fa>` — drop-in second-factor step with session-token binding.
- `<qrauth-ephemeral>` — time-limited access QRs, optionally bound to a device fingerprint.

All three components bubble `qrauth:*` events across the Shadow DOM boundary (`composed: true`) so any framework can listen with plain `addEventListener`.

## Install

```bash
npm install @qrauth/web-components
```

Or load the CDN IIFE directly in any HTML page (latest hashes at [`https://cdn.qrauth.io/v1/latest.json`](https://cdn.qrauth.io/v1/latest.json)):

```html
<script
  src="https://cdn.qrauth.io/v1/components-<version>.js"
  integrity="<sha384 for that file, from latest.json>"
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
| `redirect-url` | URL | — | Auto-redirect after success. Only an http(s) URL or a relative URL is followed; any other scheme is ignored with a console warning. |
| `on-auth` | string | — | Name of a function on `window`, called with the session result on success. It is looked up by name, so set it only from your own markup, never from user input. The `qrauth:authenticated` event carries the same data and needs no global. |
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

`qrauth:error` carries `detail.message`, which can be text from the API. Show
it with `textContent`, never `innerHTML`.

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

## Content Security Policy

The components style themselves inside their shadow root with inline
`<style>`. If the embedding page sends a Content-Security-Policy, `style-src`
must allow `'unsafe-inline'`. `connect-src` must allow the QRAuth API origin
(`https://qrauth.io` unless you set `base-url`).

## Framework integration

The components are framework-free native Custom Elements. They work in React, Vue, Svelte, Angular, plain HTML — wherever the browser exposes `customElements`. For React, wrap event listeners in `useEffect` because React's synthetic event system doesn't observe custom events directly.

## Links

- [Homepage](https://qrauth.io)
- [Docs](https://docs.qrauth.io)
- [Signing Architecture](https://docs.qrauth.io/guide/signing-architecture) — cryptographic model behind every approved session
- [Issues](https://github.com/qrauth-io/qrauth/issues)

## License

MIT.
