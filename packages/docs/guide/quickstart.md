---
title: Quickstart
description: Get up and running with QRAuth in under 5 minutes.
---

# Quickstart

::: warning Legacy sign-in integration — frozen for new public integrations
The QR-based **AuthSession** "Sign in with QRAuth" flow shown in this
quickstart is **frozen for new public integrations**. For a new sign-in
integration, follow the [OIDC provider](/guide/oidc) instead — QRAuth's
certified, standards-based sign-in surface. Existing integrations keep working.
:::

Get up and running with QRAuth in under 5 minutes.

## 1. Create an account

Sign up at [qrauth.io](https://qrauth.io). After completing onboarding you will have an **Organization** and your first **API key**.

## 2. Generate an API key

In the dashboard go to **Settings → API Keys** and create a new key. Copy it — it is shown only once.

Store it as an environment variable:

```bash
export QRAUTH_API_KEY=qrauth_...
```

::: warning Keep your API key secret
Never commit API keys to source control. Use environment variables or a secrets manager.
:::

## 3. Install the SDK

::: code-group

```bash [npm]
npm install @qrauth/node
```

```bash [yarn]
yarn add @qrauth/node
```

:::

## 4. Create your first QR code

::: code-group

```typescript [Node.js]
import { QRAuth } from '@qrauth/node'

const qrauth = new QRAuth({ apiKey: process.env.QRAUTH_API_KEY })

const qr = await qrauth.create({
  label: 'Product A — Shelf 4B',
  destination: 'https://example.com/product-a',
})

console.log(qr.token)        // the QR's token
console.log(qr.qr_image_url) // PNG you can embed or print
```
:::

::: tip Content types
QRAuth supports `url`, `vcard`, `coupon`, `event`, `pdf`, and `feedback` out of the box. Every type encodes the signed `/v/:token` verification URL in the QR image; the content is shown on the verification page after the scan is verified. See the [API reference](/api/qrcodes) for schemas.
:::

## 5. Verify a QR code

When a device scans one of your codes, QRAuth returns a **verification response** with the signature result and a heuristic trust score (0-100). You can verify a token server-side:

::: code-group

```typescript [Node.js]
const result = await qrauth.verify(qr.token, {
  clientLat: 37.7749,    // optional — enables geo-fence matching
  clientLng: -122.4194,
})

switch (result.trust_state) {
  case 'VERIFIED':                  // authentic, issuer verified by QRAuth
    console.log('Issued by', result.organization.verified && result.organization.name)
    break
  case 'SIGNED_UNVERIFIED_ISSUER':  // authentic, issuer not verified
    console.log('Authentic code from an unverified issuer')
    break
  case 'UNTRUSTED':                 // do not trust
    console.warn('Not trusted:', result.reason)
    break
}
```
:::

## 6. Add "Sign in with QRAuth"

There are two ways to let users sign in with QRAuth. Start with OIDC unless you
have a specific reason not to.

### Standards-based OIDC (recommended)

QRAuth is an [OpenID Certified™ OpenID Provider](/guide/oidc). If your app (or
your auth stack) already speaks OpenID Connect, add "Sign in with QRAuth" with a
stock OIDC client library — point it at the issuer `https://id.qrauth.io`, enable
PKCE, and read the user's identity from the ID token and UserInfo endpoint. No
QRAuth SDK required.

See the [Sign in with QRAuth (OIDC)](/guide/oidc) guide for the issuer, scopes,
claims, and a minimal `openid-client` walkthrough.

### Web Components (QR scan-to-approve)

If you want a drop-in QR login widget without an OIDC stack, use the Web
Components flow. Drop a single SRI-pinned script tag and one custom element into
any page — no build step required:

```html
<!-- 1. Load the Web Components bundle. Pin a version + SRI hash for
        cache-safe, tamper-evident loads. Latest hashes:
        https://cdn.qrauth.io/v1/latest.json -->
<script
  src="https://cdn.qrauth.io/v1/components-0.4.1.js"
  integrity="sha384-ATDFr4BLBfhdPGPtaY17C3Sh0x5idUErmUbWUMQiPmbXJyd8cdG+OMeLpHKy0NwS"
  crossorigin="anonymous"
></script>

<!-- 2. Drop the element wherever the login UI should render. -->
<qrauth-login
  tenant="qrauth_app_xxx"
  base-url="https://yourapp.com"
  redirect-uri="https://yourapp.com/dashboard/"
></qrauth-login>
```

The component creates a session, displays the QR (or a "Continue with QRAuth" CTA on mobile), polls for approval, and fires a `qrauth:authenticated` event when the user approves. Exchange the signature server-side for your own session token:

::: code-group

```typescript [Browser]
document.querySelector('qrauth-login')
  .addEventListener('qrauth:authenticated', async (e) => {
    const { sessionId, signature } = e.detail;
    await fetch('/api/auth/qrauth-callback', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ sessionId, signature }),
    });
    window.location.href = '/dashboard';
  });
```

```typescript [Node.js (your /api/auth/qrauth-callback)]
import { QRAuth } from '@qrauth/node';

const qrauth = new QRAuth({
  clientId: process.env.QRAUTH_CLIENT_ID,
  clientSecret: process.env.QRAUTH_CLIENT_SECRET,
});

app.post('/api/auth/qrauth-callback', async (req, res) => {
  const { sessionId, signature } = req.body;
  const result = await qrauth.verifyAuthResult(sessionId, signature);
  if (!result.valid) return res.status(401).end();
  // result.session.user has the verified payload — issue your own JWT and return it
  const token = mintAppJWT(result.session.user);
  res.json({ token });
});
```

:::

::: tip Two more bits you'll need
- **`base-url`** points at your origin because your backend proxies `/api/v1/auth-sessions*` to qrauth.io with your app's credentials, which must not reach the browser. See [Web Components → CORS reality](/guide/web-components#cors-reality) for the proxy snippet.
- **`redirect-uri`** must match the app's registered `redirectUrls` in the QRAuth dashboard. Required for the mobile flow to feel complete.
:::

::: tip Next steps
- Add standards-based login with the [Sign in with QRAuth (OIDC)](/guide/oidc) guide.
- Read the full [Authentication guide](/guide/authentication) for PKCE, OAuth2, and multi-tenant setup.
- Explore [Web Components](/guide/web-components) for advanced customization and theming.
- Protect physical assets with [Ephemeral Access](/guide/ephemeral) — no account creation required for end users.
:::

## Production Deployment

The quickstart uses `ECDSA_SIGNER=local` and `SLH_DSA_SIGNER=local` by default — both signers run in-process on the API server. For production:

1. Deploy the signer service (`packages/signer-service/`) on a separate host with no public network access.
2. Set `ECDSA_SIGNER=http` and `SLH_DSA_SIGNER=http` on the API server, pointing to the signer's private network address.
3. Share the `SIGNER_MASTER_KEY` between both hosts.

See [Signing Infrastructure](/guide/security#signing-infrastructure) for the full architecture.
