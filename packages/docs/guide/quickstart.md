---
title: Quickstart
description: Get up and running with QRAuth in under 5 minutes.
---

# Quickstart

Get up and running with QRAuth in under 5 minutes.

## 1. Create an account

Sign up at [qrauth.io](https://qrauth.io). After completing onboarding you will have an **Organization** and your first **API key**.

## 2. Generate an API key

In the dashboard go to **Settings → API Keys** and create a new key. Copy it — it is shown only once.

Store it as an environment variable:

```bash
export QRAUTH_API_KEY=sk_live_...
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

```bash [pip]
pip install qrauth
```

:::

## 4. Create your first QR code

::: code-group

```typescript [Node.js]
import QRAuth from '@qrauth/node'

const client = new QRAuth({ apiKey: process.env.QRAUTH_API_KEY })

const qr = await client.qrcodes.create({
  label: 'Product A — Shelf 4B',
  contentType: 'url',
  content: { url: 'https://example.com/product-a' },
})

console.log(qr.id)           // qr_01HXYZ...
console.log(qr.qr_image_url) // PNG you can embed or print
```

```python [Python]
import qrauth
import os

client = qrauth.QRAuth(api_key=os.environ["QRAUTH_API_KEY"])

qr = client.qrcodes.create(
    label="Product A — Shelf 4B",
    content_type="url",
    content={"url": "https://example.com/product-a"},
)

print(qr.id)           # qr_01HXYZ...
print(qr.qr_image_url) # PNG you can embed or print
```

:::

::: tip Content types
QRAuth supports `url`, `vcard`, `coupon`, `event`, `pdf`, and `feedback` out of the box. `url`, `coupon`, `pdf`, and `feedback` QRs route through the signed `/v/:token` verification URL at scan time; `vcard` and `event` QRs encode the raw vCard 3.0 / iCal VEVENT content directly so phones trigger native contact-import or add-to-calendar offline. See the [API reference](/api/qrcodes) and [Signing Architecture → Scope](/guide/signing-architecture#scope-which-codes-are-verified-at-scan-time) for schemas and the scan-time trust implications.
:::

## 5. Verify a QR code

When a device scans one of your codes, QRAuth returns a **verification response** including a cryptographic trust score and fraud signals. You can verify the response server-side:

::: code-group

```typescript [Node.js]
const result = await client.verify(qrId, {
  token: scanToken,      // from the scan callback
  location: {            // optional — enables proximity checks
    lat: 37.7749,
    lng: -122.4194,
  },
})

if (result.trusted) {
  // trust score >= threshold, no fraud signals
  console.log('Scan verified:', result.trustScore)
} else {
  console.warn('Suspicious scan:', result.signals)
}
```

```python [Python]
result = client.verify(
    qr_id,
    token=scan_token,
    location={"lat": 37.7749, "lng": -122.4194},
)

if result.trusted:
    print("Scan verified:", result.trust_score)
else:
    print("Suspicious scan:", result.signals)
```

:::

## 6. Add QR login to your website

Drop a single SRI-pinned script tag and one custom element into any page — no build step required:

```html
<!-- 1. Load the Web Components bundle. Pin a version + SRI hash for
        cache-safe, tamper-evident loads. Latest hashes:
        https://cdn.qrauth.io/v1/latest.json -->
<script
  src="https://cdn.qrauth.io/v1/components-0.4.0.js"
  integrity="sha384-ZsvnpXBK9tghmz/PCtZUtR+7qTF7XhR35/SGNfJuJgLOBxnIRi3JYhRt1oFxNtU6"
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

const qrauth = new QRAuth({ apiKey: process.env.QRAUTH_API_KEY });

app.post('/api/auth/qrauth-callback', async (req, res) => {
  const { sessionId, signature } = req.body;
  const result = await qrauth.verifyAuthResult(sessionId, signature);
  // result.user has the verified payload — issue your own JWT and return it
  const token = mintAppJWT(result.user);
  res.json({ token });
});
```

:::

::: tip Two more bits you'll need
- **`base-url`** points at your origin because qrauth.io's API is closed to cross-origin browsers — your backend proxies `/api/v1/auth-sessions*` to qrauth.io. See [Web Components → CORS reality](/guide/web-components#cors-reality) for the proxy snippet.
- **`redirect-uri`** must match the app's registered `redirectUrls` in the QRAuth dashboard. Required for the mobile flow to feel complete.
:::

::: tip Next steps
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
