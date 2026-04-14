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
QRAuth supports `url`, `vcard`, `coupon`, `event`, `pdf`, and `feedback` out of the box. See the [API reference](/api/qrcodes) for the full schema of each type.
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

Drop a single script tag and one HTML element into any page — no build step required:

```html
<!-- 1. Load the SDK once -->
<script
  type="module"
  src="https://cdn.qrauth.io/sdk/v1/qrauth.js"
></script>

<!-- 2. Place the login element wherever you want the button to appear -->
<qrauth-login
  app-id="app_01HXYZ..."
  redirect-uri="https://yourapp.com/auth/callback"
></qrauth-login>
```

After a successful scan the component fires a `qrauth:success` event and redirects to `redirect-uri` with an authorization code. Exchange the code for tokens on your server:

::: code-group

```typescript [Node.js]
app.get('/auth/callback', async (req, res) => {
  const { code } = req.query

  const tokens = await client.authSessions.exchange({
    code: code as string,
    redirectUri: 'https://yourapp.com/auth/callback',
  })

  // tokens.accessToken, tokens.idToken, tokens.expiresIn
  res.redirect('/dashboard')
})
```

```python [Python]
@app.route("/auth/callback")
def callback():
    code = request.args.get("code")

    tokens = client.auth_sessions.exchange(
        code=code,
        redirect_uri="https://yourapp.com/auth/callback",
    )

    # tokens.access_token, tokens.id_token, tokens.expires_in
    return redirect("/dashboard")
```

:::

::: tip Next steps
- Read the full [Authentication guide](/guide/authentication) for PKCE, OAuth2, and multi-tenant setup.
- Explore [Web Components](/guide/web-components) for advanced customization and theming.
- Protect physical assets with [Ephemeral Access](/guide/ephemeral) — no account creation required for end users.
:::
