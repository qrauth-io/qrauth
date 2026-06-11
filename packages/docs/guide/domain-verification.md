# Domain Verification

Domain verification proves that your organization owns the domain referenced in your QR codes. Verified domains unlock a green badge on the verification page, higher trust scores, and phishing similarity alerts that protect your brand.

---

## Why verify a domain

- **Trust badge** — the verification page shows a "domain verified" indicator beside the destination URL.
- **Score bonus** — +10 to the trust score on every scan of a QR pointing to your domain.
- **Phishing alerts** — QRAuth monitors for look-alike domains (`mybank-io.com`, `mybaŋk.com`) and warns users when a QR points to one, even if the malicious QR was created by a different account.
- **Domain similarity detection** — when you _create_ a QR pointing to a domain that resembles a different verified domain, the API returns `domain_warnings` in the response so you can catch accidental typos before deployment.

---

## Verification methods

### Method 1: DNS TXT record (recommended)

Add a TXT record to your domain's DNS:

```
_qrauth-verification.yourdomain.com  TXT  "qrauth-verify=<token>"
```

1. Go to **Settings → Domains → Add Domain**.
2. Copy the verification token shown in the dashboard.
3. Create the TXT record with your DNS provider.
4. Click **Verify** — DNS propagation can take up to 48 hours but usually completes in minutes.

::: tip Wildcard domains
Verifying `yourdomain.com` automatically covers all subdomains (`app.yourdomain.com`, `api.yourdomain.com`). You do not need a separate record per subdomain.
:::

### Method 2: Verification file

Serve a JSON file at a well-known URL:

```
https://yourdomain.com/.well-known/qrauth-verification.json
```

File contents:

```json
{
  "verification": "<token>",
  "organization": "your-org-slug"
}
```

The file must be served with `Content-Type: application/json` and accessible from the public internet. `HTTPS` is required.

---

## Domain similarity detection

When you create a QR code via the API or dashboard, QRAuth checks the destination URL against all verified domains across the platform. If the destination closely resembles a verified domain — by edit distance, homoglyph substitution, or subdomain manipulation — the API returns a `domain_warnings` array.

```ts
import { QRAuth } from '@qrauth/node';

const qrauth = new QRAuth({ apiKey: process.env.QRAUTH_API_KEY! });

const code = await qrauth.create({
  destination: 'https://qrauth-io.com/login',  // typosquat of qrauth.io
});

code.domain_warnings;
// [
//   {
//     similar_to: 'qrauth.io',
//     verified_org: 'QRAuth Inc.',
//     similarity: 0.91,
//     reason: 'hyphen-insertion'
//   }
// ]
```

::: warning
`domain_warnings` is advisory — the QR code is still created. If you receive warnings on codes you are intentionally creating (e.g., staging environments at `staging.yourapp.com` after verifying `yourapp.com`), you can dismiss them in the dashboard.
:::

### Similarity algorithms

| Technique | Example |
|---|---|
| Levenshtein distance | `qraüth.io` vs `qrauth.io` |
| Homoglyph substitution | `paypaI.com` (capital I) vs `paypal.com` |
| Hyphen insertion/removal | `qrauth-io.com` vs `qrauth.io` |
| Subdomain confusion | `qrauth.io.evil.com` — the TLD is `evil.com`, not `qrauth.io` |
| TLD swap | `qrauth.com` vs `qrauth.io` |

---

## Phishing warnings on the verification page

When a user scans a QR whose destination URL resembles a verified domain, the verification page shows a red alert banner:

> **Phishing Risk Detected**
> This QR code points to `qrauth-io.com`, which closely resembles `qrauth.io` — a verified domain owned by QRAuth Inc. Do not proceed unless you are certain this is legitimate.

The alert appears **even if the QR code has a valid signature** because the QR may have been legitimately signed by a bad actor using their own (unverified) account.

The trust score also drops by −40 when a domain warning is active, typically pushing the score below 50 and triggering the failure reveal flow.

---

## Verification status in the API

```ts
const result = await qrauth.verify('AbCdEfGh');

result.organization.domainVerified; // true | false

result.domain_warning;
// present when look-alike detected:
// {
//   message: string,
//   similarDomain: string,
//   verifiedOrg: string,
// }
```

---

## Managing domains

```
GET    /api/v1/domains           — list verified domains
POST   /api/v1/domains           — add a domain
GET    /api/v1/domains/:id/check — re-check verification status
DELETE /api/v1/domains/:id       — remove a domain
```

::: code-group

```ts [Node.js]
// Add a domain via REST (SDK wrapper coming soon)
const res = await fetch('https://qrauth.io/api/v1/domains', {
  method: 'POST',
  headers: {
    Authorization: `Bearer ${apiKey}`,
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({ domain: 'yourcompany.com' }),
});

const { verificationToken, method } = await res.json();
// Add the TXT record, then call /check
```

```python [Python]
import httpx

resp = httpx.post(
    "https://qrauth.io/api/v1/domains",
    headers={"Authorization": f"Bearer {api_key}"},
    json={"domain": "yourcompany.com"},
)
data = resp.json()
verification_token = data["verificationToken"]
```

:::
