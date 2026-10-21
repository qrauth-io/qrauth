# Domain Verification

Domain verification confirms, through a DNS TXT record, that your organization controls the domain set on your organization profile. A verified domain adds a "Domain Verified" badge to the verification page for your QR codes and is used by phishing similarity checks that protect your brand.

---

## Why verify a domain

- **Trust badge** — the verification page shows a "Domain Verified" badge on the issuer card for QR codes issued by your organization.
- **Phishing warnings** — when a QR code from another organization points to a destination that resembles your verified domain, the verification page shows a phishing warning and the trust score is lowered (see [below](#phishing-warnings-on-the-verification-page)).
- **Domain similarity detection** — when you _create_ a QR pointing to a domain that resembles a different organization's verified domain, the API returns `domain_warnings` in the response so you can catch accidental typos before deployment.

---

## Verification method: DNS TXT record

Add a TXT record on the domain itself (not on a subdomain):

```
yourdomain.com  TXT  "qrauth-verify=<token>"
```

1. Go to **Settings** and set your organization's **Domain**.
2. Generate the verification token and copy the TXT record shown.
3. Create the TXT record with your DNS provider.
4. Click **Verify** — DNS propagation can take up to 48 hours but usually completes in minutes.

---

## Domain similarity detection

When you create a QR code via the API or dashboard, QRAuth compares the destination host against other organizations' verified domains (and the destination domains of their active QR codes). If the destination closely resembles one, the API returns a `domain_warnings` array.

```ts
import { QRAuth } from '@qrauth/node';

const qrauth = new QRAuth({ apiKey: process.env.QRAUTH_API_KEY! });

const code = await qrauth.create({
  destination: 'https://qr-auth.io/login',  // look-alike of qrauth.io
});

code.domain_warnings;
// [
//   {
//     similar_to: 'qrauth.io',
//     verified_org: 'QRAuth Inc.',
//     similarity: 95,              // 0-100
//     reason: 'homoglyph_match'
//   }
// ]
```

::: warning
`domain_warnings` is advisory — the QR code is still created. If a match scores 80 or more, a `HIGH`-severity fraud incident is also recorded on the new QR code.
:::

### Similarity checks

The comparison ignores a leading `www.` and the top-level domain.

| Check (`reason`) | Score | Example |
|---|---|---|
| Same name after mapping look-alike characters (`0`/`o`, `1`/`l`/`i`, `rn`/`m`, `vv`/`w`, `cl`/`d`) and removing hyphens (`homoglyph_match`) | 95 | `paypa1.com` vs `paypal.com`, `qr-auth.io` vs `qrauth.io`, `qrauth.com` vs `qrauth.io` (TLD swap) |
| One-character difference (`one_char_difference`) | 90 | `qrauthx.io` vs `qrauth.io` |
| Edit distance of 2 (`typosquatting`) | 80 | `qrauht.io` vs `qrauth.io` |
| One name contains the other, length difference of 4 or less (`substring_match`) | 70 | `qrauth-pay.io` vs `qrauth.io` |
| Overall similarity of 80% or more (`high_similarity`) | 80-100 | — |

---

## Phishing warnings on the verification page

When a user scans a QR whose destination resembles another organization's verified domain with a similarity score of 80 or more, the verification page shows a phishing warning:

> **Phishing Warning:** This URL looks similar to "qrauth.io" which belongs to verified organization "QRAuth Inc.". Proceed with caution.

The warning appears **even if the QR code has a valid signature**, because the QR may have been legitimately signed by a bad actor using their own account.

The trust score also drops by 30 when this warning is shown. Verification fails only if the final score is 20 or below (see [Trust Levels](./trust-levels)).

---

## Verification status in the API

```ts
const result = await qrauth.verify('AbCdEfGh');

result.organization.domainVerified; // true | false

result.domain_warning;
// present when a look-alike scoring 80 or more is detected:
// {
//   message: string,
//   similar_to: string,
//   verified_org: string,
//   similarity: number,
// }
```

---

## Managing your domain

```
PATCH /api/v1/organizations/:id                         — set { "domain": "yourcompany.com" }
POST  /api/v1/organizations/:id/generate-verify-token    — get the TXT record value
POST  /api/v1/organizations/:id/verify-domain            — check the TXT record and mark the domain verified
```

The token and verify endpoints require the OWNER or ADMIN role.

::: code-group

```ts [Node.js]
const res = await fetch(`https://qrauth.io/api/v1/organizations/${orgId}/generate-verify-token`, {
  method: 'POST',
  headers: { Authorization: `Bearer ${token}` },
});

const { dnsRecord } = await res.json();
// dnsRecord: { type: 'TXT', name: 'yourcompany.com', value: 'qrauth-verify=<token>' }
// Add the TXT record, then POST /verify-domain → { verified: true } or { verified: false, error }
```

```python [Python]
import httpx

resp = httpx.post(
    f"https://qrauth.io/api/v1/organizations/{org_id}/generate-verify-token",
    headers={"Authorization": f"Bearer {token}"},
)
dns_record = resp.json()["dnsRecord"]
```

:::
