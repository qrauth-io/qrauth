# Domain Verification

Domain verification confirms, through a DNS TXT record, that your organization controls the domain set on your organization profile. A verified domain makes your organization a verified issuer, so valid scans of your codes are `VERIFIED` and name your organization. It also adds a "Domain Verified" badge to the verification page and is used by phishing similarity checks that protect your brand.

---

## Why verify a domain

- **Verified issuer** — valid scans of your codes are `trust_state: VERIFIED`: the verification page names your organization and shows your domain, and the JSON response includes `organization.name` and `organization.verified_domain`. Without a verified domain or approved KYC, scans are `SIGNED_UNVERIFIED_ISSUER` and your organization is not named. See [Issuer verification](./trust-levels#issuer-verification).
- **Trust badge** — the verification page shows a "Domain Verified" badge on the issuer card for QR codes issued by your organization.
- **Badge frame wording** — codes styled with the `badge` frame print "Verified by QRAuth" under the text; before verification they print "Signed with QRAuth". See [Frames](/api/qrcodes#frames).
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

## Domains that look like protected domains

A domain is checked for look-alikes when you set it and again when it would become verified. If it resembles a protected domain (another organization's verified domain or a protected brand, by the checks below), it is **held for review**: it stays unverified, and your organization is not a verified issuer through it, until a QRAuth administrator approves it. `POST /api/v1/organizations/:id/verify-domain` then answers:

```json
{ "verified": false, "pendingReview": true, "matches": [ … ], "error": "This domain resembles a protected domain, so a QRAuth administrator reviews it before it can be verified." }
```

An approved domain is verified (or can complete DNS verification if ownership was not yet proven). A rejected domain cannot be verified while it remains your organization's domain; setting a different domain starts over.

---

## Domain similarity detection

When you create a QR code via the API or dashboard, QRAuth compares the destination host, and every link of a smart link or link list code, against a set of protected domains:

- other organizations' verified domains and the destination domains of their active QR codes, and
- a list of protected brands maintained by QRAuth: Greek public services (`gov.gr`, `gsis.gr`, `aade.gr` …) and banks, payment providers and card schemes, the sign-in domains of Microsoft, Google and Apple, parcel carriers and other frequently imitated services.

If the destination closely resembles one, the API returns a `domain_warnings` array.

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
`domain_warnings` is advisory — the QR code is still created. If a match scores 80 or more, a `HIGH`-severity fraud incident is also recorded on the new QR code. The daily re-scan runs the same check on active codes and records an incident when a code has become a look-alike, for example of a newly protected brand.
:::

### Similarity checks

Before comparing, the host is converted from punycode to Unicode, normalised (NFKC, lowercase) and reduced to its Unicode *skeleton* ([UTS #39](https://www.unicode.org/reports/tr39/#Confusable_Detection)): characters that look alike map to the same prototype, so Cyrillic `а` and Latin `a`, Greek `ο` and Latin `o`, or `rn` and `m` compare equal. The comparison ignores a leading `www.`.

| Check (`reason`) | Score | Example |
|---|---|---|
| Same skeleton as a protected domain or one of its parent domains, or a protected brand's name spelled with look-alike characters or accents on any domain ending (`confusable`) | 100 | `раураl.com` (Cyrillic) vs `paypal.com`, `gοοgle.com` (Greek omicron) vs `google.com`, `g0v.gr` vs `gov.gr`, `äpple.com`, `paypa1.co.uk` |
| Letters of different scripts in one name, below UTS #39 "Highly Restrictive" (`mixed_script`) | 100 | `pаypal-help.com` (Latin with one Cyrillic `а`) |
| The exact name of a strict protected brand (banks, public services, payment and sign-in providers) on a domain ending the brand does not use (`brand_name`) | 90 | `aade.com`, `paypal.xyz` |
| Same name after mapping look-alike characters (`0`/`o`, `1`/`l`/`i`, `rn`/`m`, `vv`/`w`, `cl`/`d`) and removing hyphens (`homoglyph_match`) | 95 | `qr-auth.io` vs `qrauth.io`, `qrauth.com` vs `qrauth.io` (TLD swap of a verified organization's domain) |
| One-character difference (`one_char_difference`) | 90 | `qrauthx.io` vs `qrauth.io` |
| Edit distance of 2 (`typosquatting`) | 80 | `qrauht.io` vs `qrauth.io` |
| One name contains the other, length difference of 4 or less (`substring_match`) | 70 | `qrauth-pay.io` vs `qrauth.io` |
| Overall similarity of 80% or more (`high_similarity`) | 80-100 | — |

Not look-alikes:

- the protected domain itself and its subdomains (`login.microsoftonline.com`, `efka.gov.gr`), and your own verified domain;
- names written entirely in one script, such as Greek domains (`ουτοπία.δπθ.gr`), unless their skeleton matches a protected domain;
- for protected brands: the brand's other official domains, and, for brands that are not strict, its exact name on another domain ending (`google.com.hk`). Short brand names (under 6 characters) match only on an identical skeleton or the look-alike character map, so similar short names of different brands do not flag each other.

On shared hosting platforms where customers choose the subdomain (`*.sharepoint.com`, `*.github.io`, `*.blogspot.com` …), the subdomain counts as the name: `paypa1.sharepoint.com` is a look-alike of PayPal, `contoso.sharepoint.com` is not. The registered name of a host is found with the [Public Suffix List](https://publicsuffix.org).

---

## Phishing warnings on the verification page

When a user scans a QR whose destination is a look-alike scoring 80 or more, the verification page shows a phishing warning that says what the address looks like:

> **Phishing Warning:** This address looks like paypal.com (PayPal), but it is a different site. Proceed with caution.

For a look-alike of another organization's verified domain, the warning names the domain only (`This address looks like acme-bank.gr, but it is a different site.`).

For mixed scripts it names them:

> **Phishing Warning:** This address mixes Latin and Cyrillic letters in one name, a common way to imitate another site. Proceed with caution.

Internationalised host names are always shown in their punycode form (`xn--…`), never in the Unicode form that imitates another site.

The warning appears **even if the QR code has a valid signature**, because the QR may have been legitimately signed by a bad actor using their own account.

The trust score also drops by 30 when this warning is shown, and the result is `UNTRUSTED` (see [Trust state](/api/verification#trust-state)). A code with this warning never continues to its destination automatically.

---

## Verification status in the API

```ts
const result = await qrauth.verify('AbCdEfGh');

result.trust_state;                   // 'VERIFIED' when your organization is a verified issuer
result.organization;                  // { verified: true, name, verified_domain: 'yourcompany.com' }

result.domain_warning;
// present when a look-alike scoring 80 or more is detected:
// {
//   message: string,
//   similar_to: string,
//   verified_org: string,
//   similarity: number,
//   reason: string,     // 'confusable', 'mixed_script', 'typosquatting', ...
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
