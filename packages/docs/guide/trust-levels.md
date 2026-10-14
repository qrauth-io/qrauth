# Trust Levels

QRAuth surfaces trust at three layers: the **organization** (who owns the QR code), the **QR code** (what happened when it was scanned), and the **verification result** (the combined signal presented to the end user).

---

## Organization trust levels

Every organization registered on QRAuth has a `trustLevel` that reflects the entity type. It is set at onboarding and changes only when the organization submits a KYC upgrade request.

| Level | Badge | Who qualifies |
|---|---|---|
| `GOVERNMENT` | Blue shield | Government agencies, municipalities |
| `BUSINESS` | Green shield | Registered companies with KYC verification |
| `INDIVIDUAL` | Gray shield | Personal accounts (no entity verification) |

The trust level is visible on the verification page below the organization name and is included in the `VerificationResult` response from the SDK.

```ts
const result = await qrauth.verify('AbCdEfGh');

result.organization.trustLevel;   // 'GOVERNMENT' | 'BUSINESS' | 'INDIVIDUAL'
result.organization.kycStatus;    // 'VERIFIED' | 'UNDER_REVIEW' | 'UNVERIFIED'
result.organization.domainVerified; // boolean
```

---

## KYC verification status

| Status | Meaning |
|---|---|
| `VERIFIED` | Documents reviewed and approved |
| `UNDER_REVIEW` | Submission received, pending review (typically 1–3 business days) |
| `UNVERIFIED` | No KYC submission on file |

::: tip What KYC unlocks
Verified organizations unlock higher rate limits, the `BUSINESS` trust badge, and domain verification eligibility. Government-tier requires a separate manual review process.
:::

---

## QR code trust score

The trust score is a number from **0 to 100** computed in real-time at scan time. It starts at 100 and points are deducted by each active fraud signal.

| Signal | Deduction | Condition |
|---|---|---|
| Duplicate location | −30 | Another org's QR registered within 20m |
| Proxy detected | −25 | Scan IP matches known proxy/VPN/Tor exit |
| Geo-impossibility | −40 | Device scanned from >500km away in <30min |
| Velocity spike | −20 | Same IP scanned > N times in 1 minute |
| Bot signature | −35 | User-Agent or behavior matches bot profile |
| Device clustering | −15 | Multiple distinct fingerprints from one IP |

Dynamic rules (created by the AI agent or manually via the dashboard) can add further deductions. See [Fraud Detection](./fraud-detection).

### Score interpretation

| Range | Color | Label |
|---|---|---|
| 80–100 | Green | Trusted |
| 50–79 | Amber | Caution |
| 0–49 | Red | Suspicious |

Scores below 50 trigger the failure reveal flow (see [Trust Reveal](./trust-reveal)).

---

## Domain verification effect

When an organization has verified domain ownership, the verification page displays a green "domain verified" indicator next to the destination URL. More importantly:

- Domain-verified orgs receive a +10 trust score bonus (counteracting minor signals).
- The phishing similarity check compares the destination URL against the verified domain. If the QR points to a look-alike domain (`qraüth.io`, `qrauth-io.com`) the verification page shows a prominent phishing warning regardless of trust score.

```ts
result.domain_warning; // present when look-alike detected
// {
//   message: 'This URL resembles qrauth.io, owned by QRAuth Inc.',
//   similarDomain: 'qrauth-io.com',
//   verifiedOrg: 'QRAuth Inc.',
// }
```

See [Domain Verification](./domain-verification) for setup instructions.

---

## Reading trust in the API response

```ts
import { QRAuth } from '@qrauth/node';

const qrauth = new QRAuth({ apiKey: process.env.QRAUTH_API_KEY! });
const result  = await qrauth.verify('AbCdEfGh', {
  clientLat: 37.9838,
  clientLng: 23.7275,
});

const {
  verified,           // boolean — signature valid + no hard failures
  organization,       // { name, trustLevel, kycStatus, domainVerified }
  security,           // { trustScore, signatureValid, proxyDetected, transparencyLogVerified }
  location_match,     // { matched, distanceM, registeredAddress }
  domain_warning,     // present when phishing risk detected
} = result;

if (security.trustScore < 50) {
  alert('Warning: this QR code shows signs of tampering.');
}
```

---

## Trust level in the verification page

The verification page at `https://qrauth.io/v/:token` maps trust to three distinct visual experiences:

1. **Score ≥ 80** — Green trust reveal, full organization details shown.
2. **Score 50–79** — Amber reveal, caution banner, details shown with warning.
3. **Score < 50** — Red failure flow, `FRAUDULENT CODE DETECTED` overlay, destination URL suppressed.

See [Trust Reveal UX](./trust-reveal) for the full animation description.
