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
result.organization.kycStatus;    // 'PENDING' | 'UNDER_REVIEW' | 'VERIFIED' | 'REJECTED'
result.organization.domainVerified; // boolean
```

---

## KYC verification status

| Status | Meaning |
|---|---|
| `PENDING` | No KYC review completed (default for new organizations) |
| `UNDER_REVIEW` | Submission received, pending review (typically 1–3 business days) |
| `VERIFIED` | Documents reviewed and approved |
| `REJECTED` | Submission reviewed and not approved |

::: tip What KYC unlocks
Verified organizations unlock higher rate limits, the `BUSINESS` trust badge, and domain verification eligibility. Government-tier requires a separate manual review process.
:::

---

## QR code trust score

The trust score is a number from **0 to 100** computed at scan time from the QR code's fraud history:

1. Start at 100.
2. For each distinct type of unresolved fraud incident on the QR code, subtract once by severity: CRITICAL −30, HIGH −20, MEDIUM −10, LOW −5. Multiple incidents of the same type count once.
3. Scan velocity on this QR code in the last 5 minutes: more than 20 scans −10, otherwise more than 10 scans −5.
4. Clamp the result to the range 30–100.
5. If the destination domain is similar to a domain verified by another organization, subtract a further 30 (floor 0). See [Domain verification effect](#domain-verification-effect).

Fraud incidents are created by the background fraud worker after each scan, and at creation time for look-alike destinations:

| Signal | Incident type | Severity | Condition |
|---|---|---|---|
| Duplicate location | `DUPLICATE_LOCATION` | HIGH (−20) | Another organization's QR code is registered within 20 m |
| Geo-impossibility | `GEO_IMPOSSIBLE` | CRITICAL (−30) | The same hashed IP reported a location more than 500 km away within 30 minutes |
| Scan velocity | `PATTERN_ANOMALY` | MEDIUM | More than 50 scans of this QR code in 5 minutes |
| Bot user agent | `PATTERN_ANOMALY` | MEDIUM | The User-Agent matches a bot profile |
| Device clustering | `PATTERN_ANOMALY` | HIGH | The same hashed IP scanned 20 or more distinct QR codes in 1 hour |
| Look-alike destination | `MANUAL_REPORT` | HIGH (−20) | Raised when the code is created, if its destination resembles a domain verified by another organization |

Scan velocity, bot user agent and device clustering share the `PATTERN_ANOMALY` type, so together they deduct once. Dynamic rules (created by the AI agent or manually via the dashboard) can create further incidents. See [Fraud Detection](./fraud-detection).

A verification succeeds (`verified: true`) only when the signatures verify, the final trust score is above 20, and no geo-fence block applies. A score of 20 or below returns `verified: false` with a low-trust reason.

### Score interpretation

| Range | Color | Label |
|---|---|---|
| 80–100 | Green | Trusted |
| 50–79 | Amber | Caution |
| 0–49 | Red | Suspicious |

The color bands control how the score is displayed. The failure reveal is driven by `verified`, not by the color band (see [Trust Reveal](./trust-reveal)).

---

## Domain verification effect

When an organization has verified domain ownership, the verification page displays a green "domain verified" indicator next to the destination URL.

Verified domains also feed the phishing similarity check. At scan time we compare the QR code's destination URL against domains verified by other organizations. If it points to a look-alike domain (`qraüth.io`, `qrauth-io.com`), the response includes `domain_warning`, the verification page shows a phishing warning, and the trust score drops by 30.

```ts
result.domain_warning; // present when look-alike detected
// {
//   message: 'This URL looks similar to "qrauth.io" which belongs to verified organization "QRAuth Inc.". Proceed with caution.',
//   similar_to: 'qrauth.io',
//   verified_org: 'QRAuth Inc.',
//   similarity: 89,   // 0-100
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
  verified,           // boolean — signatures valid, trust score > 20, no geo-fence block
  organization,       // { id, name, slug, trustLevel, kycStatus, domainVerified }
  security,           // { trustScore, signatureValid, transparencyLogVerified, algVersion, ... }
  location_match,     // { matched, distanceM, registeredAddress }
  domain_warning,     // present when phishing risk detected
} = result;

if (security.trustScore < 50) {
  alert('Warning: this QR code shows signs of tampering.');
}
```

---

## Trust level in the verification page

The verification page at `https://qrauth.io/v/:token` maps the result to two visual experiences:

1. **Verified** — the trust reveal shows the "Verified" state; the trust score is shown in the color of its band (green ≥ 80, amber 50–79, red below 50).
2. **Not verified** (invalid signature or final trust score of 20 or below) — red failure reveal with "Fraudulent Code Detected — Do not proceed". For URL codes, the "Continue" button is replaced by "Do not proceed - this QR code is not verified".

Revoked, expired and scan-limited codes, and codes with an unsupported `alg_version`, show a simple failure page instead. Geo-fence blocks show a location prompt or a block page.

See [Trust Reveal UX](./trust-reveal) for the full animation description.
