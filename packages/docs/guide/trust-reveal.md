# Trust Reveal UX

When a user scans a QRAuth-signed QR code, they land on the verification page at `https://qrauth.io/v/:token`. The page stages a 3-second animated reveal that communicates the result before showing any details. What it shows follows the response's [`trust_state`](/api/verification#trust-state).

The reveal is implemented entirely in CSS animations and vanilla JS. There is no external animation library.

---

## Page states

| State | When | What the scanner sees |
|---|---|---|
| **Verified** | `trust_state` `VERIFIED` | Green shield with a check mark, "Verified", "Issued by *organization*" and the issuer's verified domain. The issuer card shows the organization name with its "Identity Verified" and/or "Domain Verified" tags. URL codes show a green "Continue to *host*" button |
| **Signed, issuer not verified** | `trust_state` `SIGNED_UNVERIFIED_ISSUER` | Neutral (grey) shield without a check mark, "Authentic signed code" and "Issuer not verified by QRAuth". The issuer is not named anywhere on the page, in the title or in link previews. A notice says QRAuth has not verified who issued the code. URL codes show the destination host prominently ("You are about to visit *host*") above a neutral "Continue to *host*" button |
| **Untrusted** | `trust_state` `UNTRUSTED` with the full response | Red shield, "Not Verified" and "Fraudulent Code Detected — Do not proceed". A phishing warning appears when the destination resembles another organization's verified domain. URL codes show "Do not proceed - this QR code is not verified" instead of a Continue button. The issuer is named only if it is verified |
| **Disabled** | Issuer organization suspended | Failure page "QR Code Disabled" with "This code has been disabled." No destination, no issuer name |
| **Flagged as dangerous** | Destination flagged by screening | Failure page "Dangerous Site Blocked" with "This code points to a site flagged as dangerous." No destination, no issuer name |

Revoked, expired and scan-limited codes, and codes with an unsupported `alg_version`, show a failure page ("QR Code Revoked", "QR Code Expired", "Scan Limit Reached", "Verification Failed") without a destination; the issuer is named there only if it is verified. Geo-fence blocks show a location prompt or a block page.

Every state links to **Report this code** at the bottom of the page. The link opens a short form (reason, optional details, optional email) that sends the report to QRAuth; see [Report a code](/api/verification#report-a-code).

Users with `prefers-reduced-motion` get the final state without animation.

---

## Reveal sequence

```
1. Shield pop-in      (~400ms)
2. Color sweep        (~800ms)   green / neutral / red
3. Status and issuer  (~300ms)
4. Visual fingerprint (~500ms)
5. Fade to detail view
```

**1. Shield pop-in**
A shield icon scales in from 0 to 1 with a `cubic-bezier(0.175, 0.885, 0.32, 1.275)` spring.

**2. Color sweep**
The background tints in the state's color: the trust-score color for Verified (see [below](#trust-score-coloring-reference)), grey for Signed, issuer not verified, and an escalating red for Untrusted.

**3. Status and issuer**
The status text fades in below the shield: "Verified" with the organization name, "Authentic signed code" with "Issuer not verified by QRAuth", or "Not Verified" with the alarm text.

**4. Visual fingerprint**
A deterministic SVG of 7 geometric shapes on a 120×120 canvas appears below the status. It is derived from a per-scan keyed SHA-256 value, so the pattern differs on every scan. See [Visual fingerprint](#visual-fingerprint).

**5. Detail view**
The overlay fades out and the full verification detail appears: destination, location match, content, and the live proof block.

---

## Leaving the verify page

The verify page is served with `Referrer-Policy: no-referrer`. When a visitor continues to the destination, whether with the Continue button or automatically for codes set to redirect, the destination receives **no `Referer` header**, so traffic from QR scans does not show up as a referral from qrauth.io.

To attribute that traffic, put UTM parameters in the code's destination URL:

```
https://example.com/offer?utm_source=qrauth&utm_medium=qr&utm_campaign=spring-poster
```

---

## Visual fingerprint

The fingerprint SVG is generated server-side by `generateVisualFingerprint(seed)` in `packages/api/src/renderers/visual-fingerprint.ts`. The seed is a keyed SHA-256 value over a server-side secret, the token, the scan timestamp and the client IP, so every scan produces a different pattern. The same seed always produces the same SVG.

- 7 shapes on a 120×120 canvas.
- Each shape consumes 4 seed bytes: x position, y position, size, and a byte that selects color and shape type.
- Shape types: circle, rounded rectangle, triangle, diamond. Colors come from an 8-color palette.
- A subtle radial glow sits behind the shapes.

---

## Ephemeral proof

Every verification page shows an ephemeral proof block: a set of facts generated by the server for this specific scan.

| Field | Value | Source |
|---|---|---|
| Location | e.g. "Athens" | Resolved from the IP address the server saw |
| Device | e.g. "Safari on iOS" | Parsed from User-Agent at scan time |
| Time | e.g. "10 Apr 2026, 14:32" | Server-recorded; not client-supplied |
| Proof ID | 12 hex chars | Keyed SHA-256 over the token, timestamp and client IP; unique per scan, not in the QR payload |

::: info Origin integrity check
The verification page JavaScript checks `window.location.hostname` against `qrauth.io`. If it does not match, the page shows a phishing warning.
:::

---

## Trust score coloring reference

```ts
function trustColor(score: number): string {
  if (score >= 80) return '#00a76f'; // green
  if (score >= 50) return '#ffab00'; // amber
  return '#ff5630';                  // red
}
```

The same color is used for the trust score indicator and, on the Verified page, for the color sweep. The Signed, issuer not verified page uses grey for both.

---

## Mobile design

The reveal is designed for portrait mobile viewports (360px+):
- All animations use `transform` and `opacity` only (no layout-triggering properties).
- Font sizes use `clamp()` to scale between 360px and 768px.
- The shield SVG is `100px × 100px` on mobile, `140px × 140px` on desktop.
- Touch-to-dismiss collapses the reveal on small screens.
