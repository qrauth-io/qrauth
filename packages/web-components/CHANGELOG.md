# @qrauth/web-components

## [0.4.1] — 2026-04-29

### Fixed
- Removed dependency on `api.qrserver.com` for QR rendering. QR codes are now rendered locally as inline SVG via the `qrcode` library. Required for WP.org plugin directory submission and for any consumer with strict CSP.
- QR quiet zone increased from 1 to 4 modules per ISO/IEC 18004 — restores the scan reliability of the previous external renderer on stricter readers (iPhone Camera, older Android, low-light captures).
- Capacity overflow in `qrToSvg()` no longer crashes the component render — `QRCode.create` is now wrapped in try/catch and returns an empty SVG on overflow, letting the calling state render its empty-qr fallback.

### Changed
- New runtime dependency: `qrcode@1.5.4` (already pinned by `@qrauth/animated-qr`).
- **`<qrauth-login>` and `<qrauth-2fa>` mobile "Continue with QRAuth" CTA** now appends `?dr=1` to the hosted approval URL. Forward-compatible with an upcoming server-side change at `qrauth.io/a/:token` that will gate the post-approval redirect on this flag — same-device clicks redirect, cross-device scans land on a terminal "Approved, you can close this tab" state. No behavior change until the server gating ships; safe to deploy independently.

## 0.4.0

- **`<qrauth-login>` and `<qrauth-2fa>`: new `redirect-uri` attribute.** After the user taps Approve on the mobile CTA path, the QRAuth hosted approval page now navigates back to the consumer site instead of landing on a "you can close this page" dead end. The attribute is forwarded to `POST /api/v1/auth-sessions` as `redirectUrl` and validated server-side against the app's registered `redirectUrls` allowlist (same security model as OAuth 2.0 redirect URIs — strips trailing slash and ignores query + fragment before comparison). No-op on the desktop QR flow since polling in the original tab already handles the transition.
- **Backend requirement:** running against QRAuth API ≥ 2026-04-19 (the server-side allowlist check ships in the same release train).

## 0.3.0

- `<qrauth-2fa>`: mobile-aware pending state. Primary CTA opens the hosted approval page (`/a/:token`) in a new tab; QR demoted to a "Use another device" expander. Polling in the original tab continues to fire `qrauth:verified` on approval. Adds `force-mode` and `mobile-fallback-only` attributes.
- `<qrauth-ephemeral>`: adds `force-mode` and `mobile-fallback-only` attributes for forward compatibility. No default mobile UI change — the ephemeral flow is a QR meant to be scanned by another device, so QR-first remains correct on all viewports.

## 0.2.0 — 2026-04-18

### Minor

- **`<qrauth-login>` — mobile-aware pending state.** Mobile-aware pending state: primary CTA opens the hosted approval page (`/a/:token`) in a new tab. QR demoted to a "Use another device" expander. Polling in the original tab continues to fire `qrauth:authenticated` on approval.
- **New attribute `force-mode="mobile" | "desktop" | "auto"`** — overrides the automatic detection. Useful for demos, screenshots, and host sites that know their audience's form factor.
- **New attribute `mobile-fallback-only`** — when present, disables the mobile-aware UI entirely and keeps the QR-first body on every device. Intended for host sites that already provide a same-device login path around the component; the QRAuth modal is then purely the cross-device scan option.
- **Shared `isMobileLike()` detector on `QRAuthElement`** — base-class helper so `<qrauth-2fa>` and `<qrauth-ephemeral>` can adopt the same branch without refactor when they grow analogous mobile-aware modes.
- **`MOBILE_MEDIA_QUERY` export** — `'(pointer: coarse) and (hover: none)'`, for documentation and test mocks.

### Internal

- Added `vitest` + `happy-dom` test harness (`npm test` runs the new `tests/login.mobile.test.ts`).
- Added Playwright spec `packages/e2e/tests/qrauth-login-mobile.spec.ts` under an iPhone 13 viewport (chromium-emulated).
- Bundle size: 10.4 KB gzipped IIFE / 10.2 KB gzipped ESM (target was <12 KB).

### Non-breaking

- Event surface (`qrauth:authenticated`, `qrauth:scanned`, `qrauth:expired`, `qrauth:denied`, `qrauth:error`) unchanged.
- Desktop pending body markup unchanged.
- Polling / SSE path unchanged — APPROVED transitions still fire `qrauth:authenticated` regardless of whether approval completed on the hosted page or via a scanned QR.

## 0.1.0

- Initial release: `<qrauth-login>`, `<qrauth-2fa>`, `<qrauth-ephemeral>` Shadow DOM custom elements.
