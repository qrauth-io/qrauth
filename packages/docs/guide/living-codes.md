# Living Codes (Animated QR)

Living Codes encode a new URL into the QR matrix on every frame (the renderer default interval is 1000 ms; the examples below use 500 ms). Each frame URL carries a frame index, a millisecond timestamp, and a 16-hex-character tag: the first 8 bytes of HMAC-SHA-256 under a per-session frame secret. The frame-verify endpoint accepts a frame only within a short time window and only if its index is higher than any frame already accepted for that session (see [Server validation](#server-validation)).

**Package:** `@qrauth/animated-qr`

---

## Install

::: code-group

```bash [npm]
npm install @qrauth/animated-qr
```

```html [CDN (pinned, recommended)]
<!-- Pin a version + SRI hash; latest.json has the current values. -->
<!-- https://cdn.qrauth.io/v1/latest.json -->
<script
  src="https://cdn.qrauth.io/v1/animated-qr-0.1.0.js"
  integrity="sha384-SnNpFyNumJMmixn2wxp7xG2+yyoDAJUrm4vxnHJ1dcweHFXiceM0ITfryqgbr3eu"
  crossorigin="anonymous"
></script>
```

```html [CDN (rolling)]
<!-- Always latest. 60s edge TTL, no SRI. -->
<script src="https://cdn.qrauth.io/v1/animated-qr.js"></script>
```

:::

---

## Quick start

```ts
import { AnimatedQRRenderer } from '@qrauth/animated-qr';

// 1. Get a frame secret.
//
//    Confidential client (server side, Basic client_id:client_secret):
//    POST /api/v1/animated-qr/session returns { frameSecret, baseUrl, ttlSeconds }.
//
//    Browser (public client, X-Client-Id only): prove possession of a
//    per-display verifier. Create the verifier with Web Crypto, keep it in
//    memory, and send only its SHA-256 hash in the same request that creates
//    the auth session.
const base64url = (b: Uint8Array) =>
  btoa(String.fromCharCode(...b)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const verifier = base64url(crypto.getRandomValues(new Uint8Array(32)));
const frameChallenge = base64url(
  new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))),
);
const headers = { 'X-Client-Id': clientId, 'Content-Type': 'application/json' };
// codeChallenge: the PKCE S256 challenge public clients already send (see Authentication).

const { token } = await fetch('/api/v1/auth-sessions', {
  method: 'POST', headers,
  body: JSON.stringify({ scopes: ['identity'], codeChallenge, codeChallengeMethod: 'S256', frameChallenge }),
}).then(r => r.json());                               // frameChallenge is bound to the session here

await fetch('/api/v1/animated-qr/session', {
  method: 'POST', headers,
  body: JSON.stringify({ token }),                    // no secret in this response
});
const { frameSecret, baseUrl, ttlSeconds } = await fetch('/api/v1/animated-qr/session/secret', {
  method: 'POST', headers,
  body: JSON.stringify({ token, frameVerifier: verifier }),   // body only, never the URL
}).then(r => r.json());
// ttlSeconds is the lesser of the auth session's remaining life and 10 minutes.
// After a page reload, call /session/secret again with the same verifier: it
// issues a new frame secret and retires the previous one.

// 2. Mount the renderer on a canvas element
const canvas = document.getElementById('qr') as HTMLCanvasElement;

const renderer = new AnimatedQRRenderer({
  canvas,
  size: 400,
  baseUrl,              // e.g. https://qrauth.io/v/AbCdEfGh
  frameSecret,          // hex-encoded per-session HMAC secret
  frameInterval: 500,   // ms between QR matrix updates (default: 1000)
  theme: 'light',       // 'light' | 'dark'
});

await renderer.start();
```

---

## Architecture

### Frame signing (client)

Each frame the `FrameSigner` class:
1. Increments a monotonically increasing `frameIndex`.
2. Records the current `timestamp` (milliseconds).
3. Computes HMAC-SHA-256 over `baseUrl + ":" + timestamp + ":" + frameIndex` under the frame secret, using the Web Crypto API.
4. Truncates the HMAC to the first 16 hex characters (8 bytes) for compact QR encoding.
5. Builds the final URL: `https://qrauth.io/v/AbCdEfGh?f=42&t=1744281600123&h=a3f2c8d1e9b07f4c`

```ts
import { FrameSigner } from '@qrauth/animated-qr';

const signer = new FrameSigner({
  baseUrl: 'https://qrauth.io/v/AbCdEfGh',
  frameSecret: frameSecretHex,
});

await signer.init(); // imports the HMAC key via SubtleCrypto

const frame = await signer.generateFrame();
// { url, frameIndex, timestamp, hmac }
```

### Server validation

The frame secret is derived server-side (HKDF-SHA-256, 32 bytes) per auth session and per secret generation, and supplied to the rendering client:

- A confidential client receives it from `POST /session` with its client secret.
- A public (browser) client sends `frameChallenge = base64url(SHA-256(frameVerifier))` in the `POST /auth-sessions` request that creates the auth session, so the challenge is bound before the session token exists anywhere else. `POST /animated-qr/session` never registers a challenge for a public client. The secret comes from `POST /session/secret` only on presenting `frameVerifier` in the request body, with at most 10 attempts per auth session per minute. A verifier in the query string is refused.
- Every issuance (including a refetch after a reload) starts a new generation. Only the current generation verifies, so frames signed with an earlier secret are rejected.

 Frame checks run at the frame-verify endpoint; call it from your integration to validate a scanned frame. When it is called, the server:
1. Checks that `baseUrl` is on the QRAuth origin and resolves the auth session from its token.
2. Rejects frames older than 5 seconds or more than 2 seconds in the future.
3. Re-derives the frame secret of the session's current generation and recomputes the 16-hex-character tag over `baseUrl:timestamp:frameIndex`, comparing in constant time.
4. Keeps the highest accepted frame index per session and generation in Redis (10-minute TTL) and rejects any frame whose index is not strictly greater. If Redis is unavailable, the frame is rejected.

```
POST /api/v1/animated-qr/validate
{ baseUrl, frameIndex, timestamp, hmac }
→ 200 { valid: true }
→ 200 { valid: false, reason }   // e.g. 'Frame expired (older than 5 seconds)', 'Invalid HMAC', 'Replayed frame index'
→ 400 malformed input or foreign baseUrl origin
→ 404 unknown auth session
```

### Dual renderer

| Renderer | Size | Use case |
|---|---|---|
| Canvas 2D (default) | ~13 KB gzipped (includes `qrcode`) | All browsers, CPU-based |
| CanvasKit/Skia WASM | ~7 MB WASM, ~2.9 MB gzipped (lazy) | GPU-accelerated |

The CanvasKit renderer is loaded on demand and not bundled by default.

---

## Two-layer animation

**Layer 1 — Frame rotation (every `frameInterval`)**
- Generate new signed URL via `FrameSigner`.
- Encode URL into a QR matrix (wraps the `qrcode` npm package).
- Diff the new matrix against the previous one.
- Start per-module ripple transitions for changed cells.

**Layer 2 — Visual interpolation (60 fps via `requestAnimationFrame`)**
- Finder pattern glow (pulsing green halo on corner squares).
- Ambient pulse rings radiating from the center.
- Color wash in the quiet zone.
- Per-module ripple transitions for changed cells.
- All trust-reactive effects (see below).

::: info Scannability
Visual effects are cosmetic and are designed to keep module contrast scannable. Test your theme and trust states with the scanners your users have.
:::

---

## Trust-reactive animation

Update the visual state in response to server-side fraud signals without stopping the animation:

```ts
renderer.setTrustState({
  pulseSpeed: 1.0,        // 1.0 = normal, >1 = faster (alarm)
  hueShift: 0,            // degrees toward amber/red; 0 = normal (green)
  distortionLevel: 0,     // 0–1 module jitter
  dissolveProgress: 0,    // 0–1 module dissolution
});
```

| Trust score | Suggested state |
|---|---|
| 80–100 (trusted) | `pulseSpeed: 1.0, hueShift: 0` |
| 50–79 (caution) | `pulseSpeed: 1.4, hueShift: 30` |
| < 50 (suspicious) | `pulseSpeed: 2.5, hueShift: 120, distortionLevel: 0.4` |

---

## Lifecycle control

```ts
// Pause — stops all animation, holds last frame. CPU usage drops to 0.
renderer.freeze();

// Resume: request a new frameSecret from your backend, create a new
// renderer with it, then call start()

// Destroy — releases canvas and all resources
renderer.stop();
```

Visibility is managed automatically via `IntersectionObserver`. The renderer pauses itself when the canvas scrolls off-screen and resumes when it returns to the viewport.

---

## Performance targets

Design targets, not measured guarantees. Use the [benchmark harness](#benchmark-harness) to measure on your hardware.

| Metric | Target |
|---|---|
| Frame generation (FrameSigner + QR encode) | < 8 ms |
| Visual interpolation frame rate | 60 fps (transitions), ~15 fps (idle) |
| Off-screen frame rate | 0 fps (IntersectionObserver pause) |
| Bundle size (Canvas 2D renderer) | ~13 KB gzipped (includes `qrcode`) |

---

## Full options reference

```ts
interface AnimatedQROptions {
  canvas: HTMLCanvasElement;
  size: number;                  // Canvas width/height in px
  baseUrl: string;               // Verification URL for this QR token
  frameSecret: string;           // Hex-encoded HMAC secret from server
  frameInterval?: number;        // ms between matrix updates (default: 1000)
  theme?: 'light' | 'dark';      // Color theme (default: 'light')
  trustState?: TrustState;       // Initial trust state
  onFrame?: (p: FramePayload) => void;    // Called after each frame is generated
  onFreeze?: (last: FramePayload | null) => void; // Called when frozen
}

interface TrustState {
  pulseSpeed: number;
  hueShift: number;
  distortionLevel: number;
  dissolveProgress: number;
}
```

---

## Benchmark harness

A performance benchmark is available at `/benchmark/qr-renderer` in the repo. It measures frame generation time, encode time, and draw time separately across 1000 frames.

```bash
# From repo root
npm run dev:web
# Navigate to http://localhost:8081/benchmark/qr-renderer
```

---

## React example

```tsx
import { useEffect, useRef } from 'react';
import { AnimatedQRRenderer } from '@qrauth/animated-qr';

export function LiveQR({ token }: { token: string }) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const rendererRef = useRef<AnimatedQRRenderer | null>(null);

  useEffect(() => {
    let mounted = true;

    async function init() {
      const { frameSecret } = await fetch('/api/animated-session', {
        method: 'POST',
        body: JSON.stringify({ token }),
      }).then(r => r.json());

      if (!mounted || !canvasRef.current) return;

      rendererRef.current = new AnimatedQRRenderer({
        canvas: canvasRef.current,
        size: 320,
        baseUrl: `https://qrauth.io/v/${token}`,
        frameSecret,
      });

      await rendererRef.current.start();
    }

    init();

    return () => {
      mounted = false;
      rendererRef.current?.stop();
    };
  }, [token]);

  return <canvas ref={canvasRef} width={320} height={320} />;
}
```

::: warning React Strict Mode
In development, React Strict Mode double-invokes effects. Call `renderer.stop()` in the cleanup function (as shown above) — the renderer handles concurrent mount/unmount without state leaks.
:::
