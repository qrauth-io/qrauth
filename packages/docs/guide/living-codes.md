# Living Codes (Animated QR)

A static QR code is a screenshot away from being replayed. Living Codes solve this by encoding a new cryptographically signed URL into the QR matrix every 500 ms. Each frame contains a frame index, a timestamp, and an HMAC-SHA256 signature derived from a per-session secret. Screenshotted frames become stale within seconds.

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

// 1. Get a session secret from the QRAuth API
const { sessionId, frameSecret } = await fetch('/api/v1/animated-qr/session', {
  method: 'POST',
  headers: { Authorization: `Bearer ${apiKey}` },
  body: JSON.stringify({ token: 'AbCdEfGh' }),
}).then(r => r.json());

// 2. Mount the renderer on a canvas element
const canvas = document.getElementById('qr') as HTMLCanvasElement;

const renderer = new AnimatedQRRenderer({
  canvas,
  size: 400,
  baseUrl: `https://qrauth.io/v/AbCdEfGh`,
  frameSecret,          // hex-encoded per-session HMAC secret
  frameInterval: 500,   // ms between QR matrix updates (default: 500)
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
3. Computes `HMAC-SHA256(baseUrl + ":" + timestamp + ":" + frameIndex)` using the Web Crypto API.
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

On each scan the server:
1. Derives the same HMAC key from the session secret stored in Redis.
2. Recomputes the HMAC for the received `f`, `t` values.
3. Checks the timestamp is within a ±5-second freshness window.
4. Rejects any previously seen `frameIndex` (replay prevention via Redis SET).

```
POST /api/v1/animated-qr/validate
{ token, frameIndex, timestamp, hmac }
→ 200 { valid: true }
→ 422 { valid: false, reason: 'stale_frame' | 'replay' | 'invalid_hmac' }
```

### Dual renderer

| Renderer | Size | Use case |
|---|---|---|
| Canvas 2D (default) | ~15 KB | All browsers, CPU-based |
| CanvasKit/Skia WASM | ~180 KB (lazy) | GPU-accelerated, smooth at 60fps |

The CanvasKit renderer is loaded on demand and not bundled by default.

---

## Two-layer animation

**Layer 1 — Frame rotation (every 500 ms)**
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

::: info Scannability guarantee
All visual effects are purely cosmetic. Module luminance contrast is maintained above the ISO 18004 minimum at every animation frame. Any QR scanner that reads the static version will read the animated version.
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

// Resume with a fresh session (new frameSecret from server)
await renderer.restart();

// Destroy — releases canvas and all resources
renderer.stop();
```

Visibility is managed automatically via `IntersectionObserver`. The renderer pauses itself when the canvas scrolls off-screen and resumes when it returns to the viewport.

---

## Performance targets

| Metric | Target |
|---|---|
| Frame generation (FrameSigner + QR encode) | < 8 ms |
| Visual interpolation frame rate | 60 fps (transitions), ~15 fps (idle) |
| Off-screen frame rate | 0 fps (IntersectionObserver pause) |
| Bundle size (Canvas 2D renderer) | ~15 KB gzipped |

---

## Full options reference

```ts
interface AnimatedQROptions {
  canvas: HTMLCanvasElement;
  size: number;                  // Canvas width/height in px
  baseUrl: string;               // Verification URL for this QR token
  frameSecret: string;           // Hex-encoded HMAC secret from server
  frameInterval?: number;        // ms between matrix updates (default: 500)
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
