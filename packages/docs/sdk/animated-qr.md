---
title: Animated QR SDK
description: Living Codes — animated QR codes with an HMAC-signed URL on every frame.
---

# Animated QR SDK

`@qrauth/animated-qr` renders Living Codes: QR codes that animate during transitions and carry a new HMAC-SHA-256-tagged URL on every frame. Frames are verified server-side by the frame-verify endpoint (`POST /api/v1/animated-qr/validate`), which accepts a frame at most 5 seconds after its timestamp (and at most 2 seconds ahead of it), and only if its index is higher than any frame already accepted for that session.

## Installation

::: code-group

```bash [npm]
npm install @qrauth/animated-qr
```

```bash [yarn]
yarn add @qrauth/animated-qr
```

:::

One runtime dependency (`qrcode`); `canvaskit-wasm` is an optional dependency used only by the CanvasKit renderer. The default bundle is about 13 KB gzipped, including `qrcode`. MIT licensed.

---

## `AnimatedQRRenderer`

The main class. Renders an animated QR code onto a `<canvas>` element.

```typescript
import { AnimatedQRRenderer } from '@qrauth/animated-qr'

const renderer = new AnimatedQRRenderer({
  canvas: document.getElementById('qr-canvas') as HTMLCanvasElement,
  size: 300,
  baseUrl,                      // from POST /api/v1/animated-qr/session
  frameSecret,                  // from POST /api/v1/animated-qr/session
  frameInterval: 500,           // ms between frame transitions
  theme: 'light',               // 'light' | 'dark'
  trustState: {
    pulseSpeed: 1.0,
    hueShift: 0,
    distortionLevel: 0,
    dissolveProgress: 0,
  },
  onFrame: (payload) => {
    // optional callback — receives each FramePayload as it is rendered
    console.log('frame:', payload.frameIndex)
  },
})

renderer.start()
```

### Constructor options

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `canvas` | `HTMLCanvasElement` | Yes | Target canvas element |
| `size` | number | Yes | Canvas size in CSS pixels |
| `baseUrl` | string | Yes | Verification URL for the session (`baseUrl` from the session response) |
| `frameSecret` | string | Yes | Hex-encoded per-session frame secret from the server |
| `frameInterval` | number | No | Milliseconds between frame changes (default: 1000) |
| `theme` | `'light' \| 'dark'` | No | Color theme (default: `'light'`) |
| `trustState` | `TrustState` | No | Initial visual trust state |
| `onFrame` | function | No | Called with each `FramePayload` after rendering |
| `onFreeze` | function | No | Called with the last `FramePayload` when `freeze()` is called |

### Instance methods

| Method | Description |
|--------|-------------|
| `start()` | Begin animation |
| `setTrustState(state)` | Update visual trust parameters with a smooth transition |
| `setTheme(theme)` | Switch between `'light'` and `'dark'` |
| `freeze()` | Stop animation and hold the last frame — 0 CPU usage |
| `stop()` | Stop the renderer and release its resources |

To resume after `freeze()`, request a new frame secret from your backend and create a new renderer.

---

## `TrustState`

Pass a `TrustState` to `setTrustState()` to reflect fraud signals visually. All fields are numbers in the range `0–1` unless noted.

```typescript
renderer.setTrustState({
  pulseSpeed: 2.0,         // faster pulsing when suspicious
  hueShift: 0.3,           // shift accent hue toward red
  distortionLevel: 0.1,    // subtle warp effect
  dissolveProgress: 0.0,   // 1.0 = full dissolve (revoked)
})
```

| Field | Range | Description |
|-------|-------|-------------|
| `pulseSpeed` | 0–5 | Animation speed multiplier (1.0 = normal) |
| `hueShift` | 0–1 | Shifts accent color: 0 = default, 1 = fully shifted to danger red |
| `distortionLevel` | 0–1 | Visual noise / warp on QR modules |
| `dissolveProgress` | 0–1 | Dissolve animation for revoked / expired codes |

---

## `FrameSigner`

Low-level class for signing frame payloads using HMAC-SHA-256 via the Web Crypto API. Used internally by `AnimatedQRRenderer`. Use it directly if you need to integrate with a custom renderer.

```typescript
import { FrameSigner } from '@qrauth/animated-qr'

const signer = new FrameSigner({
  baseUrl,       // e.g. 'https://qrauth.io/v/AbCdEfGh'
  frameSecret,   // hex
})

await signer.init()   // imports the HMAC key; call once before generateFrame()
const payload = await signer.generateFrame()
// payload: { url, frameIndex, timestamp, hmac }
```

### `FramePayload`

| Field | Type | Description |
|-------|------|-------------|
| `url` | string | The URL encoded in the QR matrix: `<baseUrl>?f=<frameIndex>&t=<timestamp>&h=<hmac>` |
| `frameIndex` | number | Monotonically increasing frame index |
| `timestamp` | number | Unix millisecond timestamp |
| `hmac` | string | First 8 bytes (16 hex characters) of HMAC-SHA-256 over `baseUrl:timestamp:frameIndex` under the frame secret |

---

## CanvasKit Renderer

A GPU-backed renderer using the CanvasKit (Skia) WASM backend. Requires WebGL and WebAssembly, and the optional `canvaskit-wasm` dependency.

```typescript
import { CanvasKitRenderer } from '@qrauth/animated-qr/canvaskit'

// Same options and methods as AnimatedQRRenderer
const renderer = new CanvasKitRenderer({ ... })
```

Import from `@qrauth/animated-qr/canvaskit`. The CanvasKit WASM binary (about 7 MB, about 2.9 MB gzipped) is loaded lazily on first use.

---

## Benchmark Utilities

```typescript
import { runBenchmark } from '@qrauth/animated-qr/benchmark'

const results = await runBenchmark({
  duration: 5000,          // ms per phase
  canvasSize: 300,
  frameInterval: 500,
  includeCanvasKit: false,
})

// One BenchmarkMetrics entry per renderer
for (const r of results) {
  console.log(r.renderer, r.frameGeneration.p50, r.renderTime.p99, r.fps)
}
```

---

## Performance Characteristics

Frame rates are design targets; run `runBenchmark` to measure on your hardware.

| Metric | Value |
|--------|-------|
| Idle framerate (target) | ~15 fps |
| Transition framerate (target) | 60 fps |
| Off-screen (via `IntersectionObserver`) | 0 fps |
| Bundle size (default renderer) | ~13 KB gzipped, including `qrcode` |
| CanvasKit WASM binary (lazy-loaded) | ~7 MB (~2.9 MB gzipped) |

The renderer pauses automatically when the canvas scrolls out of view (`IntersectionObserver`) and resumes when it becomes visible again.

---

## Server Integration

Before creating a renderer you need a frame secret for an existing auth session. The frame secret is derived server-side (HKDF-SHA-256, 32 bytes) per auth session and secret generation, and supplied to the rendering client.

```typescript
// Your backend: app credentials (Basic client_id:client_secret)
const response = await fetch('https://qrauth.io/api/v1/animated-qr/session', {
  method: 'POST',
  headers: {
    Authorization: `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString('base64')}`,
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({ authSessionId }),   // or { token } of the auth session
})

const { frameSecret, baseUrl, ttlSeconds } = await response.json()
// ttlSeconds: the lesser of the auth session's remaining life and 10 minutes
```

Each call issues a new frame secret and retires the previous one; frames signed with an earlier secret no longer verify. To rotate later, call `POST /api/v1/animated-qr/session/secret` with the same credentials.

A browser that has only the client ID uses the public flow instead: it sends `frameChallenge = base64url(SHA-256(frameVerifier))` in the `POST /api/v1/auth-sessions` request that creates the auth session, calls `POST /api/v1/animated-qr/session` (no secret is returned) and fetches the secret from `POST /api/v1/animated-qr/session/secret` with `frameVerifier` in the JSON body. See the [Living Codes guide](/guide/living-codes) for the browser code.

To validate a scanned frame, call the frame-verify endpoint from your integration:

```typescript
const res = await fetch('https://qrauth.io/api/v1/animated-qr/validate', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ baseUrl, frameIndex, timestamp, hmac }),
})
const { valid, reason } = await res.json()   // 200 { valid: true } or { valid: false, reason }
```

See [Living Codes](/guide/living-codes#server-validation) for the checks it performs.
