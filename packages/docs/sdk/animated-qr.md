---
title: Animated QR SDK
description: Living Codes — cryptographically animated QR codes that change every 500ms.
---

# Animated QR SDK

`@qrauth/animated-qr` renders Living Codes: QR codes that animate 60fps during transitions, sign each frame with HMAC-SHA256, and verify frame authenticity server-side. A screenshot is valid for at most one frame interval — making static image reuse impossible.

## Installation

::: code-group

```bash [npm]
npm install @qrauth/animated-qr
```

```bash [yarn]
yarn add @qrauth/animated-qr
```

:::

Approximately 15 KB gzipped. Zero runtime dependencies. MIT licensed.

---

## `AnimatedQRRenderer`

The main class. Renders an animated QR code onto a `<canvas>` element.

```typescript
import { AnimatedQRRenderer } from '@qrauth/animated-qr'

const renderer = new AnimatedQRRenderer({
  canvas: document.getElementById('qr-canvas') as HTMLCanvasElement,
  size: 300,
  baseUrl: 'https://qrauth.io',
  frameSecret: sessionSecret,   // from POST /api/v1/animated-qr/session
  frameInterval: 500,           // ms between frame transitions
  theme: {
    foreground: '#000000',
    background: '#ffffff',
    accentHue: 210,
  },
  trustState: {
    pulseSpeed: 1.0,
    hueShift: 0,
    distortionLevel: 0,
    dissolveProgress: 0,
  },
  onFrame: (payload) => {
    // optional callback — receives each FramePayload as it is rendered
    console.log('frame:', payload.frameId)
  },
})

renderer.start()
```

### Constructor options

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `canvas` | `HTMLCanvasElement` | Yes | Target canvas element |
| `size` | number | No | Canvas size in CSS pixels (default: 256) |
| `baseUrl` | string | Yes | QRAuth instance base URL |
| `frameSecret` | string | Yes | Per-session HMAC secret from the server |
| `frameInterval` | number | No | Milliseconds between frame changes (default: 500) |
| `theme` | object | No | Color configuration (see below) |
| `trustState` | `TrustState` | No | Initial visual trust state |
| `onFrame` | function | No | Called with each `FramePayload` after rendering |

### `theme` options

| Field | Type | Description |
|-------|------|-------------|
| `foreground` | string | QR module color (default: `"#000000"`) |
| `background` | string | Background color (default: `"#ffffff"`) |
| `accentHue` | number | Hue (0–360) for animated accent elements |

### Instance methods

| Method | Description |
|--------|-------------|
| `start()` | Begin animation |
| `setTrustState(state)` | Update visual trust parameters with a smooth transition |
| `freeze()` | Stop animation and hold the last frame — 0 CPU usage |
| `restart()` | Request a new server session and resume animation |
| `destroy()` | Tear down the renderer and release the canvas |

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

Low-level class for signing frame payloads using HMAC-SHA256 via the Web Crypto API. Used internally by `AnimatedQRRenderer`. Use it directly if you need to integrate with a custom renderer.

```typescript
import { FrameSigner } from '@qrauth/animated-qr'

const signer = new FrameSigner({
  baseUrl: 'https://qrauth.io',
  frameSecret: sessionSecret,
})

const payload = await signer.generateFrame()
// payload: { frameId, timestamp, hmac, qrData }
```

### `FramePayload`

| Field | Type | Description |
|-------|------|-------------|
| `frameId` | string | Monotonically increasing frame identifier |
| `timestamp` | number | Unix millisecond timestamp |
| `hmac` | string | HMAC-SHA256 hex digest covering `frameId + timestamp` |
| `qrData` | string | The string encoded in the QR matrix for this frame |

---

## CanvasKit Renderer

A higher-fidelity renderer using the CanvasKit (Skia) backend. Larger bundle (~120 KB) but supports sub-pixel antialiasing and advanced blend modes.

```typescript
import { AnimatedQRRenderer } from '@qrauth/animated-qr/canvaskit'

// Same API as the default renderer
const renderer = new AnimatedQRRenderer({ ... })
```

Import from `@qrauth/animated-qr/canvaskit`. The CanvasKit WASM binary is loaded lazily on first use.

---

## Benchmark Utilities

```typescript
import { runBenchmark } from '@qrauth/animated-qr/benchmark'

const results = await runBenchmark({
  frames: 1000,
  size: 300,
  frameInterval: 500,
})

console.log(results.avgFrameMs)   // average frame render time
console.log(results.p99FrameMs)   // 99th percentile
console.log(results.droppedFrames)
```

---

## Performance Characteristics

| Metric | Value |
|--------|-------|
| Idle framerate | ~15 fps |
| Transition framerate | 60 fps |
| Off-screen (via `IntersectionObserver`) | 0 fps |
| Bundle size (default renderer) | ~15 KB gzipped |
| Bundle size (CanvasKit renderer) | ~120 KB gzipped |

The renderer pauses automatically when the canvas scrolls out of view (`IntersectionObserver`) and resumes when it becomes visible again.

---

## Server Integration

Before creating a renderer you need a session secret from the server:

```typescript
// Your backend
const response = await fetch('https://qrauth.io/api/v1/animated-qr/session', {
  method: 'POST',
  headers: { 'X-API-Key': process.env.QRAUTH_API_KEY },
  body: JSON.stringify({ qrToken: 'abc123' }),
})

const { frameSecret, sessionId } = await response.json()
// Pass frameSecret to the frontend securely (e.g., via a server-rendered page or short-lived token)
```

Frame validation happens automatically when a scanner hits the verification endpoint — no extra integration required.
