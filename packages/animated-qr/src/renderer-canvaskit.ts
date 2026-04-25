/**
 * CanvasKitRenderer — Skia WASM-powered renderer for Living Codes.
 *
 * Uses canvaskit-wasm for hardware-accelerated rendering via WebGL.
 * This is the benchmark candidate to compare against Canvas 2D.
 *
 * Key differences from Canvas 2D renderer:
 *   - GPU-backed rendering via WebGL (vs CPU-bound Canvas 2D)
 *   - Skia batches draw calls (vs N² fillRect calls)
 *   - ~6MB WASM module (lazy-loaded)
 *   - Requires WebGL + WebAssembly support
 */

import type { CanvasKit, Surface, Canvas as SkCanvas, Paint } from 'canvaskit-wasm';
import { encodeQR, initEncoder, type QRMatrix } from './qr-encoder.js';
import { FrameSigner, type FramePayload } from './frame-signer.js';
import type {
  IAnimatedQRRenderer,
  AnimatedQROptions,
  TrustState,
  RendererStatus,
} from './renderer-interface.js';

// ---------------------------------------------------------------------------
// Constants (shared with Canvas 2D renderer)
// ---------------------------------------------------------------------------

const QUIET_ZONE = 4;
const TRANSITION_DURATION = 200;
const PULSE_PERIOD = 2000;
const PULSE_RING_COUNT = 3;
const RING_PERIOD = 2400;
const WASH_PERIOD = 20000;

const DEFAULT_TRUST_STATE: TrustState = {
  pulseSpeed: 1.0,
  hueShift: 0,
  distortionLevel: 0,
  dissolveProgress: 0,
};

// ---------------------------------------------------------------------------
// Color themes
// ---------------------------------------------------------------------------

interface ThemeColors {
  bg: [number, number, number, number];
  module: [number, number, number, number];
  moduleLight: [number, number, number, number];
  finderInner: [number, number, number, number];
  quietZone: [number, number, number, number];
  pulseColor: [number, number, number, number];
}

function hexToFloat4(hex: string, alpha = 1): [number, number, number, number] {
  const c = hex.replace('#', '');
  return [
    parseInt(c.slice(0, 2), 16) / 255,
    parseInt(c.slice(2, 4), 16) / 255,
    parseInt(c.slice(4, 6), 16) / 255,
    alpha,
  ];
}

const THEMES: Record<'light' | 'dark', ThemeColors> = {
  light: {
    bg: hexToFloat4('#ffffff'),
    module: hexToFloat4('#1a1a2e'),
    moduleLight: hexToFloat4('#ffffff'),
    finderInner: hexToFloat4('#00a76f'),
    quietZone: hexToFloat4('#f8f9fa'),
    pulseColor: [0, 167 / 255, 111 / 255, 0.08],
  },
  dark: {
    bg: hexToFloat4('#0f1117'),
    module: hexToFloat4('#e8eaed'),
    moduleLight: hexToFloat4('#0f1117'),
    finderInner: hexToFloat4('#00a76f'),
    quietZone: hexToFloat4('#161822'),
    pulseColor: [0, 167 / 255, 111 / 255, 0.1],
  },
};

// ---------------------------------------------------------------------------
// Per-module state (same as Canvas 2D — typed arrays for performance)
// ---------------------------------------------------------------------------

interface ModuleStateArrays {
  isDark: Uint8Array;
  progress: Float32Array;
  transitionStart: Float64Array;
  delay: Float32Array;
  distFromCenter: Float32Array;
  isFinder: Uint8Array;
  isFinderInner: Uint8Array;
}

function allocModuleState(size: number): ModuleStateArrays {
  const n = size * size;
  return {
    isDark: new Uint8Array(n),
    progress: new Float32Array(n).fill(1),
    transitionStart: new Float64Array(n).fill(-Infinity),
    delay: new Float32Array(n),
    distFromCenter: new Float32Array(n),
    isFinder: new Uint8Array(n),
    isFinderInner: new Uint8Array(n),
  };
}

// ---------------------------------------------------------------------------
// Finder pattern helpers
// ---------------------------------------------------------------------------

function isFinderModule(row: number, col: number, size: number): boolean {
  if (row <= 6 && col <= 6) return true;
  if (row <= 6 && col >= size - 7) return true;
  if (row >= size - 7 && col <= 6) return true;
  return false;
}

function isFinderInnerModule(row: number, col: number, size: number): boolean {
  if (row >= 2 && row <= 4 && col >= 2 && col <= 4) return true;
  const tr = size - 5;
  if (row >= 2 && row <= 4 && col >= tr && col <= tr + 2) return true;
  const bl = size - 5;
  if (row >= bl && row <= bl + 2 && col >= 2 && col <= 4) return true;
  return false;
}

function finderCenters(size: number): Array<[number, number]> {
  return [[3, 3], [3, size - 4], [size - 4, 3]];
}

function easeOut(t: number): number {
  return 1 - Math.pow(1 - t, 3);
}

// ---------------------------------------------------------------------------
// CanvasKit Renderer
// ---------------------------------------------------------------------------

/** Lazily loaded CanvasKit instance. */
let _ck: CanvasKit | null = null;

/**
 * Load CanvasKit WASM module. Call once; subsequent calls are no-ops.
 * Accepts an optional locateFile override for CDN hosting of the WASM binary.
 */
export async function initCanvasKit(
  locateFile?: (file: string) => string,
): Promise<CanvasKit> {
  if (_ck) return _ck;

  const CanvasKitInit = (await import('canvaskit-wasm')).default;
  _ck = await CanvasKitInit(locateFile ? { locateFile } : undefined);
  return _ck;
}

export class CanvasKitRenderer implements IAnimatedQRRenderer {
  // --- config ---
  private readonly canvas: HTMLCanvasElement;
  private readonly cssSize: number;
  private readonly frameInterval: number;
  private readonly onFrame?: (payload: FramePayload) => void;
  private readonly onFreeze?: (lastFrame: FramePayload | null) => void;

  // --- CanvasKit resources ---
  private ck: CanvasKit | null = null;
  private surface: Surface | null = null;
  private modulePaint: Paint | null = null;
  private bgPaint: Paint | null = null;
  private glowPaint: Paint | null = null;
  private ringPaint: Paint | null = null;

  // --- subsystems ---
  private readonly signer: FrameSigner;

  // --- state ---
  private theme: 'light' | 'dark';
  private trustState: TrustState;
  private running = false;
  private frozen = false;
  private lastPayload: FramePayload | null = null;

  // --- QR / module state ---
  private currentMatrix: QRMatrix | null = null;
  private moduleState: ModuleStateArrays | null = null;

  // --- animation ---
  private rafId: number | null = null;
  private frameTimerId: ReturnType<typeof setTimeout> | null = null;
  private startTime = 0;
  private lastDrawTime = 0;
  private needsRedraw = true;
  private visible = true;
  private observer: IntersectionObserver | null = null;

  constructor(options: AnimatedQROptions) {
    this.canvas = options.canvas;
    this.cssSize = options.size;
    this.frameInterval = options.frameInterval ?? 1000;
    this.theme = options.theme ?? 'light';
    this.trustState = { ...DEFAULT_TRUST_STATE, ...options.trustState };
    this.onFrame = options.onFrame;
    this.onFreeze = options.onFreeze;

    this.signer = new FrameSigner({
      baseUrl: options.baseUrl,
      frameSecret: options.frameSecret,
    });
  }

  // ---------------------------------------------------------------------------
  // Public API
  // ---------------------------------------------------------------------------

  async start(): Promise<void> {
    if (this.running) return;
    this.running = true;
    this.startTime = performance.now();

    // Initialize CanvasKit + QR encoder in parallel
    const [ck] = await Promise.all([
      initCanvasKit(),
      this.signer.init(),
      initEncoder(),
    ]);
    if (!this.running) return;

    this.ck = ck;
    this.initSurface();
    this.initPaints();

    // Visibility observer
    if (typeof IntersectionObserver !== 'undefined') {
      this.observer = new IntersectionObserver(
        ([entry]) => { this.visible = entry.isIntersecting; },
        { threshold: 0 },
      );
      this.observer.observe(this.canvas);
    }

    await this.rotateFrame();
    if (!this.running) return;

    this.scheduleNextFrame();
    this.rafId = requestAnimationFrame(this.renderLoop);
  }

  stop(): void {
    this.running = false;
    this.cleanupAnimation();
    this.cleanupSkiaResources();
  }

  freeze(): void {
    if (!this.running || this.frozen) return;
    this.frozen = true;
    this.running = false;
    this.cleanupAnimation();
    this.onFreeze?.(this.lastPayload);
  }

  get status(): RendererStatus {
    if (this.frozen) return 'frozen';
    if (this.running) return 'running';
    if (this.currentMatrix) return 'stopped';
    return 'idle';
  }

  get frameCount(): number {
    return this.lastPayload?.frameIndex ?? 0;
  }

  setTrustState(state: Partial<TrustState>): void {
    this.trustState = { ...this.trustState, ...state };
    this.needsRedraw = true;
  }

  setTheme(theme: 'light' | 'dark'): void {
    this.theme = theme;
    this.needsRedraw = true;
  }

  // ---------------------------------------------------------------------------
  // Initialization
  // ---------------------------------------------------------------------------

  private initSurface(): void {
    const ck = this.ck!;
    const dpr = typeof window !== 'undefined' ? (window.devicePixelRatio || 1) : 1;
    const physSize = Math.round(this.cssSize * dpr);

    this.canvas.width = physSize;
    this.canvas.height = physSize;
    this.canvas.style.width = `${this.cssSize}px`;
    this.canvas.style.height = `${this.cssSize}px`;

    this.surface = ck.MakeWebGLCanvasSurface(this.canvas);
    if (!this.surface) {
      // Fallback: software surface (slower but works without WebGL)
      this.surface = ck.MakeSWCanvasSurface(this.canvas);
    }
    if (!this.surface) {
      throw new Error('CanvasKitRenderer: failed to create Skia surface');
    }
  }

  private initPaints(): void {
    const ck = this.ck!;
    this.modulePaint = new ck.Paint();
    this.modulePaint.setAntiAlias(false); // QR modules are intentionally sharp
    this.modulePaint.setStyle(ck.PaintStyle.Fill);

    this.bgPaint = new ck.Paint();
    this.bgPaint.setStyle(ck.PaintStyle.Fill);

    this.glowPaint = new ck.Paint();
    this.glowPaint.setStyle(ck.PaintStyle.Fill);
    this.glowPaint.setAntiAlias(true);

    this.ringPaint = new ck.Paint();
    this.ringPaint.setStyle(ck.PaintStyle.Stroke);
    this.ringPaint.setStrokeWidth(1.5);
    this.ringPaint.setAntiAlias(true);
  }

  // ---------------------------------------------------------------------------
  // Frame rotation (Layer 1) — identical logic to Canvas 2D
  // ---------------------------------------------------------------------------

  private async rotateFrame(): Promise<void> {
    if (!this.running) return;
    try {
      const payload = await this.signer.generateFrame();
      if (!this.running) return;
      this.lastPayload = payload;
      this.onFrame?.(payload);

      const newMatrix = encodeQR(payload.url);
      this.applyNewMatrix(newMatrix);
      this.needsRedraw = true;
    } catch (err) {
      console.error('[animated-qr/canvaskit] Frame generation failed:', err);
    }
  }

  private scheduleNextFrame(): void {
    if (!this.running) return;
    this.frameTimerId = setTimeout(async () => {
      await this.rotateFrame();
      this.scheduleNextFrame();
    }, this.frameInterval);
  }

  private applyNewMatrix(newMatrix: QRMatrix): void {
    const size = newMatrix.size;
    const now = performance.now();

    if (!this.moduleState || this.currentMatrix?.size !== size) {
      this.moduleState = allocModuleState(size);
      this.precomputeStaticFields(size);

      for (let r = 0; r < size; r++) {
        for (let c = 0; c < size; c++) {
          const idx = r * size + c;
          this.moduleState.isDark[idx] = newMatrix.modules[r][c] ? 1 : 0;
          this.moduleState.progress[idx] = 1;
        }
      }
    } else {
      const state = this.moduleState;
      for (let r = 0; r < size; r++) {
        for (let c = 0; c < size; c++) {
          const idx = r * size + c;
          const newDark = newMatrix.modules[r][c] ? 1 : 0;
          if (state.isDark[idx] !== newDark) {
            const dist = state.distFromCenter[idx];
            const delay = dist * size * 15;
            state.transitionStart[idx] = now + delay;
            state.progress[idx] = 0;
            state.isDark[idx] = newDark;
          }
        }
      }
    }
    this.currentMatrix = newMatrix;
  }

  private precomputeStaticFields(size: number): void {
    const state = this.moduleState!;
    const cx = (size - 1) / 2;
    const cy = (size - 1) / 2;
    const maxDist = Math.sqrt(cx * cx + cy * cy);

    for (let r = 0; r < size; r++) {
      for (let c = 0; c < size; c++) {
        const idx = r * size + c;
        const dx = r - cy;
        const dy = c - cx;
        state.distFromCenter[idx] = Math.sqrt(dx * dx + dy * dy) / maxDist;
        state.isFinder[idx] = isFinderModule(r, c, size) ? 1 : 0;
        state.isFinderInner[idx] = isFinderInnerModule(r, c, size) ? 1 : 0;
      }
    }
  }

  // ---------------------------------------------------------------------------
  // Render loop
  // ---------------------------------------------------------------------------

  private renderLoop = (now: number): void => {
    if (!this.running) return;

    if (!this.visible) {
      this.rafId = requestAnimationFrame(this.renderLoop);
      return;
    }

    const dt = now - this.lastDrawTime;
    const minInterval = this.needsRedraw ? 0 : 60;

    if (dt >= minInterval) {
      this.draw(now);
      this.lastDrawTime = now;
    }

    this.rafId = requestAnimationFrame(this.renderLoop);
  };

  private draw(now: number): void {
    if (!this.currentMatrix || !this.moduleState || !this.surface || !this.ck) return;

    const ck = this.ck;
    const skCanvas = this.surface.getCanvas();
    const matrix = this.currentMatrix;
    const state = this.moduleState;
    const { size } = matrix;
    const elapsed = now - this.startTime;
    const trust = this.trustState;
    const theme = THEMES[this.theme];

    const dpr = typeof window !== 'undefined' ? (window.devicePixelRatio || 1) : 1;
    const phys = Math.round(this.cssSize * dpr);
    const totalModules = size + QUIET_ZONE * 2;
    const moduleSize = phys / totalModules;
    const quietPx = QUIET_ZONE * moduleSize;

    // --- 1. Background ---
    skCanvas.clear(ck.Color4f(...theme.bg));

    // --- 2. Quiet zone color wash ---
    this.drawColorWash(skCanvas, phys, quietPx, moduleSize * size, elapsed, theme);

    // --- 3. Pulse rings ---
    this.drawPulseRings(skCanvas, quietPx, moduleSize * size, elapsed, trust, theme);

    // --- 4. Finder glows ---
    this.drawFinderGlows(skCanvas, size, moduleSize, quietPx, elapsed, trust, theme);

    // --- 5. Advance transitions ---
    this.advanceTransitions(state, size, now);

    // --- 6. Draw modules ---
    this.drawModules(skCanvas, state, size, moduleSize, quietPx, now, trust, theme);

    // Flush to screen
    this.surface.flush();
  }

  // ---------------------------------------------------------------------------
  // Draw subsystems (Skia equivalents)
  // ---------------------------------------------------------------------------

  private drawColorWash(
    skCanvas: SkCanvas,
    phys: number,
    quietPx: number,
    dataPx: number,
    elapsed: number,
    theme: ThemeColors,
  ): void {
    const ck = this.ck!;
    const paint = this.bgPaint!;

    const phase = (elapsed % WASH_PERIOD) / WASH_PERIOD;
    const angle = phase * Math.PI * 2;
    const blend = 0.06 + 0.06 * Math.sin(angle);

    const [qr, qg, qb] = theme.quietZone;
    const [ar, ag, ab] = theme.finderInner;
    const wr = qr + (ar - qr) * blend;
    const wg = qg + (ag - qg) * blend;
    const wb = qb + (ab - qb) * blend;

    paint.setColor(ck.Color4f(wr, wg, wb, 1));

    // Top, Bottom, Left, Right strips
    skCanvas.drawRect(ck.LTRBRect(0, 0, phys, quietPx), paint);
    skCanvas.drawRect(ck.LTRBRect(0, quietPx + dataPx, phys, quietPx + dataPx + quietPx), paint);
    skCanvas.drawRect(ck.LTRBRect(0, quietPx, quietPx, quietPx + dataPx), paint);
    skCanvas.drawRect(ck.LTRBRect(quietPx + dataPx, quietPx, quietPx + dataPx + quietPx, quietPx + dataPx), paint);
  }

  private drawPulseRings(
    skCanvas: SkCanvas,
    quietPx: number,
    dataPx: number,
    elapsed: number,
    trust: TrustState,
    theme: ThemeColors,
  ): void {
    const ck = this.ck!;
    const paint = this.ringPaint!;
    const cx = quietPx + dataPx / 2;
    const cy = quietPx + dataPx / 2;
    const maxR = (dataPx / 2) * 1.1;

    const speed = trust.pulseSpeed;
    const period = RING_PERIOD / speed;

    for (let i = 0; i < PULSE_RING_COUNT; i++) {
      const phase = ((elapsed / period) + i / PULSE_RING_COUNT) % 1;
      const r = phase * maxR;
      const opacity = (1 - phase) * 0.35;

      const [pr, pg, pb] = theme.pulseColor;
      paint.setColor(ck.Color4f(pr, pg, pb, opacity));
      skCanvas.drawCircle(cx, cy, r, paint);
    }
  }

  private drawFinderGlows(
    skCanvas: SkCanvas,
    size: number,
    moduleSize: number,
    quietPx: number,
    elapsed: number,
    trust: TrustState,
    theme: ThemeColors,
  ): void {
    const ck = this.ck!;
    const paint = this.glowPaint!;
    const speed = trust.pulseSpeed;
    const glowIntensity = 0.3 + 0.7 * Math.sin((elapsed * Math.PI) / (PULSE_PERIOD * speed));
    const clampedGlow = Math.max(0, Math.min(1, glowIntensity));
    const alpha = clampedGlow * 0.6;

    const [ir, ig, ib] = theme.finderInner;

    const centers = finderCenters(size);
    for (const [fr, fc] of centers) {
      const px = quietPx + fc * moduleSize + moduleSize / 2;
      const py = quietPx + fr * moduleSize + moduleSize / 2;
      const glowRadius = moduleSize * 3.5;

      // Use a radial gradient shader for the glow
      const shader = ck.Shader.MakeRadialGradient(
        [px, py],
        glowRadius,
        [
          ck.Color4f(ir, ig, ib, alpha),
          ck.Color4f(ir, ig, ib, alpha * 0.4),
          ck.Color4f(ir, ig, ib, 0),
        ],
        [0, 0.4, 1],
        ck.TileMode.Clamp,
      );

      paint.setShader(shader);
      skCanvas.drawCircle(px, py, glowRadius, paint);
      paint.setShader(null);
      shader.delete();
    }
  }

  private advanceTransitions(
    state: ModuleStateArrays,
    size: number,
    now: number,
  ): void {
    const n = size * size;
    let anyActive = false;

    for (let idx = 0; idx < n; idx++) {
      const p = state.progress[idx];
      if (p >= 1) continue;

      const elapsed = now - state.transitionStart[idx];
      if (elapsed > 2000) {
        state.progress[idx] = 1;
        continue;
      }
      if (elapsed < 0) {
        anyActive = true;
        continue;
      }

      const raw = elapsed / TRANSITION_DURATION;
      const newP = Math.min(1, easeOut(raw));
      state.progress[idx] = newP;
      if (newP < 1) anyActive = true;
    }

    if (!anyActive) this.needsRedraw = false;
  }

  private drawModules(
    skCanvas: SkCanvas,
    state: ModuleStateArrays,
    size: number,
    moduleSize: number,
    quietPx: number,
    now: number,
    trust: TrustState,
    theme: ThemeColors,
  ): void {
    const ck = this.ck!;
    const paint = this.modulePaint!;

    const [dr, dg, db] = theme.module;
    const [lr, lg, lb] = theme.moduleLight;
    const [ir, ig, ib] = theme.finderInner;

    const hueRatio = Math.min(1, trust.hueShift / 180);
    const distortion = trust.distortionLevel;
    const dissolve = trust.dissolveProgress;

    let seed = 0x9e3779b9;
    const rand = (idx: number): number => {
      let x = seed ^ (idx * 0x6c62272e);
      x ^= x >>> 16;
      x = Math.imul(x, 0x45d9f3b);
      x ^= x >>> 16;
      return (x >>> 0) / 0xffffffff;
    };
    seed ^= Math.round(now) & 0xffff;

    for (let r = 0; r < size; r++) {
      for (let c = 0; c < size; c++) {
        const idx = r * size + c;

        if (dissolve > 0 && rand(idx) < dissolve * 0.8) continue;

        const isDark = state.isDark[idx] === 1;
        const progress = state.progress[idx];
        const isFinder = state.isFinder[idx] === 1;
        const isInner = state.isFinderInner[idx] === 1;

        const darkFraction = isDark ? progress : 1 - progress;

        let fillR: number, fillG: number, fillB: number;
        if (isInner && darkFraction > 0.5) {
          const t = (darkFraction - 0.5) * 2;
          fillR = lr + (ir - lr) * t;
          fillG = lg + (ig - lg) * t;
          fillB = lb + (ib - lb) * t;
        } else {
          fillR = lr + (dr - lr) * darkFraction;
          fillG = lg + (dg - lg) * darkFraction;
          fillB = lb + (db - lb) * darkFraction;
        }

        // Hue shift toward amber
        if (hueRatio > 0 && darkFraction > 0.5) {
          fillR = fillR + (1.0 - fillR) * hueRatio;
          fillG = fillG + (140 / 255 - fillG) * hueRatio;
          fillB = fillB + (0 - fillB) * hueRatio;
        }

        let px = quietPx + c * moduleSize;
        let py = quietPx + r * moduleSize;

        if (distortion > 0 && !isFinder) {
          const jitter = distortion * moduleSize * 0.18;
          px += (rand(idx + 0x1000) - 0.5) * jitter;
          py += (rand(idx + 0x2000) - 0.5) * jitter;
        }

        paint.setColor(ck.Color4f(fillR, fillG, fillB, 1));
        skCanvas.drawRect(
          ck.LTRBRect(px, py, px + moduleSize, py + moduleSize),
          paint,
        );
      }
    }
  }

  // ---------------------------------------------------------------------------
  // Cleanup
  // ---------------------------------------------------------------------------

  private cleanupAnimation(): void {
    if (this.rafId !== null) {
      cancelAnimationFrame(this.rafId);
      this.rafId = null;
    }
    if (this.frameTimerId !== null) {
      clearTimeout(this.frameTimerId);
      this.frameTimerId = null;
    }
    if (this.observer) {
      this.observer.disconnect();
      this.observer = null;
    }
  }

  private cleanupSkiaResources(): void {
    this.modulePaint?.delete();
    this.bgPaint?.delete();
    this.glowPaint?.delete();
    this.ringPaint?.delete();
    this.surface?.delete();
    this.modulePaint = null;
    this.bgPaint = null;
    this.glowPaint = null;
    this.ringPaint = null;
    this.surface = null;
  }
}
