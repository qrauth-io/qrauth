/**
 * AnimatedQRRenderer — the visual engine for QRAuth Living Codes.
 *
 * Two-layer animation architecture:
 *   Layer 1: Frame rotation (every 500ms) — generates new cryptographically
 *            signed URLs, encodes them as QR matrices, diffs against previous
 *            matrix, and starts per-module ripple transitions.
 *   Layer 2: Visual interpolation (60fps via requestAnimationFrame) — renders
 *            breathing finder patterns, ambient pulse rings, color wash in the
 *            quiet zone, module transitions, and trust-reactive effects.
 *
 * QR scannability is never compromised. All visual effects are cosmetic:
 * modules maintain sufficient luminance contrast for any scanner.
 */

import { encodeQR, initEncoder, type QRMatrix } from './qr-encoder.js';
import { FrameSigner, type FramePayload } from './frame-signer.js';

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export { type FramePayload };

export interface TrustState {
  /** Pulse speed multiplier. 1.0 = normal. */
  pulseSpeed: number;
  /** Hue shift in degrees toward amber/red. 0 = normal. */
  hueShift: number;
  /** Module jitter level. 0 = none, 1 = full. */
  distortionLevel: number;
  /** Module dissolve probability. 0 = fully visible, 1 = fully dissolved. */
  dissolveProgress: number;
}

export interface AnimatedQROptions {
  canvas: HTMLCanvasElement;
  size: number;
  baseUrl: string;
  frameSecret: string;
  frameInterval?: number;
  theme?: 'light' | 'dark';
  trustState?: TrustState;
  onFrame?: (payload: FramePayload) => void;
  /** Called when the renderer is stopped via freeze(). */
  onFreeze?: (lastFrame: FramePayload | null) => void;
}

/** Status of the renderer lifecycle. */
export type RendererStatus = 'idle' | 'running' | 'frozen' | 'stopped';

// ---------------------------------------------------------------------------
// Color themes
// ---------------------------------------------------------------------------

interface Theme {
  bg: string;
  module: string;
  moduleLight: string;
  finderOuter: string;
  finderInner: string;
  quietZone: string;
  glowColor: string;
  pulseColor: string;
}

const THEMES: Record<'light' | 'dark', Theme> = {
  light: {
    bg: '#ffffff',
    module: '#1a1a2e',
    moduleLight: '#ffffff',
    finderOuter: '#1a1a2e',
    finderInner: '#00a76f',
    quietZone: '#f8f9fa',
    glowColor: 'rgba(0, 167, 111, 0.15)',
    pulseColor: 'rgba(0, 167, 111, 0.08)',
  },
  dark: {
    bg: '#0f1117',
    module: '#e8eaed',
    moduleLight: '#0f1117',
    finderOuter: '#e8eaed',
    finderInner: '#00a76f',
    quietZone: '#161822',
    glowColor: 'rgba(0, 167, 111, 0.2)',
    pulseColor: 'rgba(0, 167, 111, 0.1)',
  },
};

// ---------------------------------------------------------------------------
// Internal constants
// ---------------------------------------------------------------------------

/** Quiet zone in modules (ISO 18004 specifies 4, we use 4). */
const QUIET_ZONE = 4;
/** Module corner radius as a fraction of module size. 0 = sharp squares (best scannability). */
const MODULE_RADIUS_RATIO = 0;
/** Duration of a single module transition in ms. */
const TRANSITION_DURATION = 200;
/** Finder pattern glow pulse period in ms (at pulseSpeed=1). */
const PULSE_PERIOD = 2000;
/** Number of ambient pulse rings. */
const PULSE_RING_COUNT = 3;
/** Ambient pulse ring expansion period in ms. */
const RING_PERIOD = 2400;
/** Background hue wash full-cycle duration in ms. */
const WASH_PERIOD = 20000;

// ---------------------------------------------------------------------------
// Per-module state (flattened into typed arrays for performance)
// ---------------------------------------------------------------------------

/**
 * For an N×N matrix we maintain parallel flat arrays of length N*N.
 * Index = row * size + col.
 */
interface ModuleStateArrays {
  /** Current (target) dark state. 1 = dark, 0 = light. */
  isDark: Uint8Array;
  /** Transition progress 0→1 (new state). Float32, updated every rAF. */
  progress: Float32Array;
  /** Absolute timestamp when transition started (ms). */
  transitionStart: Float64Array;
  /** Stagger delay before transition begins (ms). */
  delay: Float32Array;
  /** Pre-computed distance from matrix center, normalised to [0,1]. */
  distFromCenter: Float32Array;
  /** Whether this module is part of a finder pattern. */
  isFinder: Uint8Array;
  /** Whether this module is the inner 3×3 of a finder. */
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
// Utility helpers
// ---------------------------------------------------------------------------

function easeOut(t: number): number {
  return 1 - Math.pow(1 - t, 3);
}


function hexToRGB(hex: string): [number, number, number] {
  const clean = hex.replace('#', '');
  return [
    parseInt(clean.slice(0, 2), 16),
    parseInt(clean.slice(2, 4), 16),
    parseInt(clean.slice(4, 6), 16),
  ];
}

/** Shift an rgb() color toward an amber/red hue. */
function applyHueShift(
  r: number, g: number, b: number,
  shift: number, // 0–1
): [number, number, number] {
  // Blend toward amber (255, 140, 0)
  const ar = 255, ag = 140, ab = 0;
  return [
    Math.round(r + (ar - r) * shift),
    Math.round(g + (ag - g) * shift),
    Math.round(b + (ab - b) * shift),
  ];
}

// ---------------------------------------------------------------------------
// Finder pattern helpers
// ---------------------------------------------------------------------------

/**
 * Returns true if (row, col) falls inside one of the three 7×7 finder
 * patterns for a QR matrix of the given size.
 */
function isFinderModule(row: number, col: number, size: number): boolean {
  // Top-left: rows 0–6, cols 0–6
  if (row <= 6 && col <= 6) return true;
  // Top-right: rows 0–6, cols (size-7)–(size-1)
  if (row <= 6 && col >= size - 7) return true;
  // Bottom-left: rows (size-7)–(size-1), cols 0–6
  if (row >= size - 7 && col <= 6) return true;
  return false;
}

/**
 * Returns true if (row, col) is part of the inner 3×3 of a finder pattern
 * (the central dark square whose color we accent with QRAuth green).
 */
function isFinderInnerModule(row: number, col: number, size: number): boolean {
  // Top-left inner: rows 2–4, cols 2–4
  if (row >= 2 && row <= 4 && col >= 2 && col <= 4) return true;
  // Top-right inner
  const tr = size - 5;
  if (row >= 2 && row <= 4 && col >= tr && col <= tr + 2) return true;
  // Bottom-left inner
  const bl = size - 5;
  if (row >= bl && row <= bl + 2 && col >= 2 && col <= 4) return true;
  return false;
}

// Center positions of the three finder patterns (in module coordinates)
function finderCenters(size: number): Array<[number, number]> {
  return [
    [3, 3],
    [3, size - 4],
    [size - 4, 3],
  ];
}

// ---------------------------------------------------------------------------
// AnimatedQRRenderer
// ---------------------------------------------------------------------------

const DEFAULT_TRUST_STATE: TrustState = {
  pulseSpeed: 1.0,
  hueShift: 0,
  distortionLevel: 0,
  dissolveProgress: 0,
};

export class AnimatedQRRenderer {
  // --- config ---
  private readonly canvas: HTMLCanvasElement;
  private readonly ctx: CanvasRenderingContext2D;
  private readonly dpr: number;
  private readonly cssSize: number;
  private readonly frameInterval: number;
  private readonly onFrame?: (payload: FramePayload) => void;

  // --- subsystems ---
  private readonly signer: FrameSigner;

  // --- state ---
  private theme: 'light' | 'dark';
  private trustState: TrustState;
  private running = false;
  private frozen = false;
  private lastPayload: FramePayload | null = null;
  private readonly onFreeze?: (lastFrame: FramePayload | null) => void;

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

  // --- cached color components for fast lerp ---
  private darkRGB: [number, number, number] = [0, 0, 0];
  private lightRGB: [number, number, number] = [255, 255, 255];
  private innerRGB: [number, number, number] = [0, 167, 111];

  constructor(options: AnimatedQROptions) {
    this.canvas = options.canvas;
    this.cssSize = options.size;
    this.frameInterval = options.frameInterval ?? 1000;
    this.theme = options.theme ?? 'light';
    this.trustState = { ...DEFAULT_TRUST_STATE, ...options.trustState };
    this.onFrame = options.onFrame;
    this.onFreeze = options.onFreeze;

    const ctx = options.canvas.getContext('2d');
    if (!ctx) throw new Error('AnimatedQRRenderer: could not get 2d context');
    this.ctx = ctx;

    this.dpr = typeof window !== 'undefined' ? (window.devicePixelRatio || 1) : 1;

    this.signer = new FrameSigner({
      baseUrl: options.baseUrl,
      frameSecret: options.frameSecret,
    });

    this.applyTheme();
  }

  // ---------------------------------------------------------------------------
  // Public API
  // ---------------------------------------------------------------------------

  async start(): Promise<void> {
    if (this.running) return;
    this.running = true;
    this.startTime = performance.now();

    // Pause rendering when canvas scrolls off-screen
    if (typeof IntersectionObserver !== 'undefined') {
      this.observer = new IntersectionObserver(
        ([entry]) => { this.visible = entry.isIntersecting; },
        { threshold: 0 },
      );
      this.observer.observe(this.canvas);
    }

    await Promise.all([this.signer.init(), initEncoder()]);
    if (!this.running) return;

    await this.rotateFrame();
    if (!this.running) return;

    this.scheduleNextFrame();
    this.rafId = requestAnimationFrame(this.renderLoop);
  }

  stop(): void {
    this.running = false;
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

  /**
   * Freeze the renderer — stops animation but keeps the last frame visible.
   * Use when the QR has been scanned and no longer needs to rotate.
   * The canvas retains the last rendered frame as a static image.
   */
  freeze(): void {
    if (!this.running || this.frozen) return;
    this.frozen = true;
    this.running = false;

    if (this.rafId !== null) {
      cancelAnimationFrame(this.rafId);
      this.rafId = null;
    }
    if (this.frameTimerId !== null) {
      clearTimeout(this.frameTimerId);
      this.frameTimerId = null;
    }
    // Keep observer alive so we don't waste memory, but disconnect
    if (this.observer) {
      this.observer.disconnect();
      this.observer = null;
    }

    this.onFreeze?.(this.lastPayload);
  }

  /** Current renderer lifecycle status. */
  get status(): RendererStatus {
    if (this.frozen) return 'frozen';
    if (this.running) return 'running';
    if (this.currentMatrix) return 'stopped';
    return 'idle';
  }

  /** Total frames generated since start. */
  get frameCount(): number {
    return this.lastPayload?.frameIndex ?? 0;
  }

  setTrustState(state: Partial<TrustState>): void {
    this.trustState = { ...this.trustState, ...state };
    this.needsRedraw = true;
  }

  setTheme(theme: 'light' | 'dark'): void {
    this.theme = theme;
    this.applyTheme();
  }

  // ---------------------------------------------------------------------------
  // Theme setup
  // ---------------------------------------------------------------------------

  private applyTheme(): void {
    const t = THEMES[this.theme];
    this.darkRGB = hexToRGB(t.module);
    this.lightRGB = hexToRGB(t.moduleLight);
    this.innerRGB = hexToRGB(t.finderInner);

    // Size the canvas
    const physSize = Math.round(this.cssSize * this.dpr);
    this.canvas.width = physSize;
    this.canvas.height = physSize;
    this.canvas.style.width = `${this.cssSize}px`;
    this.canvas.style.height = `${this.cssSize}px`;
  }

  // ---------------------------------------------------------------------------
  // Frame rotation (Layer 1)
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
      // Frame generation failed — log so it's diagnosable
      console.error('[animated-qr] Frame generation failed:', err);
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
      // First frame or size change — allocate fresh state
      this.moduleState = allocModuleState(size);
      this.precomputeStaticFields(size);

      // Initialise all modules to their final state immediately (no transition
      // on the very first frame so we don't start with a blank canvas)
      for (let r = 0; r < size; r++) {
        for (let c = 0; c < size; c++) {
          const idx = r * size + c;
          this.moduleState.isDark[idx] = newMatrix.modules[r][c] ? 1 : 0;
          this.moduleState.progress[idx] = 1;
        }
      }
    } else {
      // Diff against current matrix — trigger transitions only for changed modules
      const state = this.moduleState;
      const prev = this.currentMatrix!;

      for (let r = 0; r < size; r++) {
        for (let c = 0; c < size; c++) {
          const idx = r * size + c;
          const newDark = newMatrix.modules[r][c] ? 1 : 0;

          if (state.isDark[idx] !== newDark) {
            // Stagger delay: modules further from center start later (ripple)
            const dist = state.distFromCenter[idx];
            const delay = dist * size * 15; // up to ~15*size ms for edge modules

            // Record transition start with delay offset
            state.transitionStart[idx] = now + delay;
            // progress tracks 0→1 from the *old* state to the new state
            state.progress[idx] = 0;
            state.isDark[idx] = newDark;
          }
          // If unchanged, progress stays at 1 (fully settled)
        }
      }
      void prev; // suppress unused warning
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
  // Render loop (adaptive — 60fps during transitions, ~15fps idle)
  // ---------------------------------------------------------------------------

  private renderLoop = (now: number): void => {
    if (!this.running) return;

    // Skip drawing entirely if off-screen
    if (!this.visible) {
      this.rafId = requestAnimationFrame(this.renderLoop);
      return;
    }

    // Throttle: 60fps when transitions active, ~15fps otherwise
    const dt = now - this.lastDrawTime;
    const hasActiveTransitions = this.needsRedraw;
    const minInterval = hasActiveTransitions ? 0 : 60; // ~15fps idle

    if (dt >= minInterval) {
      this.draw(now);
      this.lastDrawTime = now;
    }

    this.rafId = requestAnimationFrame(this.renderLoop);
  };

  private draw(now: number): void {
    if (!this.currentMatrix || !this.moduleState) return;

    const { ctx, dpr, cssSize } = this;
    const phys = Math.round(cssSize * dpr);
    const matrix = this.currentMatrix;
    const state = this.moduleState;
    const { size } = matrix;
    const elapsed = now - this.startTime;
    const trust = this.trustState;
    const theme = THEMES[this.theme];

    // Module size in physical pixels (including quiet zone)
    const totalModules = size + QUIET_ZONE * 2;
    const moduleSize = phys / totalModules;
    const quietPx = QUIET_ZONE * moduleSize;
    const radius = moduleSize * MODULE_RADIUS_RATIO;

    // --- 1. Background ---
    ctx.fillStyle = theme.bg;
    ctx.fillRect(0, 0, phys, phys);

    // --- 2. Quiet zone color wash ---
    this.drawColorWash(ctx, phys, quietPx, moduleSize * size, elapsed, theme);

    // --- 3. Ambient pulse rings (behind modules) ---
    this.drawPulseRings(ctx, phys, quietPx, moduleSize * size, elapsed, trust, theme);

    // --- 4. Finder pattern glows (behind modules) ---
    this.drawFinderGlows(ctx, size, moduleSize, quietPx, elapsed, trust, theme);

    // --- 5. Advance transition progress ---
    this.advanceTransitions(state, size, now);

    // --- 6. Draw modules ---
    this.drawModules(ctx, state, matrix, size, moduleSize, quietPx, radius, now, trust, theme);
  }

  // ---------------------------------------------------------------------------
  // Draw subsystems
  // ---------------------------------------------------------------------------

  private drawColorWash(
    ctx: CanvasRenderingContext2D,
    phys: number,
    quietPx: number,
    dataPx: number,
    elapsed: number,
    theme: Theme,
  ): void {
    // A barely-perceptible hue gradient sweeping across the quiet zone.
    // We only paint the four border strips, not the data area.
    const phase = (elapsed % WASH_PERIOD) / WASH_PERIOD; // 0→1 over 20s
    const angle = phase * Math.PI * 2;

    // Derive two subtle accent colors from the quiet zone base
    const [qr, qg, qb] = hexToRGB(theme.quietZone);
    const [ar, ag, ab] = hexToRGB(theme.finderInner);

    // Blend strength: very subtle, max 12%
    const blend = 0.06 + 0.06 * Math.sin(angle);
    const wr = Math.round(qr + (ar - qr) * blend);
    const wg = Math.round(qg + (ag - qg) * blend);
    const wb = Math.round(qb + (ab - qb) * blend);

    ctx.fillStyle = `rgb(${wr},${wg},${wb})`;

    // Top strip
    ctx.fillRect(0, 0, phys, quietPx);
    // Bottom strip
    ctx.fillRect(0, quietPx + dataPx, phys, quietPx);
    // Left strip (inner vertical only)
    ctx.fillRect(0, quietPx, quietPx, dataPx);
    // Right strip
    ctx.fillRect(quietPx + dataPx, quietPx, quietPx, dataPx);
  }

  private drawPulseRings(
    ctx: CanvasRenderingContext2D,
    _phys: number,
    quietPx: number,
    dataPx: number,
    elapsed: number,
    trust: TrustState,
    theme: Theme,
  ): void {
    const cx = quietPx + dataPx / 2;
    const cy = quietPx + dataPx / 2;
    const maxR = (dataPx / 2) * 1.1;

    const speed = trust.pulseSpeed;
    const period = RING_PERIOD / speed;

    for (let i = 0; i < PULSE_RING_COUNT; i++) {
      const phase = ((elapsed / period) + i / PULSE_RING_COUNT) % 1;
      const r = phase * maxR;
      if (r <= 0) continue;
      const opacity = (1 - phase) * 0.35; // fade as ring expands

      ctx.beginPath();
      ctx.arc(cx, cy, r, 0, Math.PI * 2);
      ctx.strokeStyle = theme.pulseColor.replace(
        /[\d.]+\)$/,
        `${opacity.toFixed(3)})`,
      );
      ctx.lineWidth = 1.5;
      ctx.stroke();
    }
  }

  private drawFinderGlows(
    ctx: CanvasRenderingContext2D,
    size: number,
    moduleSize: number,
    quietPx: number,
    elapsed: number,
    trust: TrustState,
    _theme: Theme,
  ): void {
    const speed = trust.pulseSpeed;
    const glowIntensity = 0.3 + 0.7 * Math.sin((elapsed * Math.PI) / (PULSE_PERIOD * speed));
    const clampedGlow = Math.max(0, Math.min(1, glowIntensity));

    const centers = finderCenters(size);
    for (const [fr, fc] of centers) {
      // Center of the inner 3×3 square in physical pixels
      const px = quietPx + fc * moduleSize + moduleSize / 2;
      const py = quietPx + fr * moduleSize + moduleSize / 2;

      const glowRadius = moduleSize * 3.5;
      if (glowRadius <= 0) continue;
      const grad = ctx.createRadialGradient(px, py, 0, px, py, glowRadius);

      // Parse glow color for alpha manipulation
      const alpha = clampedGlow * 0.6;
      const [r, g, b] = this.innerRGB;
      grad.addColorStop(0, `rgba(${r},${g},${b},${alpha.toFixed(3)})`);
      grad.addColorStop(0.4, `rgba(${r},${g},${b},${(alpha * 0.4).toFixed(3)})`);
      grad.addColorStop(1, `rgba(${r},${g},${b},0)`);

      ctx.fillStyle = grad;
      ctx.beginPath();
      ctx.arc(px, py, glowRadius, 0, Math.PI * 2);
      ctx.fill();
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
      if (p >= 1) continue; // already settled

      const elapsed = now - state.transitionStart[idx];

      if (elapsed > 2000) {
        state.progress[idx] = 1;
        continue;
      }

      if (elapsed < 0) {
        anyActive = true; // still waiting on delay
        continue;
      }

      const raw = elapsed / TRANSITION_DURATION;
      const newP = Math.min(1, easeOut(raw));
      state.progress[idx] = newP;
      if (newP < 1) anyActive = true;
    }

    // When all transitions settle, drop to idle framerate
    if (!anyActive) this.needsRedraw = false;
  }

  private drawModules(
    ctx: CanvasRenderingContext2D,
    state: ModuleStateArrays,
    _matrix: QRMatrix,
    size: number,
    moduleSize: number,
    quietPx: number,
    radius: number,
    _now: number,
    trust: TrustState,
    _theme: Theme,
  ): void {
    const [dr, dg, db] = this.darkRGB;
    const [lr, lg, lb] = this.lightRGB;
    const [ir, ig, ib] = this.innerRGB;

    // Hue shift ratio (0→1 from hueShift degrees — we cap input at 180 for safety)
    const hueRatio = Math.min(1, trust.hueShift / 180);

    const distortion = trust.distortionLevel;
    const dissolve = trust.dissolveProgress;

    // Pre-seed a cheap deterministic pseudo-random for dissolve/distortion
    // using module index as seed (no per-frame allocation)
    let seed = 0x9e3779b9;
    const rand = (idx: number): number => {
      let x = seed ^ (idx * 0x6c62272e);
      x ^= x >>> 16;
      x = Math.imul(x, 0x45d9f3b);
      x ^= x >>> 16;
      return (x >>> 0) / 0xffffffff;
    };

    // Advance seed per-frame so dissolve flickers
    seed ^= Math.round(_now) & 0xffff;

    for (let r = 0; r < size; r++) {
      for (let c = 0; c < size; c++) {
        const idx = r * size + c;

        // Dissolve: probabilistically skip drawing this module
        if (dissolve > 0 && rand(idx) < dissolve * 0.8) continue;

        const isDark = state.isDark[idx] === 1;
        const progress = state.progress[idx];
        const isFinder = state.isFinder[idx] === 1;
        const isInner = state.isFinderInner[idx] === 1;

        // Determine effective "dark" fraction (blending from old to new)
        // When progress=1, the module is fully in its new state.
        // When progress=0, it is still visually in the old state (inverted isDark).
        const darkFraction = isDark ? progress : 1 - progress;

        // Finder inner modules always use the accent color
        let fillR: number, fillG: number, fillB: number;
        if (isInner && darkFraction > 0.5) {
          // Blend from light toward inner accent color
          const t = (darkFraction - 0.5) * 2;
          fillR = Math.round(lr + (ir - lr) * t);
          fillG = Math.round(lg + (ig - lg) * t);
          fillB = Math.round(lb + (ib - lb) * t);
        } else {
          // Regular lerp between light and dark
          fillR = Math.round(lr + (dr - lr) * darkFraction);
          fillG = Math.round(lg + (dg - lg) * darkFraction);
          fillB = Math.round(lb + (db - lb) * darkFraction);
        }

        // Apply hue shift (only to dark modules — light stays white/near-white)
        if (hueRatio > 0 && darkFraction > 0.5) {
          [fillR, fillG, fillB] = applyHueShift(fillR, fillG, fillB, hueRatio);
        }

        // Position
        let px = quietPx + c * moduleSize;
        let py = quietPx + r * moduleSize;

        // Distortion: add position jitter (only for non-finder modules to preserve scannability)
        if (distortion > 0 && !isFinder) {
          const jitter = distortion * moduleSize * 0.18;
          px += (rand(idx + 0x1000) - 0.5) * jitter;
          py += (rand(idx + 0x2000) - 0.5) * jitter;
        }

        ctx.fillStyle = `rgb(${fillR},${fillG},${fillB})`;
        this.fillRoundedRect(ctx, px, py, moduleSize, moduleSize, radius);
      }
    }
  }

  // ---------------------------------------------------------------------------
  // Rounded rectangle (inline for perf — avoids repeated property lookups)
  // ---------------------------------------------------------------------------

  private fillRoundedRect(
    ctx: CanvasRenderingContext2D,
    x: number,
    y: number,
    w: number,
    h: number,
    r: number,
  ): void {
    ctx.beginPath();
    ctx.moveTo(x + r, y);
    ctx.lineTo(x + w - r, y);
    ctx.arcTo(x + w, y, x + w, y + r, r);
    ctx.lineTo(x + w, y + h - r);
    ctx.arcTo(x + w, y + h, x + w - r, y + h, r);
    ctx.lineTo(x + r, y + h);
    ctx.arcTo(x, y + h, x, y + h - r, r);
    ctx.lineTo(x, y + r);
    ctx.arcTo(x, y, x + r, y, r);
    ctx.closePath();
    ctx.fill();
  }
}
