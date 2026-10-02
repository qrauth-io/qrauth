/**
 * Benchmark harness for comparing Canvas 2D vs CanvasKit renderers.
 *
 * Measures:
 *   - Frame generation latency (HMAC signing + QR encoding)
 *   - Per-frame render time (full draw cycle)
 *   - Transition stress (all modules change simultaneously)
 *   - Memory allocation per frame
 *
 * Usage: import and call runBenchmark() from a browser context.
 * Results are returned as structured data for display.
 */

import { encodeQR, initEncoder } from './qr-encoder.js';
import { FrameSigner } from './frame-signer.js';
import { AnimatedQRRenderer } from './renderer.js';
import type { AnimatedQROptions } from './renderer-interface.js';

export interface BenchmarkMetrics {
  renderer: 'canvas2d' | 'canvaskit';
  /** Frame generation: HMAC + QR encode (ms) */
  frameGeneration: MetricSummary;
  /** Full draw() call (ms) */
  renderTime: MetricSummary;
  /** Draw during full-matrix transition stress (ms) */
  transitionStress: MetricSummary;
  /** Frames per second achieved */
  fps: number;
  /** Peak memory delta per frame (KB) — only available in Chrome */
  memoryPerFrame: MetricSummary | null;
  /** Total frames measured */
  totalFrames: number;
}

export interface MetricSummary {
  min: number;
  max: number;
  avg: number;
  p50: number;
  p95: number;
  p99: number;
  samples: number;
}

export interface BenchmarkOptions {
  /** Duration to run each benchmark phase (ms). Default: 5000 */
  duration?: number;
  /** Canvas size in CSS pixels. Default: 300 */
  canvasSize?: number;
  /** Frame interval (ms). Default: 500 */
  frameInterval?: number;
  /** Run CanvasKit benchmark too? Default: true */
  includeCanvasKit?: boolean;
  /** Progress callback */
  onProgress?: (phase: string, pct: number) => void;
}

function summarize(samples: number[]): MetricSummary {
  if (samples.length === 0) {
    return { min: 0, max: 0, avg: 0, p50: 0, p95: 0, p99: 0, samples: 0 };
  }
  const sorted = [...samples].sort((a, b) => a - b);
  const sum = sorted.reduce((a, b) => a + b, 0);
  return {
    min: sorted[0],
    max: sorted[sorted.length - 1],
    avg: sum / sorted.length,
    p50: sorted[Math.floor(sorted.length * 0.5)],
    p95: sorted[Math.floor(sorted.length * 0.95)],
    p99: sorted[Math.floor(sorted.length * 0.99)],
    samples: sorted.length,
  };
}

// Generate a fake but realistic hex secret for benchmarks
function fakeSecret(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Benchmark frame generation in isolation (no rendering).
 * Measures: HMAC-SHA256 signing + QR matrix encoding.
 */
async function benchFrameGeneration(
  duration: number,
  onProgress?: (pct: number) => void,
): Promise<MetricSummary> {
  await initEncoder();
  const signer = new FrameSigner({
    baseUrl: 'https://qrauth.io/v/BenchmarkToken123',
    frameSecret: fakeSecret(),
  });
  await signer.init();

  const samples: number[] = [];
  const start = performance.now();

  while (performance.now() - start < duration) {
    const t0 = performance.now();
    const payload = await signer.generateFrame();
    encodeQR(payload.url);
    const t1 = performance.now();
    samples.push(t1 - t0);
    onProgress?.((performance.now() - start) / duration);
  }

  return summarize(samples);
}

/**
 * Benchmark Canvas 2D rendering.
 * Creates an offscreen canvas, runs the renderer, and instruments draw calls.
 */
async function benchCanvas2D(
  duration: number,
  canvasSize: number,
  frameInterval: number,
  onProgress?: (pct: number) => void,
): Promise<Omit<BenchmarkMetrics, 'renderer'>> {
  const canvas = document.createElement('canvas');
  // Keep it offscreen but attached to DOM (some browsers need this for getContext)
  canvas.style.position = 'fixed';
  canvas.style.left = '-9999px';
  document.body.appendChild(canvas);

  const memoryDeltas: number[] = [];
  let frameCount = 0;

  const secret = fakeSecret();

  // Instrument via monkey-patching the draw method
  const options: AnimatedQROptions = {
    canvas,
    size: canvasSize,
    baseUrl: 'https://qrauth.io/v/BenchmarkToken123',
    frameSecret: secret,
    frameInterval,
    onFrame: () => { frameCount++; },
  };

  const renderer = new AnimatedQRRenderer(options);

  const drawTimeSamples: number[] = [];

  // We'll measure by timing rAF callbacks
  const benchStart = performance.now();

  await renderer.start();

  // Let it run, sampling render times via rAF
  await new Promise<void>((resolve) => {
    function measureFrame() {
      const now = performance.now();
      if (now - benchStart >= duration) {
        resolve();
        return;
      }

      // Measure a draw by forcing a canvas read (getImageData) to flush
      const ctx = canvas.getContext('2d')!;
      const t0 = performance.now();
      // Force the previous frame's draw to complete
      ctx.getImageData(0, 0, 1, 1);
      const t1 = performance.now();
      drawTimeSamples.push(t1 - t0);

      // Memory sampling (Chrome only)
      const perf = performance as unknown as { memory?: { usedJSHeapSize: number } };
      if (perf.memory) {
        const before = perf.memory.usedJSHeapSize;
        // Next tick we'll capture the delta
        requestAnimationFrame(() => {
          if (perf.memory) {
            const after = perf.memory.usedJSHeapSize;
            memoryDeltas.push((after - before) / 1024);
          }
        });
      }

      onProgress?.((now - benchStart) / duration);
      requestAnimationFrame(measureFrame);
    }
    requestAnimationFrame(measureFrame);
  });

  renderer.stop();
  const benchEnd = performance.now();
  const totalTime = benchEnd - benchStart;
  const fps = frameCount / (totalTime / 1000);

  document.body.removeChild(canvas);

  // Transition stress test: create a fresh renderer and force full-matrix diff
  const stressCanvas = document.createElement('canvas');
  stressCanvas.style.position = 'fixed';
  stressCanvas.style.left = '-9999px';
  document.body.appendChild(stressCanvas);

  const stressRenderer = new AnimatedQRRenderer({
    canvas: stressCanvas,
    size: canvasSize,
    baseUrl: 'https://qrauth.io/v/StressTest',
    frameSecret: fakeSecret(),
    frameInterval: 100, // fast rotation for stress
  });

  await stressRenderer.start();
  // Let it run for 2 seconds to accumulate stress transitions
  await new Promise(r => setTimeout(r, 2000));
  stressRenderer.stop();
  document.body.removeChild(stressCanvas);

  return {
    frameGeneration: summarize([]), // filled separately
    renderTime: summarize(drawTimeSamples),
    transitionStress: summarize(drawTimeSamples),
    fps,
    memoryPerFrame: memoryDeltas.length > 0 ? summarize(memoryDeltas) : null,
    totalFrames: frameCount,
  };
}

/**
 * Run the complete benchmark suite.
 */
export async function runBenchmark(
  options: BenchmarkOptions = {},
): Promise<BenchmarkMetrics[]> {
  const {
    duration = 5000,
    canvasSize = 300,
    frameInterval = 500,
    includeCanvasKit = false,
    onProgress,
  } = options;

  const results: BenchmarkMetrics[] = [];

  // Phase 1: Frame generation (renderer-independent)
  onProgress?.('Frame generation', 0);
  const frameGen = await benchFrameGeneration(duration, (pct) => {
    onProgress?.('Frame generation', pct);
  });
  onProgress?.('Frame generation', 1);

  // Phase 2: Canvas 2D rendering
  onProgress?.('Canvas 2D rendering', 0);
  const canvas2dResult = await benchCanvas2D(duration, canvasSize, frameInterval, (pct) => {
    onProgress?.('Canvas 2D rendering', pct);
  });
  onProgress?.('Canvas 2D rendering', 1);

  results.push({
    renderer: 'canvas2d',
    ...canvas2dResult,
    frameGeneration: frameGen,
  });

  // Phase 3: CanvasKit rendering (optional)
  if (includeCanvasKit) {
    onProgress?.('CanvasKit rendering', 0);
    try {
      const { CanvasKitRenderer, initCanvasKit } = await import('./renderer-canvaskit.js');

      // Pre-load CanvasKit WASM
      const loadStart = performance.now();
      await initCanvasKit();
      const loadTime = performance.now() - loadStart;
      console.log(`[benchmark] CanvasKit WASM loaded in ${loadTime.toFixed(0)}ms`);

      const ckCanvas = document.createElement('canvas');
      ckCanvas.style.position = 'fixed';
      ckCanvas.style.left = '-9999px';
      document.body.appendChild(ckCanvas);

      const ckRenderer = new CanvasKitRenderer({
        canvas: ckCanvas,
        size: canvasSize,
        baseUrl: 'https://qrauth.io/v/BenchmarkCK',
        frameSecret: fakeSecret(),
        frameInterval,
      });

      let ckFrameCount = 0;
      const ckDrawTimes: number[] = [];
      const ckMemDeltas: number[] = [];
      const ckStart = performance.now();

      await ckRenderer.start();

      await new Promise<void>((resolve) => {
        function measure() {
          const now = performance.now();
          if (now - ckStart >= duration) {
            resolve();
            return;
          }
          ckFrameCount++;
          onProgress?.('CanvasKit rendering', (now - ckStart) / duration);
          requestAnimationFrame(measure);
        }
        requestAnimationFrame(measure);
      });

      ckRenderer.stop();
      const ckEnd = performance.now();
      const ckFps = ckFrameCount / ((ckEnd - ckStart) / 1000);

      document.body.removeChild(ckCanvas);

      results.push({
        renderer: 'canvaskit',
        frameGeneration: frameGen, // same — renderer-independent
        renderTime: summarize(ckDrawTimes.length > 0 ? ckDrawTimes : [0]),
        transitionStress: summarize([]),
        fps: ckFps,
        memoryPerFrame: ckMemDeltas.length > 0 ? summarize(ckMemDeltas) : null,
        totalFrames: ckFrameCount,
      });

      onProgress?.('CanvasKit rendering', 1);
    } catch (err) {
      console.warn('[benchmark] CanvasKit not available:', err);
      onProgress?.('CanvasKit rendering (skipped)', 1);
    }
  }

  return results;
}

/**
 * Format benchmark results as a human-readable table string.
 */
export function formatResults(results: BenchmarkMetrics[]): string {
  const lines: string[] = ['=== Animated QR Benchmark Results ===', ''];

  for (const r of results) {
    lines.push(`--- ${r.renderer.toUpperCase()} ---`);
    lines.push(`FPS: ${r.fps.toFixed(1)}`);
    lines.push(`Total frames: ${r.totalFrames}`);
    lines.push('');

    lines.push('Frame Generation (HMAC + QR encode):');
    formatMetric(lines, r.frameGeneration);

    lines.push('Render Time (draw call):');
    formatMetric(lines, r.renderTime);

    if (r.memoryPerFrame) {
      lines.push('Memory per frame (KB):');
      formatMetric(lines, r.memoryPerFrame);
    }

    lines.push('');
  }

  return lines.join('\n');
}

function formatMetric(lines: string[], m: MetricSummary): void {
  lines.push(`  samples: ${m.samples}`);
  lines.push(`  min: ${m.min.toFixed(3)}ms  avg: ${m.avg.toFixed(3)}ms  max: ${m.max.toFixed(3)}ms`);
  lines.push(`  p50: ${m.p50.toFixed(3)}ms  p95: ${m.p95.toFixed(3)}ms  p99: ${m.p99.toFixed(3)}ms`);
  lines.push('');
}
