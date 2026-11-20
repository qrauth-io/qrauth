/**
 * Shared interface for all AnimatedQR renderers.
 *
 * Both Canvas 2D and CanvasKit (Skia WASM) renderers implement this
 * interface, allowing benchmarks and the public API to swap them.
 */

import type { FramePayload } from './frame-signer.js';

export interface TrustState {
  pulseSpeed: number;
  hueShift: number;
  distortionLevel: number;
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
  onFreeze?: (lastFrame: FramePayload | null) => void;
}

export type RendererStatus = 'idle' | 'running' | 'frozen' | 'stopped';

export interface IAnimatedQRRenderer {
  start(): Promise<void>;
  stop(): void;
  freeze(): void;
  setTrustState(state: Partial<TrustState>): void;
  setTheme(theme: 'light' | 'dark'): void;
  readonly status: RendererStatus;
  readonly frameCount: number;
}
