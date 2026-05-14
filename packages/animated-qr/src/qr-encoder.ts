/**
 * QR Code Encoder — wraps the battle-tested `qrcode` library.
 *
 * Uses dynamic import() to handle all module shapes Vite/Node/esbuild
 * might produce. The create() function is resolved once and cached.
 */

import type { QRCode as QRCodeResult } from 'qrcode';

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export interface QRMatrix {
  /** 2D array: true = dark module, false = light module */
  modules: boolean[][];
  /** Size of the matrix (modules.length) */
  size: number;
  /** QR version used */
  version: number;
}

// Cached create function, resolved on first use
type CreateFn = (data: string, opts: { errorCorrectionLevel: string }) => QRCodeResult;
let _create: CreateFn | null = null;

/**
 * Initialize the encoder by resolving the qrcode module.
 * Must be called (and awaited) before encodeQR().
 */
export async function initEncoder(): Promise<void> {
  if (_create) return;

  const mod: Record<string, unknown> = await import('qrcode');

  // Handle every module shape:
  //   Named export  → mod.create        (qrcode browser build via Vite)
  //   Default obj   → mod.default.create (CJS wrapped in ESM default)
  //   Direct default → mod.default       (unlikely, but safe)
  if (typeof mod.create === 'function') {
    _create = mod.create as CreateFn;
  } else {
    const def = mod.default as Record<string, unknown> | undefined;
    if (def && typeof def.create === 'function') {
      _create = def.create as CreateFn;
    }
  }

  if (!_create) {
    console.error('[animated-qr] qrcode module keys:', Object.keys(mod));
    throw new Error('qrcode: cannot resolve create()');
  }
}

/**
 * Encode data into a QR code matrix (synchronous — requires initEncoder() first).
 */
export function encodeQR(data: string): QRMatrix {
  if (!_create) {
    throw new Error('Encoder not initialized — call initEncoder() first');
  }
  return toMatrix(_create(data, { errorCorrectionLevel: 'M' }));
}

/**
 * Async convenience — initializes on first call.
 */
export async function encodeQRAsync(data: string): Promise<QRMatrix> {
  await initEncoder();
  return encodeQR(data);
}

function toMatrix(qr: QRCodeResult): QRMatrix {
  const size = qr.modules.size;
  const flat = qr.modules.data;
  const modules: boolean[][] = [];

  for (let r = 0; r < size; r++) {
    const row: boolean[] = [];
    for (let c = 0; c < size; c++) {
      row.push(flat[r * size + c] === 1);
    }
    modules.push(row);
  }

  return { modules, size, version: qr.version };
}
