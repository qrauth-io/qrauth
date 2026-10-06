/**
 * Generates cryptographically signed frame payloads for animated QR codes.
 * Uses Web Crypto API (SubtleCrypto) — works in all modern browsers.
 */

export interface FramePayload {
  /** Full URL to encode in QR code */
  url: string;
  /** Frame index (monotonically increasing) */
  frameIndex: number;
  /** Timestamp in ms */
  timestamp: number;
  /** Hex-encoded HMAC */
  hmac: string;
}

export interface FrameSignerOptions {
  /** Base verification URL, e.g. "https://qrauth.io/v/AbCdEfGh" */
  baseUrl: string;
  /** Per-session frame secret (hex string, received from server) */
  frameSecret: string;
}

export class FrameSigner {
  private key: CryptoKey | null = null;
  private frameIndex = 0;
  private baseUrl: string;
  private frameSecretHex: string;

  constructor(options: FrameSignerOptions) {
    this.baseUrl = options.baseUrl;
    this.frameSecretHex = options.frameSecret;
  }

  /** Initialize the HMAC key. Call once before generateFrame(). */
  async init(): Promise<void> {
    const keyBytes = hexToBytes(this.frameSecretHex);
    this.key = await crypto.subtle.importKey(
      'raw',
      keyBytes.buffer as ArrayBuffer,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign'],
    );
  }

  /** Generate the next frame payload. */
  async generateFrame(): Promise<FramePayload> {
    if (!this.key) throw new Error('FrameSigner not initialized. Call init() first.');

    const frameIndex = this.frameIndex++;
    const timestamp = Date.now();

    // HMAC input: baseUrl + ":" + timestamp + ":" + frameIndex
    const message = `${this.baseUrl}:${timestamp}:${frameIndex}`;
    const encoder = new TextEncoder();
    const signature = await crypto.subtle.sign('HMAC', this.key, encoder.encode(message));
    const hmac = bytesToHex(new Uint8Array(signature)).slice(0, 16); // First 8 bytes (16 hex chars) for compact QR

    // Build the full URL for the QR code
    const url = `${this.baseUrl}?f=${frameIndex}&t=${timestamp}&h=${hmac}`;

    return { url, frameIndex, timestamp, hmac };
  }

  /** Reset frame counter (e.g., when starting a new display session). */
  reset(): void {
    this.frameIndex = 0;
  }
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}
