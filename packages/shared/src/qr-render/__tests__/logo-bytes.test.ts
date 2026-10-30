// SPDX-License-Identifier: MIT
import { describe, expect, it } from 'vitest';

import { renderQr } from '../index.js';
import { LOGO_PNG_MAX_BYTES } from '../logo.js';
import { DEFAULT_STYLE } from '../style.js';
import { LOGO_PNG_BASE64, URL_28 } from './golden-cases.js';

const LOGO_STYLE = { ...DEFAULT_STYLE, logo: { kind: 'qrauth' as const } };
const PNG = Uint8Array.from(atob(LOGO_PNG_BASE64), (c) => c.charCodeAt(0));

/** A PNG signature followed by padding up to `length` bytes. */
function pngOfLength(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  bytes.set(PNG.subarray(0, 8));
  return bytes;
}

const render = (logoPng: unknown): string =>
  renderQr({ data: URL_28, style: LOGO_STYLE, logoPng: logoPng as Uint8Array }).svg;

describe('logo bytes', () => {
  it('embeds a PNG', () => {
    expect(render(PNG)).toContain('data:image/png;base64,');
  });

  it('accepts a Buffer (a Uint8Array subclass)', () => {
    expect(render(Buffer.from(PNG))).toContain('data:image/png;base64,');
  });

  it('accepts exactly LOGO_PNG_MAX_BYTES (1 MiB)', () => {
    expect(LOGO_PNG_MAX_BYTES).toBe(1024 * 1024);
    expect(() => render(pngOfLength(LOGO_PNG_MAX_BYTES))).not.toThrow();
  });

  it('rejects one byte more', () => {
    expect(() => render(pngOfLength(LOGO_PNG_MAX_BYTES + 1))).toThrow(/qr-render: logoPng is larger/);
  });

  it.each([
    ['SVG markup', new TextEncoder().encode('<svg onload="alert(1)"/>')],
    ['JPEG', Uint8Array.from([0xff, 0xd8, 0xff, 0xe0, 0, 0x10, 0x4a, 0x46, 0x49, 0x46])],
    ['empty', new Uint8Array(0)],
    ['truncated signature', PNG.subarray(0, 7)],
  ])('rejects %s', (_name, bytes) => {
    expect(() => render(bytes)).toThrow(/qr-render: logoPng is not a PNG/);
  });

  it.each([['a string', 'iVBORw0KGgo='], ['a plain array', [0x89, 0x50]], ['an ArrayBuffer', new ArrayBuffer(8)]])(
    'rejects %s',
    (_name, value) => {
      expect(() => render(value)).toThrow(/qr-render: logoPng must be a Uint8Array/);
    },
  );

  it('null and undefined still mean no logo bytes', () => {
    expect(renderQr({ data: URL_28, style: LOGO_STYLE, logoPng: null }).meta.notDrawn).toEqual(['logo']);
    expect(renderQr({ data: URL_28, style: LOGO_STYLE }).meta.notDrawn).toEqual(['logo']);
  });
});
