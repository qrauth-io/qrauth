/**
 * Generate a deterministic abstract SVG from a hex seed.
 * Same seed always produces the same visual.
 *
 * The pattern is a crystalline/geometric arrangement of 7 shapes
 * placed on a 120x120 canvas, derived entirely from the seed bytes.
 */

const PALETTE = [
  '#60A5FA', // blue
  '#34D399', // green
  '#F472B6', // pink
  '#FBBF24', // amber
  '#A78BFA', // purple
  '#FB923C', // orange
  '#2DD4BF', // teal
  '#F87171', // red
];

/** Parse a 64-char hex string into an array of byte values (0-255). */
function hexToBytes(hex: string): number[] {
  const bytes: number[] = [];
  for (let i = 0; i < hex.length - 1; i += 2) {
    bytes.push(parseInt(hex.slice(i, i + 2), 16));
  }
  return bytes;
}

/** Map a byte value into [min, max] inclusive. */
function mapByte(byte: number, min: number, max: number): number {
  return min + Math.round((byte / 255) * (max - min));
}

/** Build a triangle polygon string centered at (cx, cy) with given radius and rotation. */
function trianglePoints(cx: number, cy: number, r: number, rotation: number): string {
  const pts: string[] = [];
  for (let i = 0; i < 3; i++) {
    const angle = rotation + (i * 2 * Math.PI) / 3;
    const x = (cx + r * Math.cos(angle)).toFixed(1);
    const y = (cy + r * Math.sin(angle)).toFixed(1);
    pts.push(`${x},${y}`);
  }
  return pts.join(' ');
}

/** Build a diamond (rotated square) polygon string. */
function diamondPoints(cx: number, cy: number, r: number): string {
  return `${cx},${cy - r} ${cx + r},${cy} ${cx},${cy + r} ${cx - r},${cy}`;
}

export function generateVisualFingerprint(seed: string): string {
  // Normalise: ensure exactly 64 hex chars; pad or truncate defensively
  const normalised = seed.replace(/[^0-9a-fA-F]/g, '').padEnd(64, '0').slice(0, 64);
  const bytes = hexToBytes(normalised);

  const shapes: string[] = [];
  const SHAPE_COUNT = 7;

  // We have 32 bytes available; each shape consumes 4 bytes
  // Byte layout per shape: [posX, posY, size, colorAndType]
  for (let i = 0; i < SHAPE_COUNT; i++) {
    const base = i * 4;
    const bx    = bytes[base]     ?? 128;
    const by    = bytes[base + 1] ?? 128;
    const bsize = bytes[base + 2] ?? 80;
    const btype = bytes[base + 3] ?? 0;

    // Position: keep shapes mostly inside the 120x120 viewport with padding
    const cx = mapByte(bx, 15, 105);
    const cy = mapByte(by, 15, 105);

    // Size: small-to-medium shapes for a layered crystalline feel
    const r = mapByte(bsize, 6, 22);

    // Color from palette
    const color = PALETTE[btype % PALETTE.length];

    // Opacity: alternate between more and less opaque for depth
    const opacity = (0.45 + (btype % 4) * 0.12).toFixed(2);

    // Shape type: 0-2 → circle, 3-4 → rounded rect, 5-6 → triangle, 7 → diamond
    const shapeType = btype % 8;

    let el: string;
    if (shapeType <= 2) {
      // Circle
      el = `<circle cx="${cx}" cy="${cy}" r="${r}" fill="${color}" opacity="${opacity}"/>`;
    } else if (shapeType <= 4) {
      // Rounded rectangle
      const w = r * 2;
      const h = mapByte(bsize, 8, 28);
      const rx2 = Math.round(r * 0.4);
      el = `<rect x="${cx - r}" y="${cy - Math.round(h / 2)}" width="${w}" height="${h}" rx="${rx2}" fill="${color}" opacity="${opacity}"/>`;
    } else if (shapeType <= 6) {
      // Triangle — rotation derived from a later byte
      const rotation = ((bytes[(base + 4) % bytes.length] ?? 0) / 255) * Math.PI * 2;
      el = `<polygon points="${trianglePoints(cx, cy, r, rotation)}" fill="${color}" opacity="${opacity}"/>`;
    } else {
      // Diamond
      el = `<polygon points="${diamondPoints(cx, cy, r)}" fill="${color}" opacity="${opacity}"/>`;
    }

    shapes.push(el);
  }

  // Add a subtle radial glow in the centre using the first two palette colours
  const glowColor1 = PALETTE[bytes[0] % PALETTE.length];
  const glowColor2 = PALETTE[bytes[1] % PALETTE.length];

  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 120 120" width="120" height="120" role="img" aria-label="Visual fingerprint">
  <defs>
    <radialGradient id="vfg" cx="50%" cy="50%" r="50%">
      <stop offset="0%" stop-color="${glowColor1}" stop-opacity="0.15"/>
      <stop offset="100%" stop-color="${glowColor2}" stop-opacity="0"/>
    </radialGradient>
  </defs>
  <rect width="120" height="120" rx="12" fill="rgba(255,255,255,0.04)"/>
  <ellipse cx="60" cy="60" rx="52" ry="52" fill="url(#vfg)"/>
  ${shapes.join('\n  ')}
</svg>`;
}
