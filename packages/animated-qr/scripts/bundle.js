import * as esbuild from 'esbuild';

// IIFE bundle for <script> tag usage
await esbuild.build({
  entryPoints: ['src/index.ts'],
  bundle: true,
  minify: true,
  sourcemap: true,
  target: 'es2020',
  format: 'iife',
  globalName: 'QRAuthAnimatedQR',
  outfile: 'dist/animated-qr.js',
});

// ESM bundle for import usage
await esbuild.build({
  entryPoints: ['src/index.ts'],
  bundle: true,
  minify: true,
  sourcemap: true,
  target: 'es2020',
  format: 'esm',
  outfile: 'dist/animated-qr.esm.js',
});

console.log('Build complete: dist/animated-qr.js (IIFE) + dist/animated-qr.esm.js (ESM)');
