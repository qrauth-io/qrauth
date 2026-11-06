#!/usr/bin/env node
/**
 * Bundle script for @qrauth/web-components
 * Produces:
 *   dist/qrauth-components.js      — IIFE for CDN <script> tag
 *   dist/qrauth-components.esm.js  — ESM for bundlers / <script type="module">
 */

import * as esbuild from 'esbuild';
import { readFileSync } from 'fs';

const pkg = JSON.parse(readFileSync('./package.json', 'utf8'));

const sharedOptions = {
  entryPoints: ['src/index.ts'],
  bundle: true,
  minify: true,
  target: 'es2020',
  sourcemap: true,
};

// IIFE — for <script src="...qrauth-components.js"></script>
await esbuild.build({
  ...sharedOptions,
  format: 'iife',
  globalName: 'QRAuthComponents',
  outfile: 'dist/qrauth-components.js',
  banner: {
    js: `/* @qrauth/web-components v${pkg.version} — https://qrauth.io */`,
  },
});

// ESM — for <script type="module"> and bundlers
await esbuild.build({
  ...sharedOptions,
  format: 'esm',
  outfile: 'dist/qrauth-components.esm.js',
  banner: {
    js: `/* @qrauth/web-components v${pkg.version} — https://qrauth.io */`,
  },
});

console.log('Build complete: dist/qrauth-components.js (IIFE) + dist/qrauth-components.esm.js (ESM)');
