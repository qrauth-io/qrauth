#!/usr/bin/env node
/**
 * Bundle script for @qrauth/cli.
 *
 * Produces a single self-contained `dist/index.js` executable. The workspace
 * packages `@qrauth/shared` and `@qrauth/node` are inlined into the bundle so
 * the CLI installs cleanly from npm with no workspace context (ADR-0002):
 *   - `@qrauth/shared` is not published — the CLI uses one function from it
 *     (`deriveCliVerificationCode`), so inlining is far simpler than publishing
 *     a whole package for it.
 *   - `@qrauth/node` is published, but bundling pins the exact code the CLI was
 *     built against and avoids any version drift.
 *
 * Both workspace packages have zero external npm dependencies, so inlining them
 * adds no transitive deps. The only runtime dependencies left external are the
 * public-npm packages `commander` and `qrcode`, declared in package.json.
 */
import * as esbuild from 'esbuild';
import { chmodSync, readFileSync } from 'node:fs';

const pkg = JSON.parse(readFileSync('./package.json', 'utf8'));

await esbuild.build({
  entryPoints: ['src/index.ts'],
  bundle: true,
  platform: 'node',
  format: 'esm',
  target: 'node20',
  outfile: 'dist/index.js',
  sourcemap: true,
  // Inline the workspace packages; keep public-npm deps + node builtins external.
  external: ['commander', 'qrcode'],
  // The shebang from src/index.ts is preserved by esbuild as the first line;
  // the banner adds only a version comment beneath it.
  banner: {
    js: `/* @qrauth/cli v${pkg.version} — https://qrauth.io */`,
  },
});

// npm sets the executable bit on `bin` targets at install time, but make the
// freshly built file runnable in-place too (npm pack tests, local runs).
chmodSync('dist/index.js', 0o755);

console.log(`Build complete: dist/index.js (ESM, @qrauth/shared + @qrauth/node inlined)`);
