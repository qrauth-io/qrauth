import { esc } from './utils.js';
import type { ScanMode } from '../services/scan-mode.js';
import { FLASH_SCRIPT } from '../lib/flash-script.js';

/**
 * Trust flash for VERIFIED URL codes (scan mode FLASH).
 *
 * The page is the full verification page. The flash only adds hooks to it:
 * a data attribute carrying the destination on the reveal overlay, the
 * external script /sdk/verify-flash.<hash>.js (lib/flash-script.ts; allowed
 * by script-src 'self'; no inline script), and CSS that applies only once
 * that script has added the `flash` class. The script shortens the reveal to
 * about 0.6 s and then replaces the page with the destination. Every flash
 * animation below ends within 0.45 s. Without JavaScript the page reads
 * exactly like the PAGE mode.
 */

export const FLASH_SCRIPT_PATH = FLASH_SCRIPT.path;

export interface FlashParts {
  /** Attribute string for the #trust-reveal element (leading space). */
  revealAttrs: string;
  /** `<script>` tag for <head>. */
  headScript: string;
  /** Extra CSS, inserted into the nonced <style> block. */
  css: string;
  /** Line under the issuer in the reveal. */
  continueLine: string;
}

const NO_FLASH: FlashParts = { revealAttrs: '', headScript: '', css: '', continueLine: '' };

export function buildFlashParts(
  scanMode: ScanMode | undefined,
  destinationUrl: string,
  trustColor: string,
): FlashParts {
  if (scanMode !== 'FLASH') return NO_FLASH;

  let url: URL;
  try {
    url = new URL(destinationUrl);
  } catch {
    return NO_FLASH;
  }
  if (url.protocol !== 'https:') return NO_FLASH;

  return {
    revealAttrs: ` data-flash-href="${esc(url.href)}"`,
    headScript: `<script src="${FLASH_SCRIPT_PATH}" defer></script>`,
    continueLine: `<div class="reveal-continue">Continuing to ${esc(url.hostname)}</div>`,
    css: `
    /* Trust flash: active only after verify-flash.js adds .flash */
    .reveal-continue { display: none; }
    /* Opaque: a tint over solid white, so the page never shows through. */
    .trust-reveal.flash {
      animation: none;
      opacity: 1;
      pointer-events: auto;
      background: linear-gradient(${trustColor}22, ${trustColor}22), #FFFFFF;
    }
    .trust-reveal.flash .trust-reveal-inner { animation: flash-content 0.3s ease-out forwards; }
    @keyframes flash-content {
      from { transform: scale(0.9); opacity: 0; }
      to   { transform: scale(1);   opacity: 1; }
    }
    .trust-reveal.flash .reveal-shield { animation-duration: 0.3s; }
    .trust-reveal.flash .reveal-status { animation-duration: 0.25s; animation-delay: 0.1s; }
    .trust-reveal.flash .reveal-org { animation-duration: 0.25s; animation-delay: 0.15s; margin-bottom: 12px; }
    .trust-reveal.flash .reveal-fingerprint { display: none; }
    .trust-reveal.flash .reveal-continue {
      display: block;
      font-size: 14px;
      color: #525252;
      opacity: 0;
      animation: reveal-fade-up 0.25s ease-out 0.2s forwards;
    }
    @media (prefers-reduced-motion: reduce) {
      .trust-reveal.flash { animation: none; opacity: 1; pointer-events: auto; }
      .trust-reveal.flash .reveal-continue { animation: none; opacity: 1; }
    }`,
  };
}
