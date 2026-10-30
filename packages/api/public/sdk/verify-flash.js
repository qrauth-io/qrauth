/*
 * QRAuth verification page: trust flash (scan mode FLASH).
 *
 * Loaded only on VERIFIED https URL codes whose issuer left quick redirect
 * on. Shortens the trust reveal to about 0.6 s, then replaces the page with
 * the destination, so Back returns to wherever the scan started. Served from
 * 'self' because the verify page CSP allows no inline script beyond its
 * nonced blocks. Without JavaScript the full verification page is shown.
 */
(function () {
  'use strict';
  var FLASH_MS = 600;
  var reveal = document.getElementById('trust-reveal');
  if (!reveal) return;
  var href = reveal.getAttribute('data-flash-href');
  if (!href) return;
  var url;
  try {
    url = new URL(href);
  } catch (e) {
    return;
  }
  if (url.protocol !== 'https:') return;
  reveal.classList.add('flash');
  window.setTimeout(function () {
    window.location.replace(url.href);
  }, FLASH_MS);
})();
