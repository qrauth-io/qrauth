import { esc, safeHttpHref } from './utils.js';
import type { RenderContext } from './index.js';

const DO_NOT_PROCEED = `<div style="display:block;width:100%;padding:14px;background:rgba(244,63,94,0.08);border:1px solid rgba(244,63,94,0.22);color:#B91C1C;border-radius:12px;font-size:15px;font-weight:600;text-align:center;">Do not proceed - this QR code is not verified</div>`;

function continueButton(href: string, host: string, background: string): string {
  return `<a href="${esc(href)}" rel="noopener" style="display:block;width:100%;padding:14px;background:${background};color:#ffffff;border:none;border-radius:12px;font-size:16px;font-weight:700;text-align:center;text-decoration:none;letter-spacing:-0.3px;">Continue to ${esc(host)}</a>`;
}

function renderUrlContent(ctx: RenderContext): string {
  const { qrCode, trustState } = ctx;

  // Only http(s) destinations are rendered as links.
  const href = safeHttpHref(qrCode.destinationUrl);
  const destinationHostname = href ? new URL(href).hostname : qrCode.destinationUrl;

  const destinationBlock = href
    ? `<a href="${esc(href)}" rel="noopener" style="display:block;padding:12px 16px;background:#FAFAF9;border:1px solid rgba(15,15,15,0.08);border-radius:10px;color:#4F46E5;text-decoration:none;font-size:14px;word-break:break-all;">${esc(href)}</a>`
    : `<div style="display:block;padding:12px 16px;background:#FAFAF9;border:1px solid rgba(15,15,15,0.08);border-radius:10px;color:#525252;font-size:14px;word-break:break-all;">${esc(qrCode.destinationUrl)}</div>`;

  let action = DO_NOT_PROCEED;
  if (href && trustState === 'VERIFIED') {
    action = continueButton(href, destinationHostname, '#047857');
  } else if (href && trustState === 'SIGNED_UNVERIFIED_ISSUER') {
    // Issuer unknown: put the host the scanner is about to visit front and
    // centre, and keep the button neutral.
    action = `
    <div data-destination-host style="margin-bottom:12px;padding:14px 16px;background:#F8FAFC;border:1px solid rgba(100,116,139,0.25);border-radius:12px;text-align:center;">
      <div style="font-size:11px;text-transform:uppercase;color:#64748B;font-weight:600;letter-spacing:0.5px;margin-bottom:4px;">You are about to visit</div>
      <div style="font-size:20px;font-weight:800;color:#0F172A;word-break:break-all;">${esc(destinationHostname)}</div>
    </div>
    ${continueButton(href, destinationHostname, '#334155')}`;
  }

  return `
    ${qrCode.label ? `
    <div style="margin-bottom:16px;">
      <div style="font-size:18px;font-weight:700;color:#0A0A0A;">${esc(qrCode.label)}</div>
    </div>` : ''}

    <div style="margin-bottom:20px;">
      <div style="font-size:11px;text-transform:uppercase;color:#737373;font-weight:600;letter-spacing:0.5px;margin-bottom:6px;">Destination</div>
      ${destinationBlock}
    </div>

    ${action}
  `;
}

export default renderUrlContent;
