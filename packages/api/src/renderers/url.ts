import { esc } from './utils.js';
import type { RenderContext } from './index.js';

function renderUrlContent(ctx: RenderContext): string {
  const { qrCode, verified } = ctx;

  let destinationHostname = qrCode.destinationUrl;
  try { destinationHostname = new URL(qrCode.destinationUrl).hostname; } catch { /* keep full url */ }

  return `
    ${qrCode.label ? `
    <div style="margin-bottom:16px;">
      <div style="font-size:18px;font-weight:700;color:#F8FAFC;">${esc(qrCode.label)}</div>
    </div>` : ''}

    <div style="margin-bottom:20px;">
      <div style="font-size:11px;text-transform:uppercase;color:rgba(248,250,252,0.35);font-weight:600;letter-spacing:0.5px;margin-bottom:6px;">Destination</div>
      <a href="${esc(qrCode.destinationUrl)}" rel="noopener" style="display:block;padding:12px 16px;background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.06);border-radius:10px;color:#60A5FA;text-decoration:none;font-size:14px;word-break:break-all;">${esc(qrCode.destinationUrl)}</a>
    </div>

    ${verified
      ? `<a href="${esc(qrCode.destinationUrl)}" rel="noopener" style="display:block;width:100%;padding:14px;background:#00A76F;color:#081b4c;border:none;border-radius:12px;font-size:16px;font-weight:700;text-align:center;text-decoration:none;letter-spacing:-0.3px;">Continue to ${esc(destinationHostname)}</a>`
      : `<div style="display:block;width:100%;padding:14px;background:rgba(255,86,48,0.15);border:1px solid rgba(255,86,48,0.2);color:#FF8A65;border-radius:12px;font-size:15px;font-weight:600;text-align:center;">Do not proceed \u2014 this QR code is not verified</div>`
    }
  `;
}

export default renderUrlContent;
