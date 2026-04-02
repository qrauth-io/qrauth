import { esc } from './utils.js';
import type { RenderContext } from './index.js';

function renderUrlContent(ctx: RenderContext): string {
  const { qrCode, verified, locationMatch: loc } = ctx;

  let destinationHostname = qrCode.destinationUrl;
  try { destinationHostname = new URL(qrCode.destinationUrl).hostname; } catch { /* keep full url */ }

  return `
    ${qrCode.label ? `<div style="margin-bottom:16px;"><div style="font-size:11px;text-transform:uppercase;color:#919eab;font-weight:600;margin-bottom:4px;">Label</div><div style="font-size:15px;color:#212b36;">${esc(qrCode.label)}</div></div>` : ''}

    <div style="margin-bottom:16px;">
      <div style="font-size:11px;text-transform:uppercase;color:#919eab;font-weight:600;margin-bottom:4px;">Destination</div>
      <a href="${esc(qrCode.destinationUrl)}" rel="noopener" style="display:block;padding:12px 16px;background:#f8f9fa;border-radius:8px;color:#0D47A1;text-decoration:none;font-size:14px;word-break:break-all;">${esc(qrCode.destinationUrl)}</a>
    </div>

    ${loc.distanceM !== null ? `
    <div style="padding:12px 16px;background:${loc.matched ? '#E8F5E9' : '#FFF8E1'};border-radius:8px;font-size:13px;margin-bottom:16px;">
      ${loc.matched
        ? `&#128205; You are within the registered area (${loc.distanceM}m away)`
        : `&#128205; You are ${loc.distanceM}m from the registered location`
      }
    </div>
    ` : ''}

    ${verified
      ? `<a href="${esc(qrCode.destinationUrl)}" rel="noopener" style="display:block;width:100%;padding:14px;background:#00A76F;color:white;border:none;border-radius:10px;font-size:16px;font-weight:600;text-align:center;text-decoration:none;">Continue to ${esc(destinationHostname)}</a>`
      : `<div style="display:block;width:100%;padding:14px;background:#637381;color:white;border-radius:10px;font-size:16px;font-weight:600;text-align:center;">Do not proceed \u2014 this QR code is not verified</div>`
    }
  `;
}

export default renderUrlContent;
