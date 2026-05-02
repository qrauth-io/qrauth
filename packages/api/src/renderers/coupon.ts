import { esc } from './utils.js';
import type { RenderContext } from './index.js';

function renderCouponContent(ctx: RenderContext): string {
  const c = ctx.qrCode.content as any;
  if (!c) return '<p>No coupon data.</p>';

  return `
    <style>
      .coupon-img { width: 100%; height: 180px; object-fit: cover; border-radius: 8px; margin-bottom: 16px; }
      .coupon-badge { display: inline-block; padding: 6px 16px; background: #FF5630; color: white; border-radius: 20px; font-weight: 700; font-size: 16px; margin-bottom: 12px; }
      .coupon-headline { font-size: 22px; font-weight: 800; color: #1B2A4A; margin-bottom: 4px; }
      .coupon-company { font-size: 14px; color: #637381; margin-bottom: 12px; }
      .coupon-desc { font-size: 14px; color: #637381; line-height: 1.6; margin-bottom: 16px; }
      .coupon-expiry { font-size: 13px; color: #FF5630; font-weight: 600; margin-bottom: 16px; }
      .coupon-terms { font-size: 11px; color: #919eab; line-height: 1.5; margin-top: 16px; padding-top: 12px; border-top: 1px solid #f0f0f0; }
      .coupon-cta { display: block; width: 100%; padding: 14px; background: #FF5630; color: white; border: none; border-radius: 10px; font-size: 16px; font-weight: 600; text-align: center; text-decoration: none; cursor: pointer; }
      .coupon-cta:hover { opacity: 0.9; }
    </style>

    <div style="text-align:center;">
      ${c.imageUrl ? `<img class="coupon-img" src="${esc(c.imageUrl)}" alt="" onerror="this.style.display='none'" />` : ''}
      ${c.discountBadge ? `<div class="coupon-badge">${esc(c.discountBadge)}</div>` : ''}
      <div class="coupon-headline">${esc(c.headline || 'Special Offer')}</div>
      ${c.company ? `<div class="coupon-company">${esc(c.company)}</div>` : ''}
      ${c.description ? `<div class="coupon-desc">${esc(c.description)}</div>` : ''}
      ${c.expiresAt ? `<div class="coupon-expiry">Expires: ${esc(new Date(c.expiresAt).toLocaleDateString('en-GB'))}</div>` : ''}
    </div>

    ${c.redemptionUrl
      ? `<a class="coupon-cta" href="${esc(c.redemptionUrl)}" rel="noopener">GET COUPON</a>`
      : `<div class="coupon-cta" style="background:#1B2A4A;">Coupon Available</div>`
    }

    ${c.terms ? `<div class="coupon-terms">${esc(c.terms)}</div>` : ''}
  `;
}

export default renderCouponContent;
