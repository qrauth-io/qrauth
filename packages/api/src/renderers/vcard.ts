import { registerRenderer } from './index.js';
import { esc } from './utils.js';
import type { RenderContext } from './index.js';

function renderVCardContent(ctx: RenderContext): string {
  const content = ctx.qrCode.content as Record<string, any> | null;
  if (!content) return '<p>No contact data available.</p>';

  const firstName: string = content['firstName'] ?? '';
  const lastName: string = content['lastName'] ?? '';
  const fullName = [firstName, lastName].filter(Boolean).join(' ');
  const address = content['address'] as Record<string, string> | undefined;
  const hasAddress = address && Object.values(address).some(Boolean);

  // Generate vCard 3.0 lines for download
  const vcfLines: string[] = [
    'BEGIN:VCARD',
    'VERSION:3.0',
    `FN:${fullName}`,
    `N:${lastName};${firstName};;;`,
  ];
  if (content['title']) vcfLines.push(`TITLE:${content['title']}`);
  if (content['company']) vcfLines.push(`ORG:${content['company']}`);
  if (content['email']) vcfLines.push(`EMAIL:${content['email']}`);
  if (content['phone']) vcfLines.push(`TEL;TYPE=WORK:${content['phone']}`);
  if (content['mobile']) vcfLines.push(`TEL;TYPE=CELL:${content['mobile']}`);
  if (content['website']) vcfLines.push(`URL:${content['website']}`);
  if (hasAddress && address) {
    vcfLines.push(`ADR:;;${address['street'] ?? ''};${address['city'] ?? ''};${address['state'] ?? ''};${address['zip'] ?? ''};${address['country'] ?? ''}`);
  }
  if (content['summary']) vcfLines.push(`NOTE:${String(content['summary']).replace(/\n/g, '\\n')}`);
  vcfLines.push('END:VCARD');

  // Encode as a data URI so no server round-trip is needed
  const vcfText = vcfLines.join('\r\n');
  const vcfDataUri = `data:text/vcard;charset=utf-8,${encodeURIComponent(vcfText)}`;
  const downloadFilename = esc(fullName.replace(/[^a-zA-Z0-9]/g, '_') || 'contact') + '.vcf';

  const socialLinks: Array<{ platform: string; url: string }> = Array.isArray(content['socialLinks'])
    ? content['socialLinks']
    : [];

  const addressDisplay = hasAddress && address
    ? esc([address['street'], address['city'], address['state'], address['zip'], address['country']].filter(Boolean).join(', '))
    : '';

  return `
    <style>
      .vcard { text-align: center; }
      .vcard-photo { width: 96px; height: 96px; border-radius: 50%; object-fit: cover; margin: 0 auto 12px; display: block; border: 3px solid #f0f0f0; }
      .vcard-photo-placeholder { width: 96px; height: 96px; border-radius: 50%; margin: 0 auto 12px; display: flex; align-items: center; justify-content: center; background: #E3F2FD; color: #0D47A1; font-size: 36px; font-weight: 700; }
      .vcard-name { font-size: 22px; font-weight: 800; color: #1B2A4A; }
      .vcard-title { font-size: 14px; color: #637381; margin-top: 2px; }
      .vcard-company { font-size: 14px; color: #637381; }
      .vcard-summary { font-size: 13px; color: #637381; margin-top: 12px; line-height: 1.6; max-width: 320px; margin-left: auto; margin-right: auto; }
      .vcard-fields { margin-top: 20px; text-align: left; }
      .vcard-field { display: flex; align-items: center; gap: 12px; padding: 12px 0; border-bottom: 1px solid #f5f5f5; }
      .vcard-field-icon { width: 36px; height: 36px; border-radius: 10px; display: flex; align-items: center; justify-content: center; flex-shrink: 0; font-size: 18px; }
      .vcard-field-label { font-size: 11px; color: #919eab; text-transform: uppercase; }
      .vcard-field-value { font-size: 14px; color: #212b36; word-break: break-word; }
      .vcard-field-value a { color: #0D47A1; text-decoration: none; }
      .vcard-save-btn { display: block; width: 100%; padding: 14px; margin-top: 24px; background: #1B2A4A; color: white; border: none; border-radius: 10px; font-size: 16px; font-weight: 600; cursor: pointer; text-align: center; text-decoration: none; }
      .vcard-save-btn:hover { background: #263B66; }
      .vcard-social { display: flex; justify-content: center; gap: 8px; margin-top: 16px; flex-wrap: wrap; }
      .vcard-social a { display: flex; align-items: center; justify-content: center; width: 40px; height: 40px; border-radius: 10px; background: #f5f5f5; color: #637381; text-decoration: none; font-size: 12px; font-weight: 700; }
      .vcard-social a:hover { background: #e0e0e0; }
    </style>

    <div class="vcard">
      ${content['photoUrl']
        ? `<img class="vcard-photo" src="${esc(content['photoUrl'])}" alt="${esc(fullName)}" />`
        : `<div class="vcard-photo-placeholder">${esc(fullName.charAt(0).toUpperCase() || '?')}</div>`
      }
      <div class="vcard-name">${esc(fullName)}</div>
      ${content['title'] ? `<div class="vcard-title">${esc(content['title'])}</div>` : ''}
      ${content['company'] ? `<div class="vcard-company">${esc(content['company'])}</div>` : ''}
      ${content['summary'] ? `<div class="vcard-summary">${esc(content['summary'])}</div>` : ''}
    </div>

    <div class="vcard-fields">
      ${content['email'] ? `
      <a href="mailto:${esc(content['email'])}" style="text-decoration:none;">
        <div class="vcard-field">
          <div class="vcard-field-icon" style="background:#E3F2FD;">&#9993;</div>
          <div><div class="vcard-field-label">Email</div><div class="vcard-field-value">${esc(content['email'])}</div></div>
        </div>
      </a>` : ''}

      ${content['phone'] ? `
      <a href="tel:${esc(content['phone'])}" style="text-decoration:none;">
        <div class="vcard-field">
          <div class="vcard-field-icon" style="background:#E8F5E9;">&#9742;</div>
          <div><div class="vcard-field-label">Phone</div><div class="vcard-field-value">${esc(content['phone'])}</div></div>
        </div>
      </a>` : ''}

      ${content['mobile'] ? `
      <a href="tel:${esc(content['mobile'])}" style="text-decoration:none;">
        <div class="vcard-field">
          <div class="vcard-field-icon" style="background:#E8F5E9;">&#128241;</div>
          <div><div class="vcard-field-label">Mobile</div><div class="vcard-field-value">${esc(content['mobile'])}</div></div>
        </div>
      </a>` : ''}

      ${content['website'] ? `
      <a href="${esc(content['website'])}" target="_blank" rel="noopener" style="text-decoration:none;">
        <div class="vcard-field">
          <div class="vcard-field-icon" style="background:#FFF3E0;">&#127760;</div>
          <div><div class="vcard-field-label">Website</div><div class="vcard-field-value">${esc(content['website'])}</div></div>
        </div>
      </a>` : ''}

      ${hasAddress ? `
      <div class="vcard-field">
        <div class="vcard-field-icon" style="background:#F3E5F5;">&#128205;</div>
        <div><div class="vcard-field-label">Address</div><div class="vcard-field-value">${addressDisplay}</div></div>
      </div>` : ''}
    </div>

    ${socialLinks.length > 0 ? `
    <div class="vcard-social">
      ${socialLinks.map((link) => `<a href="${esc(link.url)}" target="_blank" rel="noopener" title="${esc(link.platform)}">${esc(link.platform.slice(0, 2).toUpperCase())}</a>`).join('')}
    </div>` : ''}

    <a class="vcard-save-btn" href="${vcfDataUri}" download="${downloadFilename}">Save Contact</a>
  `;
}

registerRenderer('vcard', renderVCardContent);
