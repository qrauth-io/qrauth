import { esc } from './utils.js';
import type { RenderContext } from './index.js';

function renderPdfContent(ctx: RenderContext): string {
  const c = ctx.qrCode.content as any;
  if (!c) return '<p>No document data.</p>';

  return `
    <style>
      .pdf-title { font-size: 20px; font-weight: 800; color: #1B2A4A; margin-bottom: 4px; text-align: center; }
      .pdf-desc { font-size: 14px; color: #637381; text-align: center; margin-bottom: 20px; line-height: 1.6; }
      .pdf-viewer { width: 100%; height: 400px; border: 1px solid #f0f0f0; border-radius: 8px; }
      .pdf-download { display: block; width: 100%; padding: 14px; margin-top: 16px; background: #1B2A4A; color: white; border: none; border-radius: 10px; font-size: 16px; font-weight: 600; text-align: center; text-decoration: none; }
      .pdf-download:hover { opacity: 0.9; }
    </style>

    <div style="text-align:center;font-size:48px;margin-bottom:12px;">&#128196;</div>
    <div class="pdf-title">${esc(c.title || 'Document')}</div>
    ${c.description ? `<div class="pdf-desc">${esc(c.description)}</div>` : ''}

    ${c.fileUrl ? `
      <iframe class="pdf-viewer" src="${esc(c.fileUrl)}" title="${esc(c.title || 'PDF')}" frameborder="0"></iframe>
      <a class="pdf-download" href="${esc(c.fileUrl)}" target="_blank" rel="noopener" download>Download PDF</a>
    ` : `
      <div style="padding:40px;text-align:center;background:#f8f9fa;border-radius:8px;color:#919eab;">
        No document uploaded yet.
      </div>
    `}
  `;
}

export default renderPdfContent;
