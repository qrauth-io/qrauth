import { esc } from './utils.js';
import type { RenderContext } from './index.js';

function renderEventContent(ctx: RenderContext): string {
  const c = ctx.qrCode.content as any;
  if (!c) return '<p>No event data.</p>';

  const startDate = c.startDate ? new Date(c.startDate) : null;
  const endDate = c.endDate ? new Date(c.endDate) : null;
  const dateStr = startDate
    ? startDate.toLocaleDateString('en-GB', { weekday: 'long', day: 'numeric', month: 'long', year: 'numeric' })
    : '';
  const timeStr = startDate
    ? startDate.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', hour12: false })
    : '';
  const endTimeStr = endDate
    ? endDate.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', hour12: false })
    : '';

  // Google Calendar link
  const gcalStart = startDate ? startDate.toISOString().replace(/[-:]/g, '').replace(/\.\d{3}/, '') : '';
  const gcalEnd = endDate ? endDate.toISOString().replace(/[-:]/g, '').replace(/\.\d{3}/, '') : gcalStart;
  const gcalUrl = `https://calendar.google.com/calendar/render?action=TEMPLATE&text=${encodeURIComponent(c.title || '')}&dates=${gcalStart}/${gcalEnd}&location=${encodeURIComponent(c.address || c.location || '')}&details=${encodeURIComponent(c.description || '')}`;

  return `
    <style>
      .event-img { width: 100%; height: 180px; object-fit: cover; border-radius: 8px; margin-bottom: 16px; }
      .event-title { font-size: 22px; font-weight: 800; color: #1B2A4A; margin-bottom: 4px; }
      .event-organizer { font-size: 13px; color: #637381; margin-bottom: 16px; }
      .event-desc { font-size: 14px; color: #637381; line-height: 1.6; margin-bottom: 16px; }
      .event-field { display: flex; align-items: flex-start; gap: 12px; padding: 10px 0; border-bottom: 1px solid #f5f5f5; }
      .event-icon { width: 36px; height: 36px; border-radius: 10px; display: flex; align-items: center; justify-content: center; flex-shrink: 0; font-size: 18px; }
      .event-label { font-size: 11px; color: #919eab; text-transform: uppercase; }
      .event-value { font-size: 14px; color: #212b36; }
      .event-cta { display: block; width: 100%; padding: 14px; margin-top: 20px; background: #0065DB; color: white; border: none; border-radius: 10px; font-size: 16px; font-weight: 600; text-align: center; text-decoration: none; }
      .event-cta:hover { opacity: 0.9; }
    </style>

    ${c.imageUrl ? `<img class="event-img" src="${esc(c.imageUrl)}" alt="" onerror="this.style.display='none'" />` : ''}
    <div class="event-title">${esc(c.title || 'Event')}</div>
    ${c.organizer ? `<div class="event-organizer">by ${esc(c.organizer)}</div>` : ''}
    ${c.description ? `<div class="event-desc">${esc(c.description)}</div>` : ''}

    ${startDate ? `
    <div class="event-field">
      <div class="event-icon" style="background:#E3F2FD;">&#128197;</div>
      <div>
        <div class="event-label">When</div>
        <div class="event-value">${esc(dateStr)}</div>
        <div class="event-value">${esc(timeStr)}${endTimeStr ? ` \u2014 ${esc(endTimeStr)}` : ''}</div>
      </div>
    </div>
    ` : ''}

    ${c.location || c.address ? `
    <div class="event-field">
      <div class="event-icon" style="background:#F3E5F5;">&#128205;</div>
      <div>
        <div class="event-label">Where</div>
        ${c.location ? `<div class="event-value">${esc(c.location)}</div>` : ''}
        ${c.address ? `<div class="event-value" style="font-size:13px;color:#637381;">${esc(c.address)}</div>` : ''}
      </div>
    </div>
    ` : ''}

    ${c.contactEmail ? `
    <div class="event-field">
      <div class="event-icon" style="background:#E3F2FD;">&#9993;</div>
      <div>
        <div class="event-label">Contact</div>
        <div class="event-value"><a href="mailto:${esc(c.contactEmail)}" style="color:#0D47A1;text-decoration:none;">${esc(c.contactEmail)}</a></div>
      </div>
    </div>
    ` : ''}

    ${startDate ? `<a class="event-cta" href="${esc(gcalUrl)}" target="_blank" rel="noopener">Add to Calendar</a>` : ''}

    ${c.website ? `<a href="${esc(c.website)}" target="_blank" rel="noopener" style="display:block;text-align:center;margin-top:12px;font-size:13px;color:#0D47A1;">Event Website &#8594;</a>` : ''}
  `;
}

export default renderEventContent;
