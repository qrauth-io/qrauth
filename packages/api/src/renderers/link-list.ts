import { linkListContentSchema } from '@qrauth/shared';
import { esc } from './utils.js';
import { LINKS_CSS, linkState, removedNotice, renderLinkItem, safeHttpsHref, untrustedBanner } from './links.js';
import type { RenderContext } from './index.js';

/**
 * Link list page: title, optional description and the links, shown after
 * the trust reveal. It never continues on its own (scan mode is always PAGE
 * for this type). A link Web Risk lists is left out, with a note.
 */
function renderLinkListContent(ctx: RenderContext): string {
  const parsed = linkListContentSchema.safeParse(ctx.qrCode.content);
  if (!parsed.success) return '<p>This code has no links.</p>';
  const { title, description, links } = parsed.data;

  const items: string[] = [];
  let removed = 0;
  for (const link of links) {
    const href = safeHttpsHref(link.url);
    const state = linkState(ctx, link.url);
    if (!href || state.flagged) {
      removed += 1;
      continue;
    }
    items.push(renderLinkItem({ label: link.label, href, lookalike: state.lookalike }));
  }

  const notice = removed === 0
    ? null
    : `${removed} link${removed > 1 ? 's were' : ' was'} removed: Google Web Risk lists ${removed > 1 ? 'them' : 'it'} as dangerous.`;

  return `
    <style nonce="${ctx.nonce}">${LINKS_CSS}
    </style>
    <div class="ql-title">${esc(title)}</div>
    ${description ? `<div class="ql-desc">${esc(description)}</div>` : ''}
    ${untrustedBanner(ctx)}
    <ul class="ql-list">${items.join('')}</ul>
    ${removedNotice(notice)}
  `;
}

export default renderLinkListContent;
