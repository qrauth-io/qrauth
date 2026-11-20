import { isSafeHttpsUrl } from '@qrauth/shared';
import { esc } from './utils.js';
import { lookalikeNote } from '../services/lookalike.js';
import type { LinkState, RenderContext } from './index.js';

/**
 * Building blocks for the smart link and link list pages.
 *
 * Every piece of user text goes through esc(). The only attribute that
 * carries user data is href, and only for a URL that passes isSafeHttpsUrl
 * here, at render time, whatever the stored content says. Links open with
 * rel="noopener noreferrer nofollow". Styles are fixed classes in the
 * page's nonced <style> block; no user value reaches a style.
 */

export const LINK_REL = 'noopener noreferrer nofollow';

/** The URL when it is a safe absolute https URL, otherwise null. */
export function safeHttpsHref(url: unknown): string | null {
  return typeof url === 'string' && isSafeHttpsUrl(url) ? url : null;
}

export function linkState(ctx: RenderContext, url: string): LinkState {
  return ctx.links?.[url] ?? { flagged: false };
}

export const LINKS_CSS = `
      .ql-title { font-size: 20px; font-weight: 800; color: #0A0A0A; margin-bottom: 6px; word-break: break-word; }
      .ql-desc { font-size: 14px; color: #525252; line-height: 1.6; margin-bottom: 16px; word-break: break-word; }
      .ql-list { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 10px; }
      .ql-link { display: block; padding: 14px 16px; border-radius: 12px; text-decoration: none; background: #FFFFFF; border: 1px solid rgba(15,15,15,0.12); color: #0A0A0A; }
      .ql-link.ql-primary { background: #047857; border-color: #047857; color: #FFFFFF; }
      .ql-label { display: block; font-size: 16px; font-weight: 700; word-break: break-word; }
      .ql-host { display: block; font-size: 13px; opacity: 0.75; margin-top: 2px; word-break: break-all; }
      .ql-tag { display: inline-block; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.4px; margin-left: 6px; opacity: 0.85; }
      .ql-warn { display: block; font-size: 12px; font-weight: 600; color: #B91C1C; margin-top: 6px; }
      .ql-removed { padding: 12px 14px; border-radius: 10px; background: rgba(244,63,94,0.08); border: 1px solid rgba(244,63,94,0.22); color: #B91C1C; font-size: 13px; font-weight: 600; margin-top: 12px; }
      .ql-stop { padding: 14px; border-radius: 12px; background: rgba(244,63,94,0.08); border: 1px solid rgba(244,63,94,0.22); color: #B91C1C; font-size: 15px; font-weight: 600; text-align: center; margin-bottom: 14px; }`;

export interface LinkItem {
  label: string;
  href: string;
  /** Text after the label (server-chosen, e.g. "For your device"). */
  tag?: string;
  primary?: boolean;
  lookalike?: LinkState['lookalike'];
}

export function renderLinkItem(item: LinkItem): string {
  const host = new URL(item.href).hostname;
  const warn = item.lookalike
    ? `<span class="ql-warn">${esc(lookalikeNote({ domain: item.lookalike.similarTo, verifiedOrgName: item.lookalike.verifiedOrg, reason: item.lookalike.reason ?? '', scripts: item.lookalike.scripts, source: item.lookalike.source }))}</span>`
    : '';
  return `<li><a class="ql-link${item.primary ? ' ql-primary' : ''}" href="${esc(item.href)}" rel="${LINK_REL}"><span class="ql-label">${esc(item.label)}${item.tag ? `<span class="ql-tag">${esc(item.tag)}</span>` : ''}</span><span class="ql-host">${esc(host)}</span>${warn}</a></li>`;
}

/** Shown above the links when the code is UNTRUSTED. The links stay visible. */
export function untrustedBanner(ctx: RenderContext): string {
  return ctx.trustState === 'UNTRUSTED'
    ? '<div class="ql-stop">Do not proceed - this QR code is not verified</div>'
    : '';
}

/** Says which entries were hidden because Web Risk lists them. */
export function removedNotice(sentence: string | null): string {
  return sentence ? `<div class="ql-removed" role="note">${esc(sentence)}</div>` : '';
}
