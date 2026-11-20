import { appLinkContentSchema, type AppLinkContent } from '@qrauth/shared';
import { PLATFORM_URL_FIELD, type Platform } from '../services/platform.js';
import { esc } from './utils.js';
import { LINKS_CSS, linkState, removedNotice, renderLinkItem, safeHttpsHref, untrustedBanner, type LinkItem } from './links.js';
import type { RenderContext } from './index.js';

/**
 * Smart link page: the App Store, Google Play and website choices, the
 * scanner's platform first. A VERIFIED code in scan mode FLASH continues to
 * the platform's URL before this page is read (renderers/flash.ts); every
 * other scan stays here. A link Web Risk lists is left out, with a note.
 */

const CHOICES: Array<{ platform: Platform; name: string }> = [
  { platform: 'ios', name: 'App Store' },
  { platform: 'android', name: 'Google Play' },
  { platform: 'other', name: 'Website' },
];

function orderedChoices(platform: Platform) {
  return [...CHOICES].sort((a, b) => Number(b.platform === platform) - Number(a.platform === platform));
}

function renderAppLinkContent(ctx: RenderContext): string {
  const parsed = appLinkContentSchema.safeParse(ctx.qrCode.content);
  if (!parsed.success) return '<p>This code has no links.</p>';
  const content: AppLinkContent = parsed.data;
  const platform = ctx.platform ?? 'other';

  const items: string[] = [];
  const removed: string[] = [];
  for (const choice of orderedChoices(platform)) {
    const url = content[PLATFORM_URL_FIELD[choice.platform]];
    const href = safeHttpsHref(url);
    const state = linkState(ctx, url);
    if (!href || state.flagged) {
      removed.push(choice.name);
      continue;
    }
    const isDevice = choice.platform === platform && platform !== 'other';
    const item: LinkItem = {
      label: choice.name,
      href,
      tag: isDevice ? 'For your device' : undefined,
      primary: isDevice && ctx.trustState === 'VERIFIED',
      lookalike: state.lookalike,
    };
    items.push(renderLinkItem(item));
  }

  const notice = removed.length === 0
    ? null
    : `The ${removed.join(' and ')} link${removed.length > 1 ? 's were' : ' was'} removed: Google Web Risk lists ${removed.length > 1 ? 'them' : 'it'} as dangerous.`;

  return `
    <style nonce="${ctx.nonce}">${LINKS_CSS}
    </style>
    ${ctx.qrCode.label ? `<div class="ql-title">${esc(ctx.qrCode.label)}</div>` : ''}
    <div class="ql-desc">Choose where to get the app.</div>
    ${untrustedBanner(ctx)}
    <ul class="ql-list">${items.join('')}</ul>
    ${removedNotice(notice)}
  `;
}

export default renderAppLinkContent;
