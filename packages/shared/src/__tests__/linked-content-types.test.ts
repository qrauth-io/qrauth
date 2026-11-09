import { describe, expect, it } from 'vitest';

import {
  appLinkContentSchema,
  contentLinkUrls,
  getContentType,
  isLinkedContentType,
  linkListContentSchema,
  LINK_LIST_MAX_LINKS,
  planAllowsContentType,
} from '../index.js';

const APP = {
  iosUrl: 'https://apps.apple.com/app/id1',
  androidUrl: 'https://play.google.com/store/apps/details?id=x',
  fallbackUrl: 'https://example.com/app',
};
const LIST = { title: 'Our links', links: [{ label: 'Menu', url: 'https://example.com/menu' }] };

const BAD_URLS = [
  'javascript:alert(1)',
  'JaVaScRiPt:alert(1)',
  ' javascript:alert(1)',
  'data:text/html,<script>alert(1)</script>',
  'intent://scan/#Intent;scheme=zxing;package=com.google.zxing.client.android;end',
  'http://example.com/',
  'vbscript:msgbox(1)',
  'file:///etc/passwd',
  '//evil.example/',
  'https://bank.example@evil.example/',
  'https://user:pass@example.com/',
  'not a url',
  '',
];

describe('app-link content', () => {
  it('accepts three https URLs', () => {
    expect(appLinkContentSchema.safeParse(APP).success).toBe(true);
  });

  it.each(BAD_URLS)('refuses %j in every URL field', (bad) => {
    for (const field of ['iosUrl', 'androidUrl', 'fallbackUrl']) {
      expect(appLinkContentSchema.safeParse({ ...APP, [field]: bad }).success).toBe(false);
    }
  });

  it('requires all three URLs and refuses unknown keys', () => {
    expect(appLinkContentSchema.safeParse({ iosUrl: APP.iosUrl, androidUrl: APP.androidUrl }).success).toBe(false);
    expect(appLinkContentSchema.safeParse({ ...APP, style: 'color:red' }).success).toBe(false);
  });
});

describe('link-list content', () => {
  it('accepts a title, an optional description and links', () => {
    expect(linkListContentSchema.safeParse(LIST).success).toBe(true);
    expect(linkListContentSchema.safeParse({ ...LIST, description: 'x'.repeat(200) }).success).toBe(true);
  });

  it('enforces the length limits', () => {
    expect(linkListContentSchema.safeParse({ ...LIST, title: 'x'.repeat(60) }).success).toBe(true);
    expect(linkListContentSchema.safeParse({ ...LIST, title: 'x'.repeat(61) }).success).toBe(false);
    expect(linkListContentSchema.safeParse({ ...LIST, title: '   ' }).success).toBe(false);
    expect(linkListContentSchema.safeParse({ ...LIST, description: 'x'.repeat(201) }).success).toBe(false);
    const label = (l: string) => ({ ...LIST, links: [{ label: l, url: 'https://example.com/' }] });
    expect(linkListContentSchema.safeParse(label('x'.repeat(40))).success).toBe(true);
    expect(linkListContentSchema.safeParse(label('x'.repeat(41))).success).toBe(false);
    expect(linkListContentSchema.safeParse(label(' ')).success).toBe(false);
  });

  it('holds 1 to 20 links', () => {
    const links = (n: number) => Array.from({ length: n }, (_, i) => ({ label: `L${i}`, url: `https://example.com/${i}` }));
    expect(linkListContentSchema.safeParse({ ...LIST, links: links(LINK_LIST_MAX_LINKS) }).success).toBe(true);
    expect(linkListContentSchema.safeParse({ ...LIST, links: links(LINK_LIST_MAX_LINKS + 1) }).success).toBe(false);
    expect(linkListContentSchema.safeParse({ ...LIST, links: [] }).success).toBe(false);
  });

  it.each(BAD_URLS)('refuses the link URL %j', (bad) => {
    expect(linkListContentSchema.safeParse({ ...LIST, links: [{ label: 'x', url: bad }] }).success).toBe(false);
  });

  it.each(['\u202Emoc.knab', 'a\u0000b', 'a\u2066b', 'x\u200Fy'])('refuses control and text-direction characters (%j)', (bad) => {
    expect(linkListContentSchema.safeParse({ ...LIST, title: bad }).success).toBe(false);
    expect(linkListContentSchema.safeParse({ ...LIST, description: bad }).success).toBe(false);
    expect(linkListContentSchema.safeParse({ ...LIST, links: [{ label: bad, url: 'https://a.example/' }] }).success).toBe(false);
  });

  it('allows newlines in the description and non-Latin text', () => {
    expect(linkListContentSchema.safeParse({ ...LIST, title: 'Μενού καφέ', description: 'line one\nline two' }).success).toBe(true);
  });

  it('refuses unknown keys on the list and on a link', () => {
    expect(linkListContentSchema.safeParse({ ...LIST, html: '<b>' }).success).toBe(false);
    expect(linkListContentSchema.safeParse({ ...LIST, links: [{ ...LIST.links[0], target: '_top' }] }).success).toBe(false);
  });

  it('keeps HTML in text as data (escaping is the renderer\'s job)', () => {
    expect(linkListContentSchema.safeParse({ ...LIST, title: '<script>alert(1)</script>' }).success).toBe(true);
  });
});

describe('registry and helpers', () => {
  it('registers both types as paid', () => {
    for (const id of ['app-link', 'link-list']) {
      const def = getContentType(id)!;
      expect(def.freeTierAllowed).toBe(false);
      expect(planAllowsContentType('FREE', def.freeTierAllowed)).toBe(false);
      expect(planAllowsContentType('PRO', def.freeTierAllowed)).toBe(true);
    }
  });

  it('lists the outbound URLs in display order', () => {
    expect(contentLinkUrls('app-link', APP)).toEqual([APP.iosUrl, APP.androidUrl, APP.fallbackUrl]);
    expect(contentLinkUrls('link-list', LIST)).toEqual(['https://example.com/menu']);
    expect(contentLinkUrls('url', { destinationUrl: 'https://x.example' })).toEqual([]);
    expect(contentLinkUrls('link-list', { title: 'x' })).toEqual([]);
    expect(isLinkedContentType('app-link')).toBe(true);
    expect(isLinkedContentType('coupon')).toBe(false);
  });
});
