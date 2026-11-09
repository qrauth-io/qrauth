import { appLinkContentSchema, APP_LINK_URL_FIELDS } from './app-link.js';
import { linkListContentSchema } from './link-list.js';

/** Content types whose content holds outbound links (screened like a URL code's destination). */
export const LINKED_CONTENT_TYPES = ['app-link', 'link-list'] as const;
export type LinkedContentType = (typeof LINKED_CONTENT_TYPES)[number];

export function isLinkedContentType(contentType: string | null | undefined): contentType is LinkedContentType {
  return (LINKED_CONTENT_TYPES as readonly string[]).includes(contentType ?? '');
}

/**
 * The outbound URLs of a code's content, in display order, or [] when the
 * type has none or the content does not match its schema.
 */
export function contentLinkUrls(contentType: string | null | undefined, content: unknown): string[] {
  if (contentType === 'app-link') {
    const parsed = appLinkContentSchema.safeParse(content);
    return parsed.success ? APP_LINK_URL_FIELDS.map((field) => parsed.data[field]) : [];
  }
  if (contentType === 'link-list') {
    const parsed = linkListContentSchema.safeParse(content);
    return parsed.success ? parsed.data.links.map((link) => link.url) : [];
  }
  return [];
}
