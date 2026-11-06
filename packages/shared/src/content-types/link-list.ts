import { z } from 'zod';
import { registerContentType } from './registry.js';
import { httpsUrl } from '../http-url.js';

/**
 * Link list: a titled page of up to 20 https links, shown after the trust
 * reveal. It never continues on its own. Every link is screened (Web Risk
 * and the lookalike check) on create, on edit and in the daily re-scan.
 */
export const LINK_LIST_TITLE_MAX = 60;
export const LINK_LIST_DESCRIPTION_MAX = 200;
export const LINK_LIST_LABEL_MAX = 40;
export const LINK_LIST_MAX_LINKS = 20;

const notBlank = (s: string) => s.trim().length > 0;

// Control characters (other than tab and newlines) and bidirectional
// overrides, which can make a label read differently from its link.
// eslint-disable-next-line no-control-regex
const UNSAFE_TEXT = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F\u200E\u200F\u202A-\u202E\u2066-\u2069]/;
const safeText = (s: string) => !UNSAFE_TEXT.test(s);
const SAFE_TEXT_MESSAGE = 'Must not contain control or text-direction characters';

export const linkListItemSchema = z
  .object({
    label: z
      .string()
      .max(LINK_LIST_LABEL_MAX, `Label must not exceed ${LINK_LIST_LABEL_MAX} characters`)
      .refine(notBlank, { message: 'Label is required' })
      .refine(safeText, { message: SAFE_TEXT_MESSAGE }),
    url: httpsUrl(),
  })
  .strict();

export const linkListContentSchema = z
  .object({
    title: z
      .string()
      .max(LINK_LIST_TITLE_MAX, `Title must not exceed ${LINK_LIST_TITLE_MAX} characters`)
      .refine(notBlank, { message: 'Title is required' })
      .refine(safeText, { message: SAFE_TEXT_MESSAGE }),
    description: z
      .string()
      .max(LINK_LIST_DESCRIPTION_MAX, `Description must not exceed ${LINK_LIST_DESCRIPTION_MAX} characters`)
      .refine(safeText, { message: SAFE_TEXT_MESSAGE })
      .optional(),
    links: z
      .array(linkListItemSchema)
      .min(1, 'Add at least one link')
      .max(LINK_LIST_MAX_LINKS, `A link list holds at most ${LINK_LIST_MAX_LINKS} links`),
  })
  .strict();

export type LinkListContent = z.infer<typeof linkListContentSchema>;
export type LinkListItem = z.infer<typeof linkListItemSchema>;

registerContentType({
  id: 'link-list',
  label: 'Link List',
  description: 'A short page of links, each one screened',
  icon: 'solar:list-bold',
  category: 'link',
  schema: linkListContentSchema,
  fields: [
    { name: 'title', type: 'text', label: 'Title', required: true, placeholder: 'Our links', maxLength: LINK_LIST_TITLE_MAX },
    { name: 'description', type: 'textarea', label: 'Description', placeholder: 'What visitors will find here', maxLength: LINK_LIST_DESCRIPTION_MAX },
    { name: 'links', type: 'link-list', label: 'Links', required: true, maxItems: LINK_LIST_MAX_LINKS, maxLength: LINK_LIST_LABEL_MAX, helpText: 'https links only' },
  ],
  hasFileUpload: false,
  freeTierAllowed: false,
});
