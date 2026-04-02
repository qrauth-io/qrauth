import { z } from 'zod';
import { registerContentType } from './registry.js';
import type { ContentFieldDef } from './registry.js';

export const urlContentSchema = z.object({
  destinationUrl: z.string().url(),
});

export type UrlContent = z.infer<typeof urlContentSchema>;

const fields: ContentFieldDef[] = [
  { name: 'destinationUrl', type: 'url', label: 'Destination URL', placeholder: 'https://example.com', required: true },
];

registerContentType({
  id: 'url',
  label: 'Website URL',
  description: 'Link to any website or web page',
  icon: 'solar:link-bold',
  category: 'link',
  schema: urlContentSchema,
  fields,
  hasFileUpload: false,
  freeTierAllowed: true,
});
