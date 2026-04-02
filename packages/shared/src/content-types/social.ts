import { z } from 'zod';
import { registerContentType } from './registry.js';

export const socialContentSchema = z.object({
  name: z.string().min(1),
  bio: z.string().optional(),
  avatarUrl: z.string().optional(),
  links: z.array(z.object({
    platform: z.string(),
    url: z.string().url(),
    label: z.string().optional(),
  })).min(1),
});

registerContentType({
  id: 'social',
  label: 'Social Links',
  description: 'Link tree to all your social profiles',
  icon: 'solar:share-bold',
  category: 'social',
  schema: socialContentSchema,
  fields: [
    { name: 'name', type: 'text', label: 'Display Name', required: true },
    { name: 'bio', type: 'textarea', label: 'Bio', placeholder: 'A short bio...' },
    { name: 'avatarUrl', type: 'image', label: 'Avatar' },
    { name: 'links', type: 'social-links', label: 'Social Links', required: true, helpText: 'Add links to your social profiles' },
  ],
  hasFileUpload: true,
  freeTierAllowed: true,
});
