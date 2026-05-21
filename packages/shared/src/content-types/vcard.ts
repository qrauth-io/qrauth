import { z } from 'zod';
import { registerContentType } from './registry.js';
import type { ContentFieldDef } from './registry.js';

export const vcardContentSchema = z.object({
  firstName: z.string().min(1),
  lastName: z.string().optional(),
  title: z.string().optional(),
  company: z.string().optional(),
  email: z.string().email().optional(),
  phone: z.string().optional(),
  mobile: z.string().optional(),
  website: z.string().url().optional().or(z.literal('')),
  address: z.object({
    street: z.string().optional(),
    city: z.string().optional(),
    state: z.string().optional(),
    zip: z.string().optional(),
    country: z.string().optional(),
  }).optional(),
  photoUrl: z.string().optional(),
  summary: z.string().optional(),
  socialLinks: z.array(z.object({
    platform: z.string(),
    url: z.string().url(),
  })).optional(),
});

export type VCardContent = z.infer<typeof vcardContentSchema>;

const fields: ContentFieldDef[] = [
  { name: 'firstName', type: 'text', label: 'First Name', placeholder: 'Jane', required: true, group: 'Name' },
  { name: 'lastName', type: 'text', label: 'Last Name', placeholder: 'Doe', group: 'Name' },
  { name: 'title', type: 'text', label: 'Job Title', placeholder: 'Product Manager' },
  { name: 'company', type: 'text', label: 'Company', placeholder: 'Acme Corp' },
  { name: 'email', type: 'email', label: 'Email', placeholder: 'jane@example.com' },
  { name: 'phone', type: 'phone', label: 'Phone', placeholder: '+1 555-0123' },
  { name: 'mobile', type: 'phone', label: 'Mobile', placeholder: '+1 555-0124' },
  { name: 'website', type: 'url', label: 'Website', placeholder: 'https://janedoe.com' },
  { name: 'summary', type: 'textarea', label: 'About', placeholder: 'A brief description...', helpText: 'Shown below the contact name' },
  { name: 'photoUrl', type: 'image', label: 'Photo', helpText: 'Profile photo shown on the contact card' },
  { name: 'address', type: 'address', label: 'Address', group: 'Address' },
  { name: 'socialLinks', type: 'social-links', label: 'Social Links', helpText: 'Links to social media profiles' },
];

registerContentType({
  id: 'vcard',
  label: 'Contact Card',
  description: 'Share your contact details — scan to save',
  icon: 'solar:user-id-bold',
  category: 'contact',
  schema: vcardContentSchema,
  fields,
  hasFileUpload: true,
  freeTierAllowed: true,
});
