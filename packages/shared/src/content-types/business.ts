import { z } from 'zod';
import { registerContentType } from './registry.js';

export const businessContentSchema = z.object({
  name: z.string().min(1),
  logoUrl: z.string().optional(),
  description: z.string().optional(),
  phone: z.string().optional(),
  email: z.string().email().optional(),
  website: z.string().url().optional().or(z.literal('')),
  address: z.string().optional(),
  hours: z.string().optional(),
  socialLinks: z.array(z.object({ platform: z.string(), url: z.string().url() })).optional(),
});

registerContentType({
  id: 'business',
  label: 'Business Page',
  description: 'Mini-website with info, hours, and contact',
  icon: 'solar:shop-bold',
  category: 'contact',
  schema: businessContentSchema,
  fields: [
    { name: 'name', type: 'text', label: 'Business Name', required: true, placeholder: 'Your Business' },
    { name: 'logoUrl', type: 'image', label: 'Logo' },
    { name: 'description', type: 'textarea', label: 'About', placeholder: 'What your business does...' },
    { name: 'phone', type: 'phone', label: 'Phone' },
    { name: 'email', type: 'email', label: 'Email' },
    { name: 'website', type: 'url', label: 'Website' },
    { name: 'address', type: 'text', label: 'Address' },
    { name: 'hours', type: 'textarea', label: 'Business Hours', placeholder: 'Mon-Fri: 9am-5pm\nSat: 10am-2pm' },
    { name: 'socialLinks', type: 'social-links', label: 'Social Links' },
  ],
  hasFileUpload: true,
  freeTierAllowed: false,
});
