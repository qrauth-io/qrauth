import { z } from 'zod';
import { registerContentType } from './registry.js';

export const couponContentSchema = z.object({
  company: z.string().min(1),
  headline: z.string().min(1),
  description: z.string().optional(),
  imageUrl: z.string().optional(),
  discountBadge: z.string().optional(),
  expiresAt: z.string().optional(),
  redemptionUrl: z.string().url().optional().or(z.literal('')),
  terms: z.string().optional(),
});

registerContentType({
  id: 'coupon',
  label: 'Coupon / Offer',
  description: 'Branded discount with expiry and redemption',
  icon: 'solar:ticket-bold',
  category: 'marketing',
  schema: couponContentSchema,
  fields: [
    { name: 'company', type: 'text', label: 'Company', required: true, placeholder: 'Your Business' },
    { name: 'headline', type: 'text', label: 'Headline', required: true, placeholder: 'Storewide Holiday Sale' },
    { name: 'description', type: 'textarea', label: 'Description', placeholder: 'Details about the offer...' },
    { name: 'discountBadge', type: 'text', label: 'Discount Badge', placeholder: '25% OFF', helpText: 'Shown as a badge on the coupon' },
    { name: 'imageUrl', type: 'image', label: 'Image' },
    { name: 'expiresAt', type: 'date', label: 'Expires', helpText: 'When the offer expires' },
    { name: 'redemptionUrl', type: 'url', label: 'Redemption URL', placeholder: 'https://shop.com/redeem' },
    { name: 'terms', type: 'textarea', label: 'Terms & Conditions' },
  ],
  hasFileUpload: true,
  freeTierAllowed: false,
});
