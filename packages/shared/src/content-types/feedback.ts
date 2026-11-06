import { z } from 'zod';
import { registerContentType } from './registry.js';

export const feedbackContentSchema = z.object({
  title: z.string().min(1),
  description: z.string().optional(),
  thanksMessage: z.string().optional(),
  collectName: z.boolean().optional().default(false),
  collectEmail: z.boolean().optional().default(false),
  collectPhone: z.boolean().optional().default(false),
});

registerContentType({
  id: 'feedback',
  label: 'Feedback & Rating',
  description: 'Collect star ratings and comments',
  icon: 'solar:star-bold',
  category: 'interactive',
  schema: feedbackContentSchema,
  fields: [
    { name: 'title', type: 'text', label: 'Question', required: true, placeholder: 'How was your experience?' },
    { name: 'description', type: 'textarea', label: 'Description', placeholder: 'We value your feedback...' },
    { name: 'thanksMessage', type: 'text', label: 'Thank You Message', placeholder: 'Thanks for your feedback!' },
    { name: 'collectName', type: 'switch', label: 'Collect Name', helpText: 'Ask respondents for their name' },
    { name: 'collectEmail', type: 'switch', label: 'Collect Email', helpText: 'Ask respondents for their email' },
    { name: 'collectPhone', type: 'switch', label: 'Collect Phone', helpText: 'Ask respondents for their phone' },
  ],
  hasFileUpload: false,
  freeTierAllowed: false,
});
