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
    { name: 'collectName', type: 'select', label: 'Collect Name', helpText: 'Ask respondents for their name', options: [{ label: 'No', value: 'false' }, { label: 'Yes', value: 'true' }] },
    { name: 'collectEmail', type: 'select', label: 'Collect Email', helpText: 'Ask respondents for their email', options: [{ label: 'No', value: 'false' }, { label: 'Yes', value: 'true' }] },
    { name: 'collectPhone', type: 'select', label: 'Collect Phone', helpText: 'Ask respondents for their phone', options: [{ label: 'No', value: 'false' }, { label: 'Yes', value: 'true' }] },
  ],
  hasFileUpload: false,
  freeTierAllowed: false,
});
