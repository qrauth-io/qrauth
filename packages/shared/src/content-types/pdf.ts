import { z } from 'zod';
import { registerContentType } from './registry.js';

export const pdfContentSchema = z.object({
  title: z.string().min(1),
  description: z.string().optional(),
  fileUrl: z.string(),
});

registerContentType({
  id: 'pdf',
  label: 'PDF Document',
  description: 'Host and share a PDF document',
  icon: 'solar:document-bold',
  category: 'document',
  schema: pdfContentSchema,
  fields: [
    { name: 'title', type: 'text', label: 'Document Title', required: true, placeholder: 'Product Manual' },
    { name: 'description', type: 'textarea', label: 'Description' },
    { name: 'fileUrl', type: 'file', label: 'PDF File', required: true, helpText: 'Upload a PDF (max 20MB)' },
  ],
  hasFileUpload: true,
  freeTierAllowed: false,
});
