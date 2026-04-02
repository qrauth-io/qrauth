import { z } from 'zod';
import { registerContentType } from './registry.js';

export const eventContentSchema = z.object({
  title: z.string().min(1),
  description: z.string().optional(),
  imageUrl: z.string().optional(),
  startDate: z.string(),
  endDate: z.string().optional(),
  location: z.string().optional(),
  address: z.string().optional(),
  organizer: z.string().optional(),
  contactEmail: z.string().email().optional(),
  website: z.string().url().optional().or(z.literal('')),
});

registerContentType({
  id: 'event',
  label: 'Event',
  description: 'Event details with RSVP and calendar add',
  icon: 'solar:calendar-bold',
  category: 'marketing',
  schema: eventContentSchema,
  fields: [
    { name: 'title', type: 'text', label: 'Event Title', required: true, placeholder: '4th Annual Company Meetup' },
    { name: 'description', type: 'textarea', label: 'Description' },
    { name: 'imageUrl', type: 'image', label: 'Cover Image' },
    { name: 'startDate', type: 'datetime', label: 'Start Date & Time', required: true },
    { name: 'endDate', type: 'datetime', label: 'End Date & Time' },
    { name: 'location', type: 'text', label: 'Venue Name', placeholder: 'Conference Center' },
    { name: 'address', type: 'text', label: 'Address', placeholder: '123 Main St, City' },
    { name: 'organizer', type: 'text', label: 'Organizer' },
    { name: 'contactEmail', type: 'email', label: 'Contact Email' },
    { name: 'website', type: 'url', label: 'Event Website' },
  ],
  hasFileUpload: true,
  freeTierAllowed: false,
});
