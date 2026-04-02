import { z } from 'zod';

export interface ContentFieldDef {
  name: string;
  type: 'text' | 'textarea' | 'url' | 'email' | 'phone' | 'date' | 'datetime' | 'number' | 'image' | 'file' | 'select' | 'address' | 'social-links';
  label: string;
  placeholder?: string;
  required?: boolean;
  group?: string;
  helpText?: string;
  options?: Array<{ label: string; value: string }>; // For select type
}

export interface ContentTypeDef {
  id: string;
  label: string;
  description: string;
  icon: string;
  category: 'link' | 'contact' | 'marketing' | 'document' | 'social' | 'interactive';
  schema: z.ZodType;
  fields: ContentFieldDef[];
  hasFileUpload: boolean;
  freeTierAllowed: boolean;
}

export const CONTENT_TYPE_REGISTRY: Record<string, ContentTypeDef> = {};

export function registerContentType(def: ContentTypeDef): void {
  CONTENT_TYPE_REGISTRY[def.id] = def;
}

export function getContentType(id: string): ContentTypeDef | undefined {
  return CONTENT_TYPE_REGISTRY[id];
}

export function getAllContentTypes(): ContentTypeDef[] {
  return Object.values(CONTENT_TYPE_REGISTRY);
}
