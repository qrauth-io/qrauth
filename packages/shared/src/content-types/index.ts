export { CONTENT_TYPE_REGISTRY, getContentType, getAllContentTypes, registerContentType } from './registry.js';
export type { ContentTypeDef, ContentFieldDef } from './registry.js';
export { buildQRPayload } from './qr-payload.js';

// Import all types to trigger registration
import './url.js';
import './vcard.js';
import './coupon.js';
import './event.js';
import './pdf.js';
import './feedback.js';
