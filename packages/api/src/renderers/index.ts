export interface RenderContext {
  qrCode: {
    token: string;
    contentType: string;
    content: unknown;
    label?: string | null;
    destinationUrl: string;
    latitude?: number | null;
    longitude?: number | null;
    createdAt: Date;
  };
  organization: {
    id: string;
    name: string;
    slug: string;
    trustLevel: string;
    kycStatus: string;
    domainVerified: boolean;
  };
  verified: boolean;
  reason?: string;
  security: {
    signatureValid: boolean;
    proxyDetected: boolean;
    trustScore: number;
    transparencyLogVerified: boolean;
  };
  locationMatch: {
    matched: boolean;
    distanceM: number | null;
    registeredAddress: string | null;
  };
  ephemeralProof?: {
    city: string;
    device: string;
    timestamp: string;
    fingerprint: string;
  };
  domainWarning?: {
    message: string;
    similar_to: string;
    verified_org: string;
  };
  scannedAt: string;
  assetBaseUrl: string;
}

type ContentRenderer = (ctx: RenderContext) => string;

const renderers: Record<string, ContentRenderer> = {};

export function registerRenderer(contentType: string, renderer: ContentRenderer): void {
  renderers[contentType] = renderer;
}

let initialized = false;

export async function getRenderer(contentType: string): Promise<ContentRenderer | undefined> {
  if (!initialized) {
    // Lazy-load renderers to avoid circular initialization
    const urlMod = await import('./url.js');
    const vcardMod = await import('./vcard.js');
    const couponMod = await import('./coupon.js');
    const eventMod = await import('./event.js');
    const pdfMod = await import('./pdf.js');
    const feedbackMod = await import('./feedback.js');
    if (urlMod.default) registerRenderer('url', urlMod.default);
    if (vcardMod.default) registerRenderer('vcard', vcardMod.default);
    if (couponMod.default) registerRenderer('coupon', couponMod.default);
    if (eventMod.default) registerRenderer('event', eventMod.default);
    if (pdfMod.default) registerRenderer('pdf', pdfMod.default);
    if (feedbackMod.default) registerRenderer('feedback', feedbackMod.default);
    initialized = true;
  }
  return renderers[contentType];
}
