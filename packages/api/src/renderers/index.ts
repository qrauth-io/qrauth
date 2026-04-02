export interface RenderContext {
  qrCode: {
    token: string;
    contentType: string;
    content: unknown;
    label?: string | null;
    destinationUrl: string;
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

export function getRenderer(contentType: string): ContentRenderer | undefined {
  return renderers[contentType];
}

// Import renderers to trigger registration
import './url.js';
import './vcard.js';
