import type { TrustState } from '../services/trust-state.js';
import type { ScanMode } from '../services/scan-mode.js';
import type { Platform } from '../services/platform.js';

/** Screening state of one link of a smart link or link list code. */
export interface LinkState {
  /** Web Risk lists it (qr_code_link_flags): the page hides the entry. */
  flagged: boolean;
  /** It looks like this verified organization's domain (lookalike check). */
  lookalike?: { similarTo: string; verifiedOrg: string; reason?: string; scripts?: string[]; source?: 'curated' | 'verified' };
}

export interface RenderContext {
  /**
   * Per-response CSP nonce (F-007). Generated once per verify response in
   * routes/verify.ts and threaded into BOTH the CSP header and every inline
   * `<style>`/`<script>` tag the shell and content renderers emit — so no
   * directive needs `'unsafe-inline'`. The SAME value must appear in the
   * header and every nonced tag.
   */
  nonce: string;
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
    /** Org domain; shown on the VERIFIED page only when domainVerified. */
    domain?: string | null;
  };
  /** Single source of truth for every trust visual on the page. */
  trustState: TrustState;
  /** Resolved scan mode (services/scan-mode.ts). Omitted means PAGE. */
  scanMode?: ScanMode;
  /** trustState === 'VERIFIED'. */
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
    reason?: string;
    similar_to: string;
    verified_org: string;
  };
  scannedAt: string;
  assetBaseUrl: string;
  /** Smart link: the scanner's platform, from the User-Agent. */
  platform?: Platform;
  /** Smart link and link list: each link's screening state, keyed by the URL as stored. */
  links?: Record<string, LinkState>;
  /**
   * Scan mode FLASH: where the flash continues. Defaults to
   * qrCode.destinationUrl; a smart link sets its platform's URL.
   */
  continueUrl?: string;
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
    const appLinkMod = await import('./app-link.js');
    const linkListMod = await import('./link-list.js');
    if (urlMod.default) registerRenderer('url', urlMod.default);
    if (vcardMod.default) registerRenderer('vcard', vcardMod.default);
    if (couponMod.default) registerRenderer('coupon', couponMod.default);
    if (eventMod.default) registerRenderer('event', eventMod.default);
    if (pdfMod.default) registerRenderer('pdf', pdfMod.default);
    if (feedbackMod.default) registerRenderer('feedback', feedbackMod.default);
    if (appLinkMod.default) registerRenderer('app-link', appLinkMod.default);
    if (linkListMod.default) registerRenderer('link-list', linkListMod.default);
    initialized = true;
  }
  return renderers[contentType];
}
