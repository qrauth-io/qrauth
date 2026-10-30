import type { TrustState } from './trust-state.js';

/** Browser scan behaviour; mirrors the Prisma `ScanMode` enum. */
export type ScanMode = 'FLASH' | 'PAGE';

export interface ScanModeInput {
  /** The code's stored setting. Anything other than FLASH means PAGE. */
  configured: string | null | undefined;
  trustState: TrustState;
  contentType: string;
  destinationUrl: string;
  /** Code has a registered location (lat/lng), enforced or advisory. */
  locationBound: boolean;
}

function isHttpsUrl(value: string): boolean {
  try {
    return new URL(value).protocol === 'https:';
  } catch {
    return false;
  }
}

/**
 * The scan mode a browser actually gets for this scan.
 *
 * FLASH only when every condition holds: the code is set to FLASH, the scan
 * is VERIFIED, the content type is url, the destination is https, and the
 * code has no location binding (its page runs a client-side GPS check).
 * Everything else is PAGE, so neutral and UNTRUSTED results never continue
 * on their own.
 */
export function resolveScanMode(input: ScanModeInput): ScanMode {
  const isFlash =
    input.configured === 'FLASH' &&
    input.trustState === 'VERIFIED' &&
    input.contentType === 'url' &&
    !input.locationBound &&
    isHttpsUrl(input.destinationUrl);
  return isFlash ? 'FLASH' : 'PAGE';
}
