/**
 * Device type, OS and browser of a scan, from its user agent (ADR-0006 D1),
 * parsed with bowser (MIT). Names only, no versions.
 */
import Bowser from 'bowser';

export interface ScanDevice {
  /** mobile, tablet, desktop, tv or bot; null when unknown. */
  readonly deviceType: string | null;
  readonly os: string | null;
  readonly browser: string | null;
}

export const NO_DEVICE: ScanDevice = Object.freeze({ deviceType: null, os: null, browser: null });

const DEVICE_TYPES: ReadonlySet<string> = new Set(['mobile', 'tablet', 'desktop', 'tv', 'bot']);
/** Column limit on scans.os / scans.browser. */
const NAME_MAX = 64;
/** Longer user agents are cut before parsing; real ones are well under this. */
const USER_AGENT_MAX = 1024;

function name(value: string | undefined): string | null {
  const trimmed = value?.trim();
  return trimmed ? trimmed.slice(0, NAME_MAX) : null;
}

export function parseScanDevice(userAgent: string | null | undefined): ScanDevice {
  if (!userAgent) return NO_DEVICE;
  try {
    const parsed = Bowser.parse(userAgent.slice(0, USER_AGENT_MAX));
    const type = parsed.platform.type?.toLowerCase();
    return {
      deviceType: type && DEVICE_TYPES.has(type) ? type : null,
      os: name(parsed.os.name),
      browser: name(parsed.browser.name),
    };
  } catch {
    return NO_DEVICE;
  }
}
