import { describe, it, expect } from 'vitest';

import { resolveScanMode, type ScanModeInput } from '../scan-mode.js';

const FLASH_CASE: ScanModeInput = {
  configured: 'FLASH',
  trustState: 'VERIFIED',
  contentType: 'url',
  destinationUrl: 'https://pay.example.com/checkout',
  locationBound: false,
};

describe('resolveScanMode', () => {
  it('FLASH for a VERIFIED https URL code set to FLASH without a location', () => {
    expect(resolveScanMode(FLASH_CASE)).toBe('FLASH');
  });

  it.each<[string, Partial<ScanModeInput>]>([
    ['setting PAGE', { configured: 'PAGE' }],
    ['setting missing', { configured: undefined }],
    ['setting unknown', { configured: 'REDIRECT' }],
    ['SIGNED_UNVERIFIED_ISSUER', { trustState: 'SIGNED_UNVERIFIED_ISSUER' }],
    ['UNTRUSTED', { trustState: 'UNTRUSTED' }],
    ['non-URL content type', { contentType: 'coupon' }],
    ['http destination', { destinationUrl: 'http://pay.example.com/checkout' }],
    ['non-http destination', { destinationUrl: 'javascript:alert(1)' }],
    ['unparseable destination', { destinationUrl: 'not a url' }],
    ['location-bound', { locationBound: true }],
  ])('PAGE when %s', (_label, change) => {
    expect(resolveScanMode({ ...FLASH_CASE, ...change })).toBe('PAGE');
  });
});
