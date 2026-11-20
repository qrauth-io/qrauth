import { describe, expect, it } from 'vitest';

import { frameChangeRefusal, isGrandfatheredCaption, planAllowsFrame } from '../index.js';

/** Frames (ADR-0005 D9): anything but `none` needs a paid plan. */
describe('planAllowsFrame', () => {
  it.each(['caption', 'banner-bottom', 'banner-top', 'rounded-label', 'badge'])('FREE may not save a %s frame', (template) => {
    expect(planAllowsFrame('FREE', template)).toBe(false);
    for (const plan of ['PRO', 'BUSINESS', 'ENTERPRISE']) expect(planAllowsFrame(plan, template)).toBe(true);
  });

  it('no frame, or `none`, is allowed on every plan', () => {
    expect(planAllowsFrame('FREE', undefined)).toBe(true);
    expect(planAllowsFrame('FREE', 'none')).toBe(true);
  });

  it('an unknown plan is treated as FREE', () => {
    expect(planAllowsFrame('GOLD', 'badge')).toBe(false);
  });
});

/**
 * Caption grandfathering (ADR-0005 D9, amendment of 2026-10-30): on FREE, a
 * code whose stored frame is a caption may change the caption's text only,
 * or remove the frame; adding a frame or changing a template stays paid.
 */
describe('frameChangeRefusal', () => {
  const CAPTION = { template: 'caption', text: 'QRAuth Verified', color: '#FFFFFF', textColor: '#000000' };

  it('FREE may not add a frame to a style without one, nor create a code with one', () => {
    for (const template of ['caption', 'banner-bottom', 'badge']) {
      expect(frameChangeRefusal('FREE', null, { ...CAPTION, template })).toBe('plan');
      expect(frameChangeRefusal('FREE', { template: 'none' }, { ...CAPTION, template })).toBe('plan');
    }
  });

  it('FREE with a stored caption may edit its text', () => {
    expect(frameChangeRefusal('FREE', CAPTION, { ...CAPTION, text: 'Σαρώστε με' })).toBeNull();
    // Colours compare case-insensitively, as canonical styles do.
    expect(frameChangeRefusal('FREE', CAPTION, { ...CAPTION, color: '#ffffff', text: 'x' })).toBeNull();
  });

  it('FREE with a stored caption may remove the frame', () => {
    expect(frameChangeRefusal('FREE', CAPTION, { ...CAPTION, template: 'none' })).toBeNull();
    expect(frameChangeRefusal('FREE', CAPTION, undefined)).toBeNull();
  });

  it.each([
    ['the template', { ...CAPTION, template: 'banner-bottom' }],
    ['the text colour', { ...CAPTION, textColor: '#1B2A4A' }],
    ['the frame colour', { ...CAPTION, color: '#000000' }],
  ])('FREE with a stored caption may not change %s', (_label, next) => {
    expect(frameChangeRefusal('FREE', CAPTION, next)).toBe('caption-locked');
  });

  it('a stored frame other than a caption is not grandfathered on FREE', () => {
    const banner = { ...CAPTION, template: 'banner-bottom' };
    expect(isGrandfatheredCaption(banner)).toBe(false);
    expect(frameChangeRefusal('FREE', banner, { ...banner, text: 'other' })).toBe('plan');
    expect(frameChangeRefusal('FREE', banner, { ...banner, template: 'none' })).toBeNull();
  });

  it.each(['PRO', 'BUSINESS', 'ENTERPRISE'])('%s may save any frame change', (plan) => {
    expect(frameChangeRefusal(plan, null, { ...CAPTION, template: 'badge' })).toBeNull();
    expect(frameChangeRefusal(plan, CAPTION, { ...CAPTION, template: 'banner-top', color: '#000000' })).toBeNull();
  });
});
