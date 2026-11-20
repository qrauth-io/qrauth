import { describe, it, expect } from 'vitest';

import { buildFlashParts, FLASH_SCRIPT_PATH } from '../flash.js';

describe('buildFlashParts', () => {
  it('emits the hooks for FLASH and an https destination', () => {
    const parts = buildFlashParts('FLASH', 'https://pay.example.com/a?b=1&c="x"', '#10B981');

    expect(parts.headScript).toBe(`<script src="${FLASH_SCRIPT_PATH}" defer></script>`);
    expect(parts.revealAttrs).toContain('data-flash-href="https://pay.example.com/a?b=1&amp;c=%22x%22"');
    expect(parts.continueLine).toContain('Continuing to pay.example.com');
    expect(parts.css).toContain('.trust-reveal.flash');
  });

  it.each<[string, Parameters<typeof buildFlashParts>[0], string]>([
    ['PAGE', 'PAGE', 'https://pay.example.com'],
    ['mode omitted', undefined, 'https://pay.example.com'],
    ['http destination', 'FLASH', 'http://pay.example.com'],
    ['unparseable destination', 'FLASH', 'not a url'],
  ])('emits nothing for %s', (_label, mode, url) => {
    expect(buildFlashParts(mode, url, '#10B981')).toEqual({
      revealAttrs: '',
      headScript: '',
      css: '',
      continueLine: '',
    });
  });
});
