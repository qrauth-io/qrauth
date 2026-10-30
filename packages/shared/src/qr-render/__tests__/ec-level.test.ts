// SPDX-License-Identifier: MIT
import { describe, expect, it } from 'vitest';

import { renderQrCore } from '../core.js';
import { encode, type EcLevel } from '../matrix.js';
import { URL_28 } from './golden-cases.js';

describe('EC level validation', () => {
  it.each(['M', 'Q', 'H'] as const)('encodes at %s', (level) => {
    expect(encode(URL_28, level).ecLevel).toBe(level);
  });

  it.each(['L', 'bogus', 'm', '', null, undefined, 1])('rejects %j instead of falling back', (level) => {
    expect(() => encode(URL_28, level as unknown as EcLevel)).toThrow(/qr-render: ecLevel must be one of M, Q, H/);
  });

  it.each(['L', 'bogus'])('the core renderer rejects %j from a JavaScript caller', (level) => {
    expect(() => renderQrCore(URL_28, { ecLevel: level as unknown as EcLevel })).toThrow(/qr-render: ecLevel/);
  });
});
