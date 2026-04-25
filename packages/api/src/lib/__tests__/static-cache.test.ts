import { describe, it, expect } from 'vitest';
import { classifyStaticPath, cacheControlFor } from '../static-cache.js';

describe('classifyStaticPath', () => {
  it('classifies versioned bundles', () => {
    expect(classifyStaticPath('/sdk/v1/components-0.4.0.js')).toBe('versioned');
    expect(classifyStaticPath('/sdk/v1/components-0.4.0.esm.js')).toBe('versioned');
    expect(classifyStaticPath('/sdk/v1/components-0.4.0.js.map')).toBe('versioned');
    expect(classifyStaticPath('/sdk/v1/components-0.4.0.esm.js.map')).toBe('versioned');
    expect(classifyStaticPath('/sdk/v1/animated-qr-0.1.0.js')).toBe('versioned');
    expect(classifyStaticPath('/sdk/v1/animated-qr-0.1.0.esm.js.map')).toBe('versioned');
  });

  it('classifies pointer bundles', () => {
    expect(classifyStaticPath('/sdk/v1/components.js')).toBe('pointer');
    expect(classifyStaticPath('/sdk/v1/components.esm.js')).toBe('pointer');
    expect(classifyStaticPath('/sdk/v1/components.js.map')).toBe('pointer');
    expect(classifyStaticPath('/sdk/v1/components.esm.js.map')).toBe('pointer');
    expect(classifyStaticPath('/sdk/v1/animated-qr.js')).toBe('pointer');
    expect(classifyStaticPath('/sdk/v1/animated-qr.esm.js.map')).toBe('pointer');
  });

  it('does not match arbitrary or out-of-prefix paths', () => {
    expect(classifyStaticPath('/sdk/v1/README.md')).toBe('other');
    expect(classifyStaticPath('/sdk/v1/components.js.txt')).toBe('other');
    expect(classifyStaticPath('/sdk/v2/components.js')).toBe('other');
    expect(classifyStaticPath('/components.js')).toBe('other');
    expect(classifyStaticPath('/sdk/v1/')).toBe('other');
    expect(classifyStaticPath('/sdk/v1/other-bundle.js')).toBe('other');
  });

  it('rejects malformed version suffixes', () => {
    expect(classifyStaticPath('/sdk/v1/components-0.4.js')).toBe('other');
    expect(classifyStaticPath('/sdk/v1/components-v0.4.0.js')).toBe('other');
    expect(classifyStaticPath('/sdk/v1/components-0.4.0-rc.1.js')).toBe('other');
  });
});

describe('cacheControlFor', () => {
  it('returns immutable + 1y for versioned', () => {
    expect(cacheControlFor('versioned')).toBe('public, max-age=31536000, immutable');
  });

  it('returns 60s + must-revalidate for pointer', () => {
    expect(cacheControlFor('pointer')).toBe('public, max-age=60, must-revalidate');
  });

  it('returns undefined for other (defer to defaults)', () => {
    expect(cacheControlFor('other')).toBeUndefined();
  });
});
