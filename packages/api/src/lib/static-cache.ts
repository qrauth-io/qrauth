// Classifies static asset URLs served from /sdk/v1/ into the two-tier
// caching scheme that mirrors cdn.qrauth.io/v1/:
//   - versioned: components-X.Y.Z[.esm].(js|mjs|map)  → immutable, 1y
//   - pointer:   components[.esm].(js|mjs|map)        → 60s, must-revalidate
// Sourcemaps inherit their sibling JS file's classification by virtue of
// the trailing `.map` matching the (js|mjs|map) extension group.

const VERSIONED =
  /^\/sdk\/v1\/(components|animated-qr)-\d+\.\d+\.\d+(\.[a-z]+)*\.(js|mjs|map)$/;

const POINTER =
  /^\/sdk\/v1\/(components|animated-qr)(\.[a-z]+)*\.(js|mjs|map)$/;

export type StaticPathClass = 'versioned' | 'pointer' | 'other';

export function classifyStaticPath(url: string): StaticPathClass {
  if (VERSIONED.test(url)) return 'versioned';
  if (POINTER.test(url)) return 'pointer';
  return 'other';
}

export function cacheControlFor(klass: StaticPathClass): string | undefined {
  if (klass === 'versioned') return 'public, max-age=31536000, immutable';
  if (klass === 'pointer') return 'public, max-age=60, must-revalidate';
  return undefined;
}
