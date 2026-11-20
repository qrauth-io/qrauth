/**
 * Which browser origins may call the API, and whether with credentials
 * (audit 2026-10 FINDING-023).
 *
 *   - The dashboard's own origins: allowed, with credentials (the refresh
 *     cookie).
 *   - Origins derived from registered apps' redirect URLs: allowed, without
 *     credentials. Any tenant can put an origin on that list by registering
 *     an app, and nothing an embedding site calls needs a cookie: the web
 *     components authenticate with headers.
 *   - `null` (sandboxed frames, file:, and what a custom-scheme redirect URL
 *     reduces to): never.
 *   - No Origin header at all: not a browser cross-origin request; let
 *     through without CORS credentials.
 */
export interface CorsDecision {
  origin: boolean;
  credentials: boolean;
}

const REFUSED: CorsDecision = { origin: false, credentials: false };

export function corsDecision(input: {
  origin: string | undefined;
  builtInOrigins: readonly string[];
  appOrigins: ReadonlySet<string>;
  /** Dev and test: any real origin, as before. */
  permissive: boolean;
}): CorsDecision {
  const { origin } = input;
  if (!origin) return { origin: true, credentials: false };
  if (origin === 'null') return REFUSED;
  if (input.permissive || input.builtInOrigins.includes(origin)) return { origin: true, credentials: true };
  if (input.appOrigins.has(origin)) return { origin: true, credentials: false };
  return REFUSED;
}
