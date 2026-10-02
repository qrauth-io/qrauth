import { randomBytes } from 'node:crypto';
import { createRemoteJWKSet, jwtVerify, type JWTPayload } from 'jose';
import { appleKeyConfigFromEnv, getAppleClientSecret } from './apple-client-secret.js';

// ---------------------------------------------------------------------------
// Provider configuration
// ---------------------------------------------------------------------------

/**
 * Identity asserted by an OAuth provider, normalized across providers.
 *
 * `emailVerified` is true only when the PROVIDER vouches that the user
 * controls `email`. The callback links an existing QRAuth account by email
 * (and creates new accounts) only when it is true — an unverified email must
 * never be trusted for account matching (nOAuth class).
 */
export interface OAuthUser {
  providerId: string;
  email: string;
  emailVerified: boolean;
  name: string;
  avatarUrl?: string;
  /** Microsoft only: a personal account (Outlook, Hotmail, Live). These never send `xms_edov`. */
  personalMicrosoftAccount?: boolean;
}

/**
 * Every personal Microsoft account signs in through this one fixed tenant
 * ("consumers"); work and school accounts have their organisation's tenant.
 */
export const MICROSOFT_CONSUMER_TENANT_ID = '9188040d-6c67-4c5b-b112-36a304b66dad';

export interface OAuthProviderConfig {
  clientId: string;
  clientSecret: string;
  /** When set, called for a fresh client secret at each token exchange (Apple). */
  resolveClientSecret?: () => Promise<string>;
  authorizeUrl: string;
  tokenUrl: string;
  userInfoUrl: string;
  scopes: string[];
  // Maps provider-specific user fields to our standard shape
  mapUser: (data: any) => OAuthUser;
}

function env(key: string): string {
  return process.env[key] || '';
}

export function getProviders(): Record<string, OAuthProviderConfig> {
  const providers: Record<string, OAuthProviderConfig> = {};

  if (env('GOOGLE_CLIENT_ID') && env('GOOGLE_CLIENT_SECRET')) {
    providers.google = {
      clientId: env('GOOGLE_CLIENT_ID'),
      clientSecret: env('GOOGLE_CLIENT_SECRET'),
      authorizeUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
      tokenUrl: 'https://oauth2.googleapis.com/token',
      // v2 userinfo kept (not the OIDC endpoint) so `id` — the providerId
      // every existing Google user is keyed on — is unchanged; it carries
      // Google's `verified_email` flag.
      userInfoUrl: 'https://www.googleapis.com/oauth2/v2/userinfo',
      scopes: ['openid', 'email', 'profile'],
      mapUser: (d) => ({
        providerId: d.id,
        email: d.email || '',
        emailVerified: d.verified_email === true,
        name: d.name || d.email,
        avatarUrl: d.picture,
      }),
    };
  }

  if (env('GITHUB_CLIENT_ID') && env('GITHUB_CLIENT_SECRET')) {
    providers.github = {
      clientId: env('GITHUB_CLIENT_ID'),
      clientSecret: env('GITHUB_CLIENT_SECRET'),
      authorizeUrl: 'https://github.com/login/oauth/authorize',
      tokenUrl: 'https://github.com/login/oauth/access_token',
      userInfoUrl: 'https://api.github.com/user',
      scopes: ['read:user', 'user:email'],
      // exchangeCodeForUser attaches the /user/emails list as `emails`; the
      // public profile `email` alone is never trusted.
      mapUser: (d) => ({
        providerId: String(d.id),
        ...pickGithubEmail(d.email, d.emails),
        name: d.name || d.login,
        avatarUrl: d.avatar_url,
      }),
    };
  }

  if (env('MICROSOFT_CLIENT_ID') && env('MICROSOFT_CLIENT_SECRET')) {
    providers.microsoft = {
      clientId: env('MICROSOFT_CLIENT_ID'),
      clientSecret: env('MICROSOFT_CLIENT_SECRET'),
      authorizeUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
      tokenUrl: 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
      // Identity comes ONLY from the verified id_token (verifyMicrosoftIdToken),
      // never from Graph `mail`/`userPrincipalName`, which any tenant admin
      // can set to an arbitrary address.
      userInfoUrl: '',
      scopes: ['openid', 'email', 'profile'],
      mapUser: (d) => ({
        providerId: d.oid,
        email: typeof d.email === 'string' ? d.email : '',
        // Domain-owner verified per Microsoft; requires the `email` and
        // `xms_edov` optional ID-token claims on the app registration. Absent
        // or anything but `true` (incl. personal accounts) = unverified.
        emailVerified: d.xms_edov === true,
        name: d.name || d.email || '',
        avatarUrl: undefined,
        personalMicrosoftAccount: d.tid === MICROSOFT_CONSUMER_TENANT_ID,
      }),
    };
  }

  // Preferred: sign the client secret from the .p8 key (never expires on us).
  // Fallback: a pre-made APPLE_CLIENT_SECRET JWT, which Apple caps at 6 months.
  const appleKey = appleKeyConfigFromEnv(env);
  if (env('APPLE_CLIENT_ID') && (appleKey || env('APPLE_CLIENT_SECRET'))) {
    providers.apple = {
      clientId: env('APPLE_CLIENT_ID'),
      clientSecret: appleKey ? '' : env('APPLE_CLIENT_SECRET'),
      ...(appleKey ? { resolveClientSecret: () => getAppleClientSecret(appleKey) } : {}),
      authorizeUrl: 'https://appleid.apple.com/auth/authorize',
      tokenUrl: 'https://appleid.apple.com/auth/token',
      userInfoUrl: '', // Apple returns user info in the ID token
      scopes: ['name', 'email'],
      mapUser: (d) => ({
        providerId: d.sub,
        email: d.email || '',
        emailVerified: d.email_verified === true || d.email_verified === 'true',
        name: d.name ? `${d.name.firstName || ''} ${d.name.lastName || ''}`.trim() : d.email || '',
        avatarUrl: undefined,
      }),
    };
  }

  return providers;
}

// Public JWKS endpoints for ID token verification.
// Cached by jose's createRemoteJWKSet (respects Cache-Control headers).
const APPLE_JWKS = createRemoteJWKSet(
  new URL('https://appleid.apple.com/auth/keys'),
);
const MICROSOFT_JWKS = createRemoteJWKSet(
  new URL('https://login.microsoftonline.com/common/discovery/v2.0/keys'),
);

type JwksKeyResolver = Parameters<typeof jwtVerify>[1];

const GUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * GitHub: the email is the PRIMARY address that GitHub marks `verified`,
 * from /user/emails. Without one, fall back to the profile email (or none)
 * flagged unverified so the callback refuses to match on it.
 */
export function pickGithubEmail(
  profileEmail: unknown,
  emails: unknown,
): { email: string; emailVerified: boolean } {
  const list = Array.isArray(emails) ? emails as Array<{ email?: unknown; primary?: unknown; verified?: unknown }> : [];
  const primary = list.find((e) => e.primary === true && e.verified === true && typeof e.email === 'string');
  if (primary) return { email: primary.email as string, emailVerified: true };
  return { email: typeof profileEmail === 'string' ? profileEmail : '', emailVerified: false };
}

/**
 * Verify an Apple id_token (Audit-4 A4-H1): RS256 against Apple's JWKS,
 * issuer and audience pinned, `exp` required.
 */
export async function verifyAppleIdToken(
  idToken: string,
  clientId: string,
  jwks: JwksKeyResolver = APPLE_JWKS,
): Promise<JWTPayload> {
  try {
    const { payload } = await jwtVerify(idToken, jwks, {
      algorithms: ['RS256'],
      issuer: 'https://appleid.apple.com',
      audience: clientId,
      requiredClaims: ['exp'],
    });
    return payload;
  } catch (err) {
    throw new Error(
      `Apple ID token verification failed: ${err instanceof Error ? err.message : 'unknown error'}`,
    );
  }
}

/**
 * Verify a Microsoft identity platform v2.0 id_token from the multi-tenant
 * `/common` endpoint: RS256 against the common JWKS, `aud` = our client id,
 * `exp` required, and — because `/common` serves every tenant — the issuer
 * must be exactly `https://login.microsoftonline.com/{tid}/v2.0` for the
 * token's own GUID `tid`. `oid` (the user's immutable object id) is required.
 */
export async function verifyMicrosoftIdToken(
  idToken: string,
  clientId: string,
  jwks: JwksKeyResolver = MICROSOFT_JWKS,
): Promise<JWTPayload> {
  try {
    const { payload } = await jwtVerify(idToken, jwks, {
      algorithms: ['RS256'],
      audience: clientId,
      requiredClaims: ['exp', 'iss', 'tid', 'oid'],
    });
    const tid = payload.tid;
    if (typeof tid !== 'string' || !GUID_RE.test(tid)) {
      throw new Error('tid is not a tenant GUID');
    }
    if (payload.iss !== `https://login.microsoftonline.com/${tid}/v2.0`) {
      throw new Error('issuer does not match tenant');
    }
    if (typeof payload.oid !== 'string' || !payload.oid) {
      throw new Error('oid missing');
    }
    return payload;
  } catch (err) {
    throw new Error(
      `Microsoft ID token verification failed: ${err instanceof Error ? err.message : 'unknown error'}`,
    );
  }
}

export function getEnabledProviderNames(): string[] {
  return Object.keys(getProviders());
}

/**
 * Generate the OAuth authorization URL for a provider.
 */
export function buildAuthUrl(
  providerName: string,
  callbackUrl: string,
  state: string,
): string {
  const providers = getProviders();
  const p = providers[providerName];
  if (!p) throw new Error(`Unknown OAuth provider: ${providerName}`);

  const params = new URLSearchParams({
    client_id: p.clientId,
    redirect_uri: callbackUrl,
    response_type: 'code',
    scope: p.scopes.join(' '),
    state,
    ...(providerName === 'google' ? { access_type: 'offline', prompt: 'select_account' } : {}),
    ...(providerName === 'apple' ? { response_mode: 'form_post' } : {}),
    // Always show Microsoft's account picker; otherwise it silently reuses whatever
    // account the browser is signed into (often a personal one) with no way to switch.
    ...(providerName === 'microsoft' ? { prompt: 'select_account' } : {}),
  });

  // URLSearchParams encodes spaces as '+'. Apple does not decode '+' in the
  // scope, so "name email" was ignored and Apple never asked the user to
  // share or hide their email (or sent their name). Send spaces as %20, which
  // every provider accepts. A literal '+' is already encoded as %2B, so this
  // only touches spaces.
  return `${p.authorizeUrl}?${params.toString().replace(/\+/g, '%20')}`;
}

/**
 * Apple sends the user's name only on the FIRST authorisation, as a JSON
 * `user` form field next to the code (never in the ID token). Use it when present.
 */
export function withAppleFormPostName(oauthUser: OAuthUser, rawUserField: unknown): OAuthUser {
  if (typeof rawUserField !== 'string' || rawUserField === '') return oauthUser;
  try {
    const parsed = JSON.parse(rawUserField) as { name?: { firstName?: unknown; lastName?: unknown } };
    const parts = [parsed.name?.firstName, parsed.name?.lastName]
      .filter((v): v is string => typeof v === 'string' && v.trim() !== '')
      .map((v) => v.trim());
    return parts.length > 0 ? { ...oauthUser, name: parts.join(' ').slice(0, 200) } : oauthUser;
  } catch {
    return oauthUser;
  }
}

/**
 * Exchange an authorization code for user info.
 */
export async function exchangeCodeForUser(
  providerName: string,
  code: string,
  callbackUrl: string,
): Promise<OAuthUser> {
  const providers = getProviders();
  const p = providers[providerName];
  if (!p) throw new Error(`Unknown OAuth provider: ${providerName}`);

  const clientSecret = p.resolveClientSecret ? await p.resolveClientSecret() : p.clientSecret;

  // Exchange code for access token
  const tokenRes = await fetch(p.tokenUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Accept: 'application/json',
    },
    body: new URLSearchParams({
      client_id: p.clientId,
      client_secret: clientSecret,
      code,
      redirect_uri: callbackUrl,
      grant_type: 'authorization_code',
    }),
  });

  const tokenData = await tokenRes.json() as Record<string, any>;
  const accessToken = tokenData.access_token;

  if (!accessToken) {
    throw new Error(`OAuth token exchange failed: ${tokenData.error_description || tokenData.error || 'unknown error'}`);
  }

  // For Apple and Microsoft, user info comes from the ID token, trusted only
  // after signature + claim verification (a forged or cross-tenant id_token
  // could otherwise impersonate any user).
  if (providerName === 'apple' && tokenData.id_token) {
    return p.mapUser(await verifyAppleIdToken(tokenData.id_token, p.clientId));
  }
  if (providerName === 'microsoft') {
    if (typeof tokenData.id_token !== 'string') {
      throw new Error('Microsoft token response did not include an id_token');
    }
    return p.mapUser(await verifyMicrosoftIdToken(tokenData.id_token, p.clientId));
  }

  // Fetch user info
  const userRes = await fetch(p.userInfoUrl, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: 'application/json',
      'User-Agent': 'QRAuth/1.0', // Required by GitHub
    },
  });

  const userData = await userRes.json() as Record<string, any>;

  // GitHub: always read /user/emails — only GitHub's verified primary
  // address is trusted (see pickGithubEmail), never the profile email alone.
  if (providerName === 'github') {
    const emailRes = await fetch('https://api.github.com/user/emails', {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        Accept: 'application/json',
        'User-Agent': 'QRAuth/1.0',
      },
    });
    const emails = emailRes.ok ? await emailRes.json() : [];
    return p.mapUser({ ...userData, emails });
  }

  return p.mapUser(userData);
}

/**
 * Generate a random state parameter for CSRF protection.
 */
export function generateOAuthState(): string {
  return randomBytes(24).toString('base64url');
}
