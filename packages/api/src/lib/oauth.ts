import { randomBytes } from 'node:crypto';

// ---------------------------------------------------------------------------
// Provider configuration
// ---------------------------------------------------------------------------

export interface OAuthProviderConfig {
  clientId: string;
  clientSecret: string;
  authorizeUrl: string;
  tokenUrl: string;
  userInfoUrl: string;
  scopes: string[];
  // Maps provider-specific user fields to our standard shape
  mapUser: (data: any) => { providerId: string; email: string; name: string; avatarUrl?: string };
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
      userInfoUrl: 'https://www.googleapis.com/oauth2/v2/userinfo',
      scopes: ['openid', 'email', 'profile'],
      mapUser: (d) => ({
        providerId: d.id,
        email: d.email,
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
      mapUser: (d) => ({
        providerId: String(d.id),
        email: d.email || '',
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
      userInfoUrl: 'https://graph.microsoft.com/v1.0/me',
      scopes: ['openid', 'email', 'profile', 'User.Read'],
      mapUser: (d) => ({
        providerId: d.id,
        email: d.mail || d.userPrincipalName || '',
        name: d.displayName || d.mail || '',
        avatarUrl: undefined,
      }),
    };
  }

  if (env('APPLE_CLIENT_ID') && env('APPLE_CLIENT_SECRET')) {
    providers.apple = {
      clientId: env('APPLE_CLIENT_ID'),
      clientSecret: env('APPLE_CLIENT_SECRET'),
      authorizeUrl: 'https://appleid.apple.com/auth/authorize',
      tokenUrl: 'https://appleid.apple.com/auth/token',
      userInfoUrl: '', // Apple returns user info in the ID token
      scopes: ['name', 'email'],
      mapUser: (d) => ({
        providerId: d.sub,
        email: d.email || '',
        name: d.name ? `${d.name.firstName || ''} ${d.name.lastName || ''}`.trim() : d.email || '',
        avatarUrl: undefined,
      }),
    };
  }

  return providers;
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
  });

  return `${p.authorizeUrl}?${params.toString()}`;
}

/**
 * Exchange an authorization code for user info.
 */
export async function exchangeCodeForUser(
  providerName: string,
  code: string,
  callbackUrl: string,
): Promise<{ providerId: string; email: string; name: string; avatarUrl?: string }> {
  const providers = getProviders();
  const p = providers[providerName];
  if (!p) throw new Error(`Unknown OAuth provider: ${providerName}`);

  // Exchange code for access token
  const tokenRes = await fetch(p.tokenUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Accept: 'application/json',
    },
    body: new URLSearchParams({
      client_id: p.clientId,
      client_secret: p.clientSecret,
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

  // For Apple, user info is in the ID token
  if (providerName === 'apple' && tokenData.id_token) {
    const payload = JSON.parse(Buffer.from(tokenData.id_token.split('.')[1], 'base64').toString());
    return p.mapUser(payload);
  }

  // Fetch user info
  const userRes = await fetch(p.userInfoUrl, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: 'application/json',
      'User-Agent': 'vQR-Auth/1.0', // Required by GitHub
    },
  });

  const userData = await userRes.json() as Record<string, any>;

  // GitHub: email might be private, need a separate call
  if (providerName === 'github' && !userData.email) {
    const emailRes = await fetch('https://api.github.com/user/emails', {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        Accept: 'application/json',
        'User-Agent': 'vQR-Auth/1.0',
      },
    });
    const emails = await emailRes.json() as Array<{ email: string; primary: boolean; verified: boolean }>;
    const primary = emails.find((e) => e.primary && e.verified);
    if (primary) userData.email = primary.email;
  }

  return p.mapUser(userData);
}

/**
 * Generate a random state parameter for CSRF protection.
 */
export function generateOAuthState(): string {
  return randomBytes(24).toString('base64url');
}
