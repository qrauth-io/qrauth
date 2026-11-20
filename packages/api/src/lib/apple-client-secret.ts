import { readFileSync } from 'node:fs';
import { SignJWT, importPKCS8 } from 'jose';

/**
 * Apple's OAuth "client secret" is an ES256 JWT signed with the team's Sign in
 * with Apple key (.p8), valid for at most 6 months. A hand-made one pasted into
 * APPLE_CLIENT_SECRET silently expires (it did on 2026-09-28), so we sign it
 * here from the key and re-sign it before it runs out.
 */

/** Well inside Apple's 6-month maximum. */
const SECRET_LIFETIME_SECONDS = 30 * 24 * 60 * 60;
/** Re-sign this long before expiry. */
const REFRESH_MARGIN_SECONDS = 24 * 60 * 60;

export interface AppleKeyConfig {
  teamId: string;
  keyId: string;
  clientId: string;
  /** Either the PEM itself or a path to the .p8 file. */
  privateKey?: string;
  privateKeyPath?: string;
}

/**
 * Key-based config from the environment, or null when it is incomplete.
 * APPLE_PRIVATE_KEY may hold the PEM with literal "\n" (single-line env files).
 */
export function appleKeyConfigFromEnv(env: (key: string) => string): AppleKeyConfig | null {
  const teamId = env('APPLE_TEAM_ID');
  const keyId = env('APPLE_KEY_ID');
  const clientId = env('APPLE_CLIENT_ID');
  const privateKey = env('APPLE_PRIVATE_KEY');
  const privateKeyPath = env('APPLE_PRIVATE_KEY_PATH');
  if (!teamId || !keyId || !clientId || (!privateKey && !privateKeyPath)) return null;
  return {
    teamId,
    keyId,
    clientId,
    ...(privateKey ? { privateKey } : { privateKeyPath }),
  };
}

let cached: { configKey: string; secret: string; expiresAt: number } | null = null;

function configKey(config: AppleKeyConfig): string {
  return [config.teamId, config.keyId, config.clientId, config.privateKeyPath ?? 'inline'].join('|');
}

function readPem(config: AppleKeyConfig): string {
  const pem = config.privateKey ?? readFileSync(config.privateKeyPath!, 'utf8');
  return pem.replace(/\\n/g, '\n');
}

export async function getAppleClientSecret(
  config: AppleKeyConfig,
  nowSeconds: number = Math.floor(Date.now() / 1000),
): Promise<string> {
  const key = configKey(config);
  if (cached && cached.configKey === key && cached.expiresAt - REFRESH_MARGIN_SECONDS > nowSeconds) {
    return cached.secret;
  }

  const signingKey = await importPKCS8(readPem(config), 'ES256');
  const expiresAt = nowSeconds + SECRET_LIFETIME_SECONDS;
  const secret = await new SignJWT({})
    .setProtectedHeader({ alg: 'ES256', kid: config.keyId })
    .setIssuer(config.teamId)
    .setSubject(config.clientId)
    .setAudience('https://appleid.apple.com')
    .setIssuedAt(nowSeconds)
    .setExpirationTime(expiresAt)
    .sign(signingKey);

  cached = { configKey: key, secret, expiresAt };
  return secret;
}

/** Tests only. */
export function resetAppleClientSecretCache(): void {
  cached = null;
}
