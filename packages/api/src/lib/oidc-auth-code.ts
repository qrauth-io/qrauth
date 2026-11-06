import { randomBytes } from 'node:crypto';
import type { PrismaClient } from '@prisma/client';
import { hashString } from './crypto.js';

/**
 * Authorization code lifetime: 60 seconds. The relying party redeems the
 * code as soon as the browser returns to it; anything longer only widens the
 * window for a leaked code (audit 2026-10 FINDING-018).
 */
export const AUTH_CODE_TTL_SECONDS = 60;

export interface IssueAuthCodeParams {
  oidcClientId: string;
  userId: string;
  redirectUri: string;
  scopes: readonly string[];
  /** S256 challenge, or undefined when a confidential client used no PKCE. */
  codeChallenge?: string;
  nonce?: string;
  authTime: Date;
}

/**
 * Mint a single-use authorization code and store only its hash. Shared by
 * /authorize (consent already on record, or a FIRST_PARTY client) and the
 * consent Approve handler, so the two paths cannot drift.
 */
export async function issueAuthorizationCode(
  prisma: Pick<PrismaClient, 'oidcAuthCode'>,
  params: IssueAuthCodeParams,
): Promise<string> {
  const code = randomBytes(32).toString('base64url');
  await prisma.oidcAuthCode.create({
    data: {
      codeHash: hashString(code),
      oidcClientId: params.oidcClientId,
      userId: params.userId,
      redirectUri: params.redirectUri,
      scope: params.scopes.join(' '),
      // Empty string = no-PKCE sentinel (confidential client). A real S256
      // challenge is never empty; /token treats falsy codeChallenge as "no
      // PKCE" and skips verifier checking. Avoids a nullable migration.
      codeChallenge: params.codeChallenge ?? '',
      codeChallengeMethod: 'S256',
      nonce: params.nonce ?? null,
      authTime: params.authTime,
      expiresAt: new Date(Date.now() + AUTH_CODE_TTL_SECONDS * 1000),
    },
  });
  return code;
}
