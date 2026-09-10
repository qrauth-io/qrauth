import { formatApiErrorMessage } from '@qrauth/node';
import { QRAUTH_CLI_CLIENT_ID } from './constants.js';

/**
 * Error carrying the server's status, machine code, and message so commands can
 * surface CLI_MULTI_ORG / CLI_NO_MEMBERSHIP etc. verbatim.
 */
export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

function joinUrl(base: string, path: string): string {
  return base.replace(/\/+$/, '') + path;
}

/** Normalise any thrown value into a message + machine code for output. */
export function describeError(e: unknown): { message: string; code: string } {
  if (e instanceof ApiError) return { message: e.message, code: e.code };
  if (e instanceof Error) return { message: e.message, code: 'ERROR' };
  return { message: String(e), code: 'ERROR' };
}

async function parseError(res: Response): Promise<ApiError> {
  let code = 'ERROR';
  let message = res.statusText;
  try {
    const body = (await res.json()) as { error?: unknown };
    // `error` carries the machine code (e.g. CLI_MULTI_ORG) when it is a string.
    if (typeof body.error === 'string') code = body.error;
    // `message` may be a string or an array of Zod issues — format defensively
    // so validation errors never surface as "[object Object]".
    message = formatApiErrorMessage(body, res.statusText);
  } catch {
    // non-JSON body; keep statusText
  }
  return new ApiError(res.status, code, message);
}

export interface CreatedSession {
  sessionId: string;
  qrUrl: string;
  status: string;
  expiresAt: string;
}

/** Create a PKCE auth session as the public qrauth-cli client. */
export async function createAuthSession(apiUrl: string, codeChallenge: string): Promise<CreatedSession> {
  const res = await fetch(joinUrl(apiUrl, '/api/v1/auth-sessions'), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Client-Id': QRAUTH_CLI_CLIENT_ID },
    body: JSON.stringify({ codeChallenge, codeChallengeMethod: 'S256', scopes: ['cli'] }),
  });
  if (!res.ok) throw await parseError(res);
  return (await res.json()) as CreatedSession;
}

export interface SessionStatus {
  sessionId: string;
  status: 'PENDING' | 'SCANNED' | 'APPROVED' | 'DENIED' | 'EXPIRED';
}

/** Poll session status, passing the code_verifier (PKCE-bound). */
export async function getAuthSession(
  apiUrl: string,
  sessionId: string,
  codeVerifier: string,
): Promise<SessionStatus> {
  const qs = new URLSearchParams({ code_verifier: codeVerifier }).toString();
  const res = await fetch(joinUrl(apiUrl, `/api/v1/auth-sessions/${encodeURIComponent(sessionId)}?${qs}`), {
    headers: { 'X-Client-Id': QRAUTH_CLI_CLIENT_ID },
  });
  if (!res.ok) throw await parseError(res);
  return (await res.json()) as SessionStatus;
}

export interface ExchangeResult {
  apiKey: string;
  organizationId: string;
  orgSlug: string;
  role: string;
}

/** Exchange an APPROVED session for a minted API key (single-use, PKCE-bound). */
export async function exchangeSession(
  apiUrl: string,
  sessionId: string,
  codeVerifier: string,
  hostLabel?: string,
): Promise<ExchangeResult> {
  const res = await fetch(joinUrl(apiUrl, `/api/v1/auth-sessions/${encodeURIComponent(sessionId)}/exchange`), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Client-Id': QRAUTH_CLI_CLIENT_ID },
    body: JSON.stringify({ code_verifier: codeVerifier, hostLabel }),
  });
  if (!res.ok) throw await parseError(res);
  return (await res.json()) as ExchangeResult;
}

/** Revoke the caller's own API key by presenting it. */
export async function selfRevoke(apiUrl: string, apiKey: string): Promise<void> {
  const res = await fetch(joinUrl(apiUrl, '/api/v1/api-keys/self-revoke'), {
    method: 'POST',
    headers: { 'X-API-Key': apiKey },
  });
  if (!res.ok) throw await parseError(res);
}

// ---------------------------------------------------------------------------
// Ephemeral sessions — org-scoped via the stored API key (ADR-0002 step 8)
// ---------------------------------------------------------------------------

export interface EphemeralCreateInput {
  scopes: string[];
  ttl?: string;
  maxUses?: number;
  deviceBinding?: boolean;
}

export interface EphemeralSession {
  sessionId: string;
  token: string;
  status?: string;
  claimUrl: string | null;
  expiresAt: string;
  scopes: string[];
  ttlSeconds: number;
  maxUses: number;
}

export async function createEphemeral(
  apiUrl: string,
  apiKey: string,
  input: EphemeralCreateInput,
): Promise<EphemeralSession> {
  const res = await fetch(joinUrl(apiUrl, '/api/v1/ephemeral'), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-API-Key': apiKey },
    body: JSON.stringify(input),
  });
  if (!res.ok) throw await parseError(res);
  return (await res.json()) as EphemeralSession;
}

export async function listEphemeral(
  apiUrl: string,
  apiKey: string,
): Promise<{ sessions: EphemeralSession[]; total: number }> {
  const res = await fetch(joinUrl(apiUrl, '/api/v1/ephemeral'), {
    headers: { 'X-API-Key': apiKey },
  });
  if (!res.ok) throw await parseError(res);
  return (await res.json()) as { sessions: EphemeralSession[]; total: number };
}

export async function revokeEphemeral(
  apiUrl: string,
  apiKey: string,
  sessionId: string,
): Promise<{ sessionId: string; status: string }> {
  const res = await fetch(joinUrl(apiUrl, `/api/v1/ephemeral/${encodeURIComponent(sessionId)}`), {
    method: 'DELETE',
    headers: { 'X-API-Key': apiKey },
  });
  if (!res.ok) throw await parseError(res);
  return (await res.json()) as { sessionId: string; status: string };
}
