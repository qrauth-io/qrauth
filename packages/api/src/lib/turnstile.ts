import { config } from './config.js';

/**
 * Cloudflare Turnstile server-side check (siteverify).
 * https://developers.cloudflare.com/turnstile/get-started/server-side-validation/
 */

const SITEVERIFY_URL = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
const SITEVERIFY_TIMEOUT_MS = 5_000;

export type TurnstileResult =
  | { outcome: 'passed' }
  | { outcome: 'failed'; errorCodes: string[] }
  /** Cloudflare could not be reached or answered unexpectedly. */
  | { outcome: 'unavailable'; detail: string };

export async function verifyTurnstileToken(
  secretKey: string,
  token: string,
  remoteIp: string | undefined,
  fetchImpl: typeof fetch = fetch,
): Promise<TurnstileResult> {
  const form = new URLSearchParams({ secret: secretKey, response: token });
  if (remoteIp) form.set('remoteip', remoteIp);

  let res: Response;
  try {
    res = await fetchImpl(SITEVERIFY_URL, {
      method: 'POST',
      body: form,
      signal: AbortSignal.timeout(SITEVERIFY_TIMEOUT_MS),
    });
  } catch (err) {
    return { outcome: 'unavailable', detail: err instanceof Error ? err.message : String(err) };
  }
  if (!res.ok) return { outcome: 'unavailable', detail: `siteverify HTTP ${res.status}` };

  let body: { success?: unknown; 'error-codes'?: unknown };
  try {
    body = (await res.json()) as typeof body;
  } catch {
    return { outcome: 'unavailable', detail: 'siteverify returned non-JSON' };
  }
  if (body.success === true) return { outcome: 'passed' };
  const codes = Array.isArray(body['error-codes']) ? body['error-codes'].map(String) : [];
  return { outcome: 'failed', errorCodes: codes };
}

export interface TurnstileRefusal {
  statusCode: 400 | 503;
  error: string;
  message: string;
}

interface TurnstileLog {
  info: (obj: Record<string, unknown>, msg: string) => void;
  warn: (obj: Record<string, unknown>, msg: string) => void;
}

/**
 * Turnstile gate for a public form (signup, abuse report). Call it only when
 * config.turnstile.enabled. Returns null when the token passes, otherwise the
 * refusal to send: 400 for a missing or failed token, 503 when Cloudflare
 * cannot be reached (the check fails closed).
 */
export async function checkTurnstile(
  token: string | undefined,
  remoteIp: string,
  log: TurnstileLog,
  context: string,
  verify: typeof verifyTurnstileToken = verifyTurnstileToken,
): Promise<TurnstileRefusal | null> {
  const failed: TurnstileRefusal = {
    statusCode: 400,
    error: 'CaptchaFailed',
    message: 'The security check did not pass. Reload the page and try again.',
  };
  if (!token) return failed;
  const result = await verify(config.turnstile.secretKey!, token, remoteIp);
  if (result.outcome === 'passed') return null;
  if (result.outcome === 'failed') {
    log.info({ event: `${context}.turnstile_failed`, errorCodes: result.errorCodes }, `${context} refused by Turnstile`);
    return failed;
  }
  log.warn({ event: `${context}.turnstile_unavailable`, detail: result.detail }, 'Turnstile siteverify unavailable');
  return {
    statusCode: 503,
    error: 'Service Unavailable',
    message: 'This form is temporarily unavailable. Try again shortly.',
  };
}
