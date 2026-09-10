import { hostname } from 'node:os';
import QRCode from 'qrcode';
import { deriveCliVerificationCode } from '@qrauth/shared';
import { generatePkce } from '../pkce.js';
import { createAuthSession, getAuthSession, exchangeSession, describeError } from '../api.js';
import { loadConfig, saveConfig, withCredential, keyPrefix } from '../config.js';
import { emit, fail, type GlobalOpts } from '../output.js';
import { POLL_INTERVAL_MS } from '../constants.js';

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * `qrauth login` — device-style scan-to-authenticate (ADR-0002 §2).
 *
 * Progress UI (QR, verification code, waiting) goes to stderr so that with
 * `--json` stdout carries only the final result object.
 */
export async function loginCommand(opts: GlobalOpts): Promise<void> {
  const { codeVerifier, codeChallenge } = generatePkce();

  let session;
  try {
    session = await createAuthSession(opts.apiUrl, codeChallenge);
  } catch (e) {
    const { message, code } = describeError(e);
    return fail(message, opts, code);
  }

  const verificationCode = await deriveCliVerificationCode(session.sessionId);
  const qr = await QRCode.toString(session.qrUrl, { type: 'terminal', small: true });

  process.stderr.write('\nScan this QR with the QRAuth app on an already-authenticated device:\n\n');
  process.stderr.write(qr + '\n');
  process.stderr.write(`URL: ${session.qrUrl}\n\n`);
  process.stderr.write(`Verification code: ${verificationCode}\n`);
  process.stderr.write('Approve only if this matches the code on the approval page.\n\n');
  process.stderr.write('Waiting for approval...\n');

  // Poll until APPROVED or a terminal/timeout condition, capped at the session TTL.
  const deadline = new Date(session.expiresAt).getTime();
  let status = session.status;
  while (Date.now() < deadline) {
    await sleep(POLL_INTERVAL_MS);
    try {
      status = (await getAuthSession(opts.apiUrl, session.sessionId, codeVerifier)).status;
    } catch (e) {
      const { message, code } = describeError(e);
      return fail(message, opts, code);
    }
    if (status === 'APPROVED') break;
    if (status === 'DENIED') return fail('Login was denied on the device.', opts, 'DENIED');
    if (status === 'EXPIRED') return fail('Login session expired before approval.', opts, 'EXPIRED');
  }
  if (status !== 'APPROVED') return fail('Timed out waiting for approval.', opts, 'TIMEOUT');

  let result;
  try {
    result = await exchangeSession(opts.apiUrl, session.sessionId, codeVerifier, hostname());
  } catch (e) {
    // Surfaces CLI_MULTI_ORG (409) / CLI_NO_MEMBERSHIP (403) verbatim.
    const { message, code } = describeError(e);
    return fail(message, opts, code);
  }

  const prefix = keyPrefix(result.apiKey);
  const next = withCredential(loadConfig(), {
    key: result.apiKey,
    orgSlug: result.orgSlug,
    role: result.role,
    prefix,
  });
  saveConfig(next);

  emit(
    {
      organization: result.orgSlug,
      organizationId: result.organizationId,
      role: result.role,
      keyPrefix: prefix,
      active: next.active === result.orgSlug,
    },
    opts,
    (d) => {
      process.stdout.write(`\nLogged in to ${d.organization} as ${d.role}.\n`);
      process.stdout.write(`Key: qrauth_${d.keyPrefix}… (stored locally)\n`);
      if (d.active) process.stdout.write(`Active context set to ${d.organization}.\n`);
    },
  );
}
