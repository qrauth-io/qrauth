import { loadConfig, resolveCredential } from '../config.js';
import { createEphemeral, listEphemeral, revokeEphemeral, describeError } from '../api.js';
import { emit, fail, type GlobalOpts } from '../output.js';

/** Resolve the active (or --org) API key, or fail. */
function activeKey(opts: GlobalOpts): string {
  const cred = resolveCredential(loadConfig(), opts.org);
  if (!cred) {
    return fail('Not logged in. Run qrauth login (or pass --org <slug>).', opts, 'NOT_LOGGED_IN');
  }
  return cred.key;
}

export async function ephemeralCreateCommand(
  scopes: string[],
  cmdOpts: { ttl?: string; maxUses?: string; deviceBinding?: boolean },
  opts: GlobalOpts,
): Promise<void> {
  if (scopes.length === 0) {
    return fail('At least one scope is required: qrauth ephemeral create <scope...>', opts, 'INVALID_ARGS');
  }
  const maxUses = cmdOpts.maxUses ? Number(cmdOpts.maxUses) : undefined;
  if (maxUses !== undefined && (!Number.isInteger(maxUses) || maxUses < 1)) {
    return fail('--max-uses must be a positive integer.', opts, 'INVALID_ARGS');
  }
  try {
    const session = await createEphemeral(opts.apiUrl, activeKey(opts), {
      scopes,
      ttl: cmdOpts.ttl,
      maxUses,
      deviceBinding: cmdOpts.deviceBinding,
    });
    emit(session, opts, (d) => {
      process.stdout.write(`Created ephemeral session ${d.sessionId}\n`);
      process.stdout.write(`Claim URL: ${d.claimUrl ?? '-'}\n`);
      process.stdout.write(`Scopes: ${d.scopes.join(', ')}  TTL: ${d.ttlSeconds}s  Max uses: ${d.maxUses}\n`);
      process.stdout.write(`Expires: ${d.expiresAt}\n`);
    });
  } catch (e) {
    const { message, code } = describeError(e);
    fail(message, opts, code);
  }
}

export async function ephemeralListCommand(opts: GlobalOpts): Promise<void> {
  try {
    const { sessions } = await listEphemeral(opts.apiUrl, activeKey(opts));
    emit(sessions, opts, (rows) => {
      if (rows.length === 0) {
        process.stdout.write('No ephemeral sessions.\n');
        return;
      }
      for (const s of rows) {
        process.stdout.write(`${s.sessionId}  ${s.status ?? '-'}  ${s.scopes.join(',')}  expires ${s.expiresAt}\n`);
      }
    });
  } catch (e) {
    const { message, code } = describeError(e);
    fail(message, opts, code);
  }
}

export async function ephemeralRevokeCommand(sessionId: string, opts: GlobalOpts): Promise<void> {
  try {
    const res = await revokeEphemeral(opts.apiUrl, activeKey(opts), sessionId);
    emit(res, opts, () => process.stdout.write(`Revoked ${sessionId}.\n`));
  } catch (e) {
    const { message, code } = describeError(e);
    fail(message, opts, code);
  }
}
