import { QRAuth } from '@qrauth/node';
import { loadConfig, resolveCredential } from '../config.js';
import { describeError } from '../api.js';
import { emit, fail, type GlobalOpts } from '../output.js';

/** Build a @qrauth/node client from the active (or --org) stored API key. */
function client(opts: GlobalOpts): QRAuth {
  const cred = resolveCredential(loadConfig(), opts.org);
  if (!cred) {
    return fail('Not logged in. Run qrauth login (or pass --org <slug>).', opts, 'NOT_LOGGED_IN');
  }
  return new QRAuth({ apiKey: cred.key, baseUrl: opts.apiUrl });
}

export async function qrCreateCommand(destination: string, cmdOpts: { label?: string }, opts: GlobalOpts): Promise<void> {
  try {
    const res = await client(opts).create({ destination, label: cmdOpts.label });
    emit(res, opts, (d) => process.stdout.write(`Created ${d.token}\n${d.verification_url}\n`));
  } catch (e) {
    const { message, code } = describeError(e);
    fail(message, opts, code);
  }
}

export async function qrListCommand(opts: GlobalOpts): Promise<void> {
  try {
    const res = await client(opts).list();
    emit(res, opts, (d) => {
      if (d.data.length === 0) {
        process.stdout.write('No QR codes.\n');
        return;
      }
      for (const q of d.data) {
        process.stdout.write(`${q.token}  ${q.status}  ${q.label ?? '-'}  ${q.destinationUrl}\n`);
      }
    });
  } catch (e) {
    const { message, code } = describeError(e);
    fail(message, opts, code);
  }
}

export async function qrGetCommand(token: string, opts: GlobalOpts): Promise<void> {
  try {
    const res = await client(opts).get(token);
    emit(res, opts, (d) => {
      process.stdout.write(`Token: ${d.token}\nStatus: ${d.status}\nLabel: ${d.label ?? '-'}\nURL: ${d.destinationUrl}\nCreated: ${d.createdAt}\n`);
    });
  } catch (e) {
    const { message, code } = describeError(e);
    fail(message, opts, code);
  }
}

export async function qrRmCommand(token: string, opts: GlobalOpts): Promise<void> {
  try {
    await client(opts).revoke(token);
    emit({ token, status: 'REVOKED' }, opts, () => process.stdout.write(`Revoked ${token}.\n`));
  } catch (e) {
    const { message, code } = describeError(e);
    fail(message, opts, code);
  }
}
