import { loadConfig, saveConfig, resolveCredential } from '../config.js';
import { emit, fail, type GlobalOpts } from '../output.js';

/** `qrauth orgs` — list organizations with stored credentials. Local only. */
export function orgsCommand(opts: GlobalOpts): void {
  const config = loadConfig();
  const list = Object.values(config.orgs).map((c) => ({
    orgSlug: c.orgSlug,
    role: c.role,
    keyPrefix: c.prefix,
    active: config.active === c.orgSlug,
  }));
  emit(list, opts, (rows) => {
    if (rows.length === 0) {
      process.stdout.write('No organizations. Run qrauth login.\n');
      return;
    }
    for (const o of rows) {
      process.stdout.write(`${o.active ? '* ' : '  '}${o.orgSlug}  (${o.role})  qrauth_${o.keyPrefix}…\n`);
    }
  });
}

/** `qrauth org use <slug>` — set the active context. Local only. */
export function orgUseCommand(slug: string, opts: GlobalOpts): void {
  const config = loadConfig();
  if (!config.orgs[slug]) {
    return fail(`No stored credential for org "${slug}". Run qrauth login first.`, opts, 'NO_CREDENTIAL');
  }
  saveConfig({ ...config, active: slug });
  emit({ active: slug }, opts, (d) => process.stdout.write(`Active context set to ${d.active}.\n`));
}

/** `qrauth whoami` — show the active (or --org) credential. Local only, no API call. */
export function whoamiCommand(opts: GlobalOpts): void {
  const cred = resolveCredential(loadConfig(), opts.org);
  if (!cred) {
    return fail('Not logged in. Run qrauth login.', opts, 'NOT_LOGGED_IN');
  }
  emit({ organization: cred.orgSlug, role: cred.role, keyPrefix: cred.prefix }, opts, (d) => {
    process.stdout.write(`Organization: ${d.organization}\nRole: ${d.role}\nKey: qrauth_${d.keyPrefix}…\n`);
  });
}
