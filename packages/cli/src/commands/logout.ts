import { loadConfig, saveConfig, withoutCredential, resolveCredential } from '../config.js';
import { selfRevoke, describeError } from '../api.js';
import { emit, fail, type GlobalOpts } from '../output.js';

/**
 * `qrauth logout [--all]` (ADR-0002 §6). Revokes server-side (so the key stops
 * working immediately) then deletes the local entry. The local entry is removed
 * even if the server revoke fails, so a stale/offline key never lingers locally.
 */
export async function logoutCommand(opts: GlobalOpts & { all?: boolean }): Promise<void> {
  const config = loadConfig();

  if (opts.all) {
    const slugs = Object.keys(config.orgs);
    const revoked: string[] = [];
    const failed: Array<{ slug: string; message: string }> = [];
    let next = config;
    for (const slug of slugs) {
      try {
        await selfRevoke(opts.apiUrl, config.orgs[slug].key);
        revoked.push(slug);
      } catch (e) {
        failed.push({ slug, message: describeError(e).message });
      }
      next = withoutCredential(next, slug); // remove locally regardless
    }
    saveConfig(next);
    return emit({ revoked, failed }, opts, (d) => {
      process.stdout.write(`Logged out of ${d.revoked.length} organization(s).\n`);
      if (d.failed.length) {
        process.stderr.write(`Server revoke failed for ${d.failed.length} (removed locally anyway).\n`);
      }
    });
  }

  const cred = resolveCredential(config, opts.org);
  if (!cred) {
    return fail('No active credential. Use --org <slug> or run qrauth login.', opts, 'NO_CREDENTIAL');
  }
  let revokeError: string | undefined;
  try {
    await selfRevoke(opts.apiUrl, cred.key);
  } catch (e) {
    revokeError = describeError(e).message;
  }
  saveConfig(withoutCredential(config, cred.orgSlug));
  emit({ organization: cred.orgSlug, serverRevoked: !revokeError, revokeError }, opts, (d) => {
    process.stdout.write(`Logged out of ${d.organization}.\n`);
    if (revokeError) {
      process.stderr.write(`Warning: server revoke failed (${revokeError}). Revoke it in the dashboard if needed.\n`);
    }
  });
}
