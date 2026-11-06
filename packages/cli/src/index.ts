#!/usr/bin/env node
import { Command } from 'commander';
import { DEFAULT_API_URL } from './constants.js';
import type { GlobalOpts } from './output.js';
import { loginCommand } from './commands/login.js';
import { logoutCommand } from './commands/logout.js';
import { orgsCommand, orgUseCommand, whoamiCommand } from './commands/context.js';
import { qrCreateCommand, qrListCommand, qrGetCommand, qrRmCommand } from './commands/qr.js';
import {
  ephemeralCreateCommand,
  ephemeralListCommand,
  ephemeralRevokeCommand,
} from './commands/ephemeral.js';

/** Merge global flags from anywhere in the command tree and resolve the API URL. */
function gopts(command: Command): GlobalOpts {
  const o = command.optsWithGlobals() as { json?: boolean; org?: string; apiUrl?: string };
  return {
    json: !!o.json,
    org: o.org,
    apiUrl: o.apiUrl || process.env.QRAUTH_API_URL || DEFAULT_API_URL,
  };
}

const program = new Command();

program
  .name('qrauth')
  .description('QRAuth command-line interface — scan-to-authenticate and QR code management')
  .version('0.1.0')
  .option('--json', 'output machine-readable JSON')
  .option('--org <slug>', 'override the active organization context')
  .option('--api-url <url>', `QRAuth API base URL (default: ${DEFAULT_API_URL})`);

program
  .command('login')
  .description('Authenticate by scanning a QR code with the QRAuth app')
  .action(async (_opts, command: Command) => {
    await loginCommand(gopts(command));
  });

program
  .command('logout')
  .description('Revoke and remove the stored credential')
  .option('--all', 'log out of every stored organization')
  .action(async (cmdOpts: { all?: boolean }, command: Command) => {
    await logoutCommand({ ...gopts(command), all: cmdOpts.all });
  });

program
  .command('whoami')
  .description('Show the active credential (organization, role, key prefix)')
  .action((_opts, command: Command) => {
    whoamiCommand(gopts(command));
  });

program
  .command('orgs')
  .description('List organizations with stored credentials')
  .action((_opts, command: Command) => {
    orgsCommand(gopts(command));
  });

const org = program.command('org').description('Manage organization contexts');
org
  .command('use <slug>')
  .description('Set the active organization context')
  .action((slug: string, _opts, command: Command) => {
    orgUseCommand(slug, gopts(command));
  });

const qr = program.command('qr').description('Manage QR codes');
qr
  .command('create <destination>')
  .description('Create a signed QR code for a destination URL')
  .option('--label <label>', 'human-readable label')
  .action(async (destination: string, cmdOpts: { label?: string }, command: Command) => {
    await qrCreateCommand(destination, cmdOpts, gopts(command));
  });
qr
  .command('list')
  .description('List QR codes for the active organization')
  .action(async (_opts, command: Command) => {
    await qrListCommand(gopts(command));
  });
qr
  .command('get <token>')
  .description('Show a QR code by token')
  .action(async (token: string, _opts, command: Command) => {
    await qrGetCommand(token, gopts(command));
  });
qr
  .command('rm <token>')
  .description('Revoke a QR code by token')
  .action(async (token: string, _opts, command: Command) => {
    await qrRmCommand(token, gopts(command));
  });

const ephemeral = program.command('ephemeral').description('Manage ephemeral delegated-access sessions');
ephemeral
  .command('create <scopes...>')
  .description('Create an ephemeral session with one or more scopes')
  .option('--ttl <duration>', 'time to live, e.g. 30m, 6h, 1d')
  .option('--max-uses <n>', 'maximum number of claims')
  .option('--device-binding', 'bind the session to the first claiming device')
  .action(async (scopes: string[], cmdOpts: { ttl?: string; maxUses?: string; deviceBinding?: boolean }, command: Command) => {
    await ephemeralCreateCommand(scopes, cmdOpts, gopts(command));
  });
ephemeral
  .command('list')
  .description('List ephemeral sessions for the active organization')
  .action(async (_opts, command: Command) => {
    await ephemeralListCommand(gopts(command));
  });
ephemeral
  .command('revoke <sessionId>')
  .description('Revoke an ephemeral session by id')
  .action(async (sessionId: string, _opts, command: Command) => {
    await ephemeralRevokeCommand(sessionId, gopts(command));
  });

program.parseAsync(process.argv).catch((err) => {
  process.stderr.write(`Error: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
});
