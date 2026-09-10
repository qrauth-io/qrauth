import { homedir } from 'node:os';
import { join } from 'node:path';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';

/**
 * One stored CLI credential, keyed by org slug. `key` is the raw API key
 * (shown once by the exchange, stored locally only). `prefix` is derived from
 * the key for display — it matches what the dashboard shows (`qrauth_<prefix>…`).
 */
export interface StoredCredential {
  key: string;
  orgSlug: string;
  role: string;
  prefix: string;
}

export interface CliConfig {
  /** Active org slug (default context for commands). */
  active?: string;
  /** Stored credentials keyed by org slug. */
  orgs: Record<string, StoredCredential>;
}

const EMPTY_CONFIG: CliConfig = { orgs: {} };

/**
 * Config directory. Overridable via QRAUTH_CONFIG_DIR (used by tests and for
 * non-default homes). Defaults to ~/.config/qrauth.
 */
export function configDir(): string {
  return process.env.QRAUTH_CONFIG_DIR || join(homedir(), '.config', 'qrauth');
}

function configPath(): string {
  return join(configDir(), 'credentials.json');
}

/** Read the config, returning an empty config if none exists or it's unreadable. */
export function loadConfig(): CliConfig {
  const path = configPath();
  if (!existsSync(path)) return { ...EMPTY_CONFIG, orgs: {} };
  try {
    const parsed = JSON.parse(readFileSync(path, 'utf-8')) as CliConfig;
    return { active: parsed.active, orgs: parsed.orgs ?? {} };
  } catch {
    // A corrupt file shouldn't brick the CLI; treat as empty (login rewrites it).
    return { ...EMPTY_CONFIG, orgs: {} };
  }
}

/**
 * Persist the config. The directory is created 0700 and the file written 0600
 * because it holds raw API keys — keep them off other users on the machine.
 */
export function saveConfig(config: CliConfig): void {
  const dir = configDir();
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  writeFileSync(configPath(), JSON.stringify(config, null, 2) + '\n', { mode: 0o600 });
}

/** Return a new config with `cred` stored under its org slug (immutable). */
export function withCredential(config: CliConfig, cred: StoredCredential): CliConfig {
  return {
    // Adopt as the active context if none is set yet.
    active: config.active ?? cred.orgSlug,
    orgs: { ...config.orgs, [cred.orgSlug]: cred },
  };
}

/** Return a new config with the org slug removed (immutable). */
export function withoutCredential(config: CliConfig, orgSlug: string): CliConfig {
  const orgs = { ...config.orgs };
  delete orgs[orgSlug];
  const active = config.active === orgSlug ? Object.keys(orgs)[0] : config.active;
  return { active, orgs };
}

/**
 * Resolve the credential to use: an explicit `--org` override wins, otherwise
 * the active context. Returns undefined if the chosen org has no stored key.
 */
export function resolveCredential(config: CliConfig, orgOverride?: string): StoredCredential | undefined {
  const slug = orgOverride ?? config.active;
  if (!slug) return undefined;
  return config.orgs[slug];
}

/** Derive the dashboard-style prefix from a raw `qrauth_<64hex>` key. */
export function keyPrefix(rawKey: string): string {
  const randomPart = rawKey.startsWith('qrauth_') ? rawKey.slice('qrauth_'.length) : rawKey;
  return randomPart.slice(0, 8);
}
