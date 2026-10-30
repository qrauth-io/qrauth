import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync, existsSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  loadConfig,
  saveConfig,
  withCredential,
  withoutCredential,
  resolveCredential,
  keyPrefix,
  type StoredCredential,
} from '../config.js';

const cred = (orgSlug: string, key = `qrauth_${orgSlug}key`): StoredCredential => ({
  key,
  orgSlug,
  role: 'ADMIN',
  prefix: orgSlug.slice(0, 8),
});

let dir: string;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'qrauth-cli-'));
  process.env.QRAUTH_CONFIG_DIR = dir;
});
afterEach(() => {
  delete process.env.QRAUTH_CONFIG_DIR;
  rmSync(dir, { recursive: true, force: true });
});

describe('config store', () => {
  it('returns an empty config when none exists', () => {
    expect(loadConfig()).toEqual({ orgs: {} });
  });

  it('persists a 0600 file and round-trips, adopting the first cred as active', () => {
    saveConfig(withCredential({ orgs: {} }, cred('acme')));
    const path = join(dir, 'credentials.json');
    expect(existsSync(path)).toBe(true);
    expect(statSync(path).mode & 0o777).toBe(0o600);

    const reloaded = loadConfig();
    expect(reloaded.orgs.acme.key).toBe('qrauth_acmekey');
    expect(reloaded.active).toBe('acme');
  });

  it('isolates multiple orgs and keeps the original active context on add', () => {
    let cfg = withCredential({ orgs: {} }, cred('alpha'));
    cfg = withCredential(cfg, cred('beta'));
    expect(cfg.active).toBe('alpha');
    expect(Object.keys(cfg.orgs)).toEqual(['alpha', 'beta']);
    expect(resolveCredential(cfg)?.orgSlug).toBe('alpha');
    expect(resolveCredential(cfg, 'beta')?.orgSlug).toBe('beta');
  });

  it('removes a credential and reassigns active when the active one is removed', () => {
    let cfg = withCredential({ orgs: {} }, cred('alpha'));
    cfg = withCredential(cfg, cred('beta'));
    cfg = withoutCredential(cfg, 'alpha');
    expect(cfg.orgs.alpha).toBeUndefined();
    expect(cfg.active).toBe('beta');
  });

  it('does not mutate the input config (immutability)', () => {
    const base = { orgs: {} };
    withCredential(base, cred('alpha'));
    expect(base).toEqual({ orgs: {} });
  });

  it('derives the dashboard prefix from a raw key', () => {
    expect(keyPrefix('qrauth_0123456789abcdef')).toBe('01234567');
  });
});
