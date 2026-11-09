import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, it, expect, beforeAll, beforeEach, afterEach, vi } from 'vitest';
import { generateKeyPair, exportPKCS8, jwtVerify, decodeProtectedHeader, type KeyLike } from 'jose';

import {
  appleKeyConfigFromEnv,
  getAppleClientSecret,
  resetAppleClientSecretCache,
  type AppleKeyConfig,
} from '../apple-client-secret.js';

let pem: string;
let publicKey: KeyLike;

beforeAll(async () => {
  const pair = await generateKeyPair('ES256', { extractable: true });
  pem = await exportPKCS8(pair.privateKey);
  publicKey = pair.publicKey;
});

beforeEach(() => resetAppleClientSecretCache());

const base = { teamId: 'TEAM123456', keyId: 'KEY1234567', clientId: 'gr.example.app' };
const NOW = 1_790_000_000;

describe('getAppleClientSecret', () => {
  it('signs an ES256 client secret Apple accepts: kid header, iss team, sub client, aud appleid', async () => {
    const secret = await getAppleClientSecret({ ...base, privateKey: pem }, NOW);

    expect(decodeProtectedHeader(secret)).toEqual({ alg: 'ES256', kid: 'KEY1234567' });
    const { payload } = await jwtVerify(secret, publicKey, {
      issuer: 'TEAM123456',
      subject: 'gr.example.app',
      audience: 'https://appleid.apple.com',
      currentDate: new Date(NOW * 1000),
    });
    expect(payload.iat).toBe(NOW);
    expect(payload.exp! - payload.iat!).toBe(30 * 24 * 60 * 60);
  });

  it('reuses the cached secret until a day before it expires, then signs a new one', async () => {
    const config = { ...base, privateKey: pem };
    const first = await getAppleClientSecret(config, NOW);

    expect(await getAppleClientSecret(config, NOW + 28 * 24 * 60 * 60)).toBe(first);
    const renewed = await getAppleClientSecret(config, NOW + 29 * 24 * 60 * 60 + 1);
    expect(renewed).not.toBe(first);
  });

  it('reads the key from APPLE_PRIVATE_KEY_PATH', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'apple-key-'));
    const path = join(dir, 'AuthKey.p8');
    writeFileSync(path, pem, { mode: 0o600 });

    const secret = await getAppleClientSecret({ ...base, privateKeyPath: path }, NOW);

    await expect(jwtVerify(secret, publicKey, { currentDate: new Date(NOW * 1000) })).resolves.toBeDefined();
  });

  it('accepts a single-line PEM with literal \\n escapes', async () => {
    const oneLine = pem.replace(/\n/g, '\\n');

    const secret = await getAppleClientSecret({ ...base, privateKey: oneLine }, NOW);

    await expect(jwtVerify(secret, publicKey, { currentDate: new Date(NOW * 1000) })).resolves.toBeDefined();
  });
});

describe('appleKeyConfigFromEnv', () => {
  const fromEnv = (vars: Record<string, string>) => appleKeyConfigFromEnv((k) => vars[k] ?? '');

  it('needs team, key id, client id and a key', () => {
    expect(fromEnv({ APPLE_TEAM_ID: 't', APPLE_KEY_ID: 'k', APPLE_CLIENT_ID: 'c', APPLE_PRIVATE_KEY_PATH: '/k.p8' }))
      .toEqual<AppleKeyConfig>({ teamId: 't', keyId: 'k', clientId: 'c', privateKeyPath: '/k.p8' });
    expect(fromEnv({ APPLE_KEY_ID: 'k', APPLE_CLIENT_ID: 'c', APPLE_PRIVATE_KEY: 'pem' })).toBeNull();
    expect(fromEnv({ APPLE_TEAM_ID: 't', APPLE_KEY_ID: 'k', APPLE_CLIENT_ID: 'c' })).toBeNull();
  });
});

describe('Apple token exchange', () => {
  const saved = { ...process.env };
  afterEach(() => {
    process.env = { ...saved };
    vi.unstubAllGlobals();
  });

  async function exchangeAndCaptureSecret(): Promise<string> {
    const fetchMock = vi.fn(async () => ({ json: async () => ({ error: 'invalid_grant' }) }));
    vi.stubGlobal('fetch', fetchMock);
    const { exchangeCodeForUser } = await import('../oauth.js');
    await expect(exchangeCodeForUser('apple', 'code', 'https://qrauth.test/cb')).rejects.toThrow(/invalid_grant/);
    const body = (fetchMock.mock.calls[0] as unknown as [string, { body: URLSearchParams }])[1].body;
    return body.get('client_secret') ?? '';
  }

  it('signs the client secret from the key when APPLE_TEAM_ID / APPLE_KEY_ID / key are set', async () => {
    Object.assign(process.env, {
      APPLE_CLIENT_ID: 'gr.example.app',
      APPLE_TEAM_ID: 'TEAM123456',
      APPLE_KEY_ID: 'KEY1234567',
      APPLE_PRIVATE_KEY: pem.replace(/\n/g, '\\n'),
      APPLE_CLIENT_SECRET: 'old-expired-static-secret',
    });

    const secret = await exchangeAndCaptureSecret();

    expect(secret).not.toBe('old-expired-static-secret');
    expect(decodeProtectedHeader(secret).kid).toBe('KEY1234567');
  });

  it('falls back to the static APPLE_CLIENT_SECRET when no key is configured', async () => {
    Object.assign(process.env, { APPLE_CLIENT_ID: 'gr.example.app', APPLE_CLIENT_SECRET: 'static-secret' });
    delete process.env.APPLE_TEAM_ID;
    delete process.env.APPLE_KEY_ID;
    delete process.env.APPLE_PRIVATE_KEY;
    delete process.env.APPLE_PRIVATE_KEY_PATH;

    expect(await exchangeAndCaptureSecret()).toBe('static-secret');
  });
});
