import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { chmodSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createPublicKey, createSign, generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto';
import { slh_dsa_sha2_128s } from '@noble/post-quantum/slh-dsa.js';
import {
  ToolError,
  decryptEnvelope,
  encryptEnvelope,
  parseArgs,
  readKekFile,
  rewrapEnvelope,
  runLiveCheck,
  runRewrap,
  runVerify,
} from '../kek-rewrap.mjs';

let root;
let oldKey;
let newKey;
let oldKekFile;
let newKekFile;

function writeKek(name, key, mode = 0o600) {
  const p = join(root, name);
  writeFileSync(p, key.toString('base64'));
  chmodSync(p, mode);
  return p;
}

/** Create one ES256+SLH-DSA key and one RS256 key under `key` in `dir`; return pubkeys rows. */
function makeKeys(dir, key) {
  const es = generateKeyPairSync('ec', { namedCurve: 'prime256v1', publicKeyEncoding: { type: 'spki', format: 'pem' }, privateKeyEncoding: { type: 'pkcs8', format: 'pem' } });
  const slh = slh_dsa_sha2_128s.keygen(randomBytes(48));
  const rsa = generateKeyPairSync('rsa', { modulusLength: 2048, publicKeyEncoding: { type: 'spki', format: 'pem' }, privateKeyEncoding: { type: 'pkcs8', format: 'pem' } });
  const esId = randomUUID();
  const rsId = randomUUID();
  writeFileSync(join(dir, `${esId}.ecdsa.enc`), encryptEnvelope(Buffer.from(es.privateKey), key));
  writeFileSync(join(dir, `${esId}.slhdsa.enc`), encryptEnvelope(Buffer.from(slh.secretKey), key));
  writeFileSync(join(dir, `${rsId}.rsa.enc`), encryptEnvelope(Buffer.from(rsa.privateKey), key));
  return {
    esId,
    rsId,
    rows: [
      { keyId: esId, algorithm: 'ES256', status: 'ACTIVE', publicKey: es.publicKey, slhdsaPublicKey: Buffer.from(slh.publicKey).toString('base64') },
      { keyId: rsId, algorithm: 'RS256', status: 'ACTIVE', publicKey: rsa.publicKey, slhdsaPublicKey: null },
    ],
  };
}

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'kek-rewrap-'));
  oldKey = randomBytes(32);
  newKey = randomBytes(32);
  oldKekFile = writeKek('kek-old', oldKey);
  newKekFile = writeKek('kek-new', newKey);
  mkdirSync(join(root, 'src'));
  mkdirSync(join(root, 'dst'));
  chmodSync(join(root, 'dst'), 0o700);
});

afterEach(() => rmSync(root, { recursive: true, force: true }));

describe('master-key files', () => {
  it('refuses a key file readable by group or others (0644)', () => {
    const p = writeKek('kek-open', oldKey, 0o644);
    expect(() => readKekFile(p)).toThrow(/group or others/);
  });
  it('accepts 0600 and 0400', () => {
    expect(readKekFile(oldKekFile).equals(oldKey)).toBe(true);
    expect(readKekFile(writeKek('kek-ro', oldKey, 0o400)).equals(oldKey)).toBe(true);
  });
  it('refuses a key of the wrong length', () => {
    expect(() => readKekFile(writeKek('kek-short', randomBytes(16)))).toThrow(/32 bytes/);
  });
});

describe('rewrapEnvelope', () => {
  it('re-encrypts under the new key with identical plaintext', () => {
    const sk = slh_dsa_sha2_128s.keygen(randomBytes(48)).secretKey;
    const out = rewrapEnvelope('slhdsa', encryptEnvelope(Buffer.from(sk), oldKey), oldKey, newKey);
    expect(decryptEnvelope(out, newKey).equals(Buffer.from(sk))).toBe(true);
    expect(() => decryptEnvelope(out, oldKey)).toThrow(ToolError);
  });
  it('fails with the wrong old key', () => {
    expect(() => rewrapEnvelope('slhdsa', encryptEnvelope(randomBytes(64), newKey), oldKey, newKey)).toThrow(/decryption failed/);
  });
  it('fails on a tampered tag', () => {
    const parts = encryptEnvelope(randomBytes(64), oldKey).split('\0');
    const tag = Buffer.from(parts[3], 'base64');
    tag[0] ^= 1;
    parts[3] = tag.toString('base64');
    expect(() => rewrapEnvelope('slhdsa', parts.join('\0'), oldKey, newKey)).toThrow(/decryption failed/);
  });
  it('fails when the plaintext is not of the file type', () => {
    expect(() => rewrapEnvelope('ecdsa', encryptEnvelope(randomBytes(64), oldKey), oldKey, newKey)).toThrow(/not a PEM private key/);
    expect(() => rewrapEnvelope('slhdsa', encryptEnvelope(randomBytes(63), oldKey), oldKey, newKey)).toThrow(/64 bytes/);
    const rsa = generateKeyPairSync('rsa', { modulusLength: 2048, privateKeyEncoding: { type: 'pkcs8', format: 'pem' }, publicKeyEncoding: { type: 'spki', format: 'pem' } });
    expect(() => rewrapEnvelope('ecdsa', encryptEnvelope(Buffer.from(rsa.privateKey), oldKey), oldKey, newKey)).toThrow(/EC P-256/);
  });
  it('fails when the round trip does not reproduce the plaintext (simulated)', () => {
    const faulty = (p, k) => encryptEnvelope(Buffer.concat([p.subarray(0, p.length - 1), Buffer.from([p[p.length - 1] ^ 1])]), k);
    expect(() => rewrapEnvelope('slhdsa', encryptEnvelope(randomBytes(64), oldKey), oldKey, newKey, faulty)).toThrow(/round trip/);
  });
});

describe('runRewrap', () => {
  it('rewraps every envelope, writes 0600 files, and reports counts', () => {
    makeKeys(join(root, 'src'), oldKey);
    const r = runRewrap({ src: join(root, 'src'), dst: join(root, 'dst'), oldKekFile, newKekFile });
    expect(r.counts).toEqual({ ecdsa: 1, slhdsa: 1, rsa: 1 });
    expect(r.failures).toEqual([]);
    for (const n of readdirSync(join(root, 'dst'))) {
      expect(statSync(join(root, 'dst', n)).mode & 0o777).toBe(0o600);
      expect(() => decryptEnvelope(readFileSync(join(root, 'dst', n), 'utf8'), newKey)).not.toThrow();
    }
  });
  it('refuses a non-empty destination without --delta', () => {
    makeKeys(join(root, 'src'), oldKey);
    writeFileSync(join(root, 'dst', 'something'), 'x');
    expect(() => runRewrap({ src: join(root, 'src'), dst: join(root, 'dst'), oldKekFile, newKekFile })).toThrow(/not empty/);
  });
  it('--delta processes only names missing from the destination', () => {
    makeKeys(join(root, 'src'), oldKey);
    runRewrap({ src: join(root, 'src'), dst: join(root, 'dst'), oldKekFile, newKekFile });
    const second = makeKeys(join(root, 'src'), oldKey);
    const r = runRewrap({ src: join(root, 'src'), dst: join(root, 'dst'), oldKekFile, newKekFile, delta: true });
    expect(r.counts).toEqual({ ecdsa: 1, slhdsa: 1, rsa: 1 });
    expect(r.skipped.length).toBe(3);
    expect(readdirSync(join(root, 'dst')).some((n) => n.startsWith(second.esId))).toBe(true);
  });
  it('--exclude-keyid skips every file of that keyId and reports it', () => {
    const { esId } = makeKeys(join(root, 'src'), oldKey);
    const r = runRewrap({ src: join(root, 'src'), dst: join(root, 'dst'), oldKekFile, newKekFile, excludeKeyIds: [esId] });
    expect(r.counts).toEqual({ ecdsa: 0, slhdsa: 0, rsa: 1 });
    expect(r.excluded.sort()).toEqual([`${esId}.ecdsa.enc`, `${esId}.slhdsa.enc`]);
    expect(readdirSync(join(root, 'dst')).some((n) => n.startsWith(esId))).toBe(false);
  });
  it('reports a per-file failure and continues', () => {
    makeKeys(join(root, 'src'), oldKey);
    writeFileSync(join(root, 'src', `${randomUUID()}.slhdsa.enc`), encryptEnvelope(randomBytes(64), newKey));
    const r = runRewrap({ src: join(root, 'src'), dst: join(root, 'dst'), oldKekFile, newKekFile });
    // The undecryptable file fails, and the completeness check reports it missing from --dst.
    expect(r.failures.length).toBe(2);
    expect(r.failures.some((f) => f.includes('missing from --dst'))).toBe(true);
    expect(r.counts).toEqual({ ecdsa: 1, slhdsa: 1, rsa: 1 });
  });
  it('fails when an excluded keyId has no envelope in --src, and rewraps nothing', () => {
    makeKeys(join(root, 'src'), oldKey);
    const typo = randomUUID();
    const r = runRewrap({ src: join(root, 'src'), dst: join(root, 'dst'), oldKekFile, newKekFile, excludeKeyIds: [typo] });
    expect(r.failures).toEqual([`--exclude-keyid ${typo}: no envelope with this keyId in --src`]);
    expect(readdirSync(join(root, 'dst'))).toEqual([]);
  });
  it('refuses a destination accessible by group or others', () => {
    makeKeys(join(root, 'src'), oldKey);
    chmodSync(join(root, 'dst'), 0o755);
    expect(() => runRewrap({ src: join(root, 'src'), dst: join(root, 'dst'), oldKekFile, newKekFile })).toThrow(/chmod 700/);
  });
  it('refuses a master-key file that is a symbolic link', () => {
    makeKeys(join(root, 'src'), oldKey);
    const link = join(root, 'kek-link');
    symlinkSync(newKekFile, link);
    expect(() => runRewrap({ src: join(root, 'src'), dst: join(root, 'dst'), oldKekFile, newKekFile: link })).toThrow(/symbolic link/);
  });
});

describe('runVerify', () => {
  it('passes for matching envelopes and public keys (with SLH-DSA signing)', () => {
    const { rows } = makeKeys(join(root, 'src'), oldKey);
    const pub = join(root, 'pubkeys.json');
    writeFileSync(pub, JSON.stringify(rows));
    const r = runVerify({ dir: join(root, 'src'), kekFile: oldKekFile, pubkeysFile: pub, slhdsaSign: 'all' });
    expect(r).toMatchObject({ checked: 2, failures: [], missing: [], orphans: [] });
  });
  it('detects ES256, SLH-DSA and RS256 public-key mismatches', () => {
    const { rows } = makeKeys(join(root, 'src'), oldKey);
    const other = makeKeys(join(root, 'dst'), oldKey).rows;
    const pub = join(root, 'pubkeys.json');
    for (const mutate of [
      (r) => ({ ...r[0], publicKey: other[0].publicKey }),
      (r) => ({ ...r[0], slhdsaPublicKey: other[0].slhdsaPublicKey }),
      (r) => ({ ...r[1], publicKey: other[1].publicKey }),
    ]) {
      const bad = mutate(rows);
      writeFileSync(pub, JSON.stringify([bad]));
      const r = runVerify({ dir: join(root, 'src'), kekFile: oldKekFile, pubkeysFile: pub });
      expect(r.failures.length).toBe(1);
    }
  });
  it('fails under the wrong master key and lists missing and orphan envelopes', () => {
    const { rows } = makeKeys(join(root, 'src'), oldKey);
    const pub = join(root, 'pubkeys.json');
    writeFileSync(pub, JSON.stringify([...rows, { ...rows[1], keyId: randomUUID() }]));
    writeFileSync(join(root, 'src', `${randomUUID()}.rsa.enc`), encryptEnvelope(Buffer.from('x'), oldKey));
    const wrong = runVerify({ dir: join(root, 'src'), kekFile: newKekFile, pubkeysFile: pub });
    expect(wrong.failures.length).toBe(2);
    expect(wrong.missing.length).toBe(1);
    expect(wrong.orphans.length).toBe(1);
  });
});

describe('runVerify input', () => {
  it('refuses an empty or non-array public-key file', () => {
    makeKeys(join(root, 'src'), oldKey);
    for (const content of ['[]', '{}']) {
      const pub = join(root, 'pubkeys.json');
      writeFileSync(pub, content);
      expect(() => runVerify({ dir: join(root, 'src'), kekFile: oldKekFile, pubkeysFile: pub })).toThrow(/non-empty JSON array/);
    }
  });
});

describe('runLiveCheck', () => {
  it('signs through the (stubbed) signer and verifies with database public keys', async () => {
    const es = generateKeyPairSync('ec', { namedCurve: 'prime256v1', publicKeyEncoding: { type: 'spki', format: 'pem' }, privateKeyEncoding: { type: 'pkcs8', format: 'pem' } });
    const slh = slh_dsa_sha2_128s.keygen(randomBytes(48));
    const rows = [{ keyId: randomUUID(), algorithm: 'ES256', status: 'ACTIVE', publicKey: es.publicKey, slhdsaPublicKey: Buffer.from(slh.publicKey).toString('base64') }];
    const pub = join(root, 'pubkeys.json');
    writeFileSync(pub, JSON.stringify(rows));
    const env = join(root, 'api.env');
    writeFileSync(env, 'ECDSA_SIGNER_URL=http://signer.test\nECDSA_SIGNER_TOKEN="tok"\n');
    chmodSync(env, 0o600);
    const fetchJson = async (url, _token, body) => {
      if (url.endsWith('/v1/sign-ecdsa')) return { signature: createSign('SHA256').update('qrauth:ecdsa-canonical:v1:' + body.message).sign(es.privateKey, 'base64') };
      if (url.endsWith('/v1/sign')) {
        const msg = Buffer.concat([Buffer.from('qrauth:merkle-root:v1:'), Buffer.from(body.message, 'base64')]);
        return { signature: Buffer.from(slh_dsa_sha2_128s.sign(msg, slh.secretKey)).toString('base64') };
      }
      throw new Error('unexpected');
    };
    expect(await runLiveCheck({ envFile: env, pubkeysFile: pub, fetchJson })).toEqual({ checked: 1, failures: [] });
    rows[0].publicKey = createPublicKey(generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey).export({ type: 'spki', format: 'pem' });
    writeFileSync(pub, JSON.stringify(rows));
    expect((await runLiveCheck({ envFile: env, pubkeysFile: pub, fetchJson })).failures.length).toBe(1);
  });
  it('refuses an env file readable by group or others', async () => {
    const env = join(root, 'api.env');
    writeFileSync(env, 'ECDSA_SIGNER_URL=x\n');
    chmodSync(env, 0o644);
    await expect(runLiveCheck({ envFile: env, pubkeysFile: env })).rejects.toThrow(/group or others/);
  });
});

describe('parseArgs', () => {
  it('collects repeated --exclude-keyid and rejects malformed ones', () => {
    const a = randomUUID();
    const b = randomUUID();
    expect(parseArgs(['rewrap', '--exclude-keyid', a, '--exclude-keyid', b, '--delta']).excludeKeyIds).toEqual([a, b]);
    expect(() => parseArgs(['rewrap', '--exclude-keyid', 'nope'])).toThrow(/not a keyId/);
    expect(() => parseArgs(['rewrap', '--exclude-keyid', '-'.repeat(36)])).toThrow(/not a keyId/);
    expect(() => parseArgs(['rewrap', '--kek', 'value'])).toThrow(/unknown/);
  });
});
