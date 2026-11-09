#!/usr/bin/env node
/**
 * kek-rewrap.mjs — re-encrypt signing-key envelopes under a new master key,
 * and verify envelope sets against the database public keys.
 *
 * Envelope format (packages/signer-service/src/key-at-rest.ts):
 *   "qrauth-kek-v1" \0 base64(iv) \0 base64(ciphertext) \0 base64(tag)
 *   AES-256-GCM, 12-byte IV, 16-byte tag, 32-byte master key, no AAD.
 *
 * Modes:
 *   rewrap     --src DIR --dst DIR --old-kek-file F --new-kek-file F
 *              [--exclude-keyid ID ...] [--delta]
 *   verify     --dir DIR --kek-file F --pubkeys pubkeys.json
 *              [--slhdsa-sign all|signing|none]
 *   live-check --env FILE --pubkeys pubkeys.json
 *
 * Rules:
 *   - Master keys are read only from files given by path, never from argv
 *     values or the environment. Key files (and the --env file) that are
 *     group- or world-readable are refused.
 *   - Nothing derived from key bytes is printed: no keys, no hashes of keys.
 *     Output is counts, keyIds and file names.
 *   - Exit status is non-zero on any failure.
 *
 * Uses only node:crypto, node:fs and @noble/post-quantum.
 */
import {
  createCipheriv,
  createDecipheriv,
  createPrivateKey,
  createPublicKey,
  createSign,
  createVerify,
  randomBytes,
} from 'node:crypto';
import { closeSync, fsyncSync, lstatSync, openSync, readFileSync, readdirSync, renameSync, statSync, writeSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { slh_dsa_sha2_128s } from '@noble/post-quantum/slh-dsa.js';

const FORMAT_TAG = 'qrauth-kek-v1';
const KEY_BYTES = 32;
const IV_BYTES = 12;
const ENVELOPE_RE = /^([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\.(ecdsa|slhdsa|rsa)\.enc$/;
const PROBE = Buffer.from('qrauth:kek-verify:v1:probe', 'utf8');
const ECDSA_CANONICAL_PREFIX = 'qrauth:ecdsa-canonical:v1:';
const MERKLE_ROOT_PREFIX = Buffer.from('qrauth:merkle-root:v1:', 'utf8');

export class ToolError extends Error {}

// ---------------------------------------------------------------------------
// Files
// ---------------------------------------------------------------------------

/** Refuse a secret-bearing file that is readable by group or others. */
export function assertPrivateFile(path) {
  const st = lstatSync(path);
  if (st.isSymbolicLink()) throw new ToolError(`${path}: refusing a symbolic link`);
  if (!st.isFile()) throw new ToolError(`${path}: not a regular file`);
  if (typeof process.getuid === 'function' && st.uid !== process.getuid()) {
    throw new ToolError(`${path}: refusing a file owned by another user`);
  }
  if ((st.mode & 0o077) !== 0) {
    throw new ToolError(`${path}: refusing a file readable by group or others (chmod 600 or 400)`);
  }
}

/** Read a master key from a file: base64 of 32 bytes. */
export function readKekFile(path) {
  assertPrivateFile(path);
  const key = Buffer.from(readFileSync(path, 'utf8').trim(), 'base64');
  if (key.length !== KEY_BYTES) {
    throw new ToolError(`${path}: master key must decode to ${KEY_BYTES} bytes`);
  }
  return key;
}

/** A keyId: lowercase UUID, the same shape as envelope file names. */
export const KEY_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/** The destination directory must be a private (0700) directory owned by this user. */
export function assertPrivateDir(path) {
  const st = lstatSync(path);
  if (st.isSymbolicLink() || !st.isDirectory()) throw new ToolError(`${path}: not a directory`);
  if ((st.mode & 0o077) !== 0) throw new ToolError(`${path}: refusing a directory accessible by group or others (chmod 700)`);
  if (typeof process.getuid === 'function' && st.uid !== process.getuid()) {
    throw new ToolError(`${path}: refusing a directory owned by another user`);
  }
}

/** Write a new file: temp file with mode 0600, fsync, rename. */
function writeAtomic(path, contents) {
  const tmp = `${path}.tmp.${randomBytes(8).toString('hex')}`;
  const fd = openSync(tmp, 'wx', 0o600);
  try {
    writeSync(fd, contents);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  renameSync(tmp, path);
}

/** List envelope files in `dir` as { name, keyId, type }. Other names are reported, not read. */
export function listEnvelopes(dir) {
  const envelopes = [];
  const unknown = [];
  for (const name of readdirSync(dir).sort()) {
    const m = ENVELOPE_RE.exec(name);
    if (m) envelopes.push({ name, keyId: m[1], type: m[2] });
    else unknown.push(name);
  }
  return { envelopes, unknown };
}

// ---------------------------------------------------------------------------
// Envelope crypto
// ---------------------------------------------------------------------------

export function encryptEnvelope(plaintext, key) {
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return [FORMAT_TAG, iv.toString('base64'), ct.toString('base64'), cipher.getAuthTag().toString('base64')].join('\0');
}

export function decryptEnvelope(envelope, key) {
  if (!envelope.startsWith(FORMAT_TAG + '\0')) throw new ToolError('missing format tag');
  const parts = envelope.split('\0');
  if (parts.length !== 4) throw new ToolError('malformed envelope');
  const [, iv, ct, tag] = parts.map((p, i) => (i === 0 ? p : Buffer.from(p, 'base64')));
  const decipher = createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  try {
    return Buffer.concat([decipher.update(ct), decipher.final()]);
  } catch {
    throw new ToolError('decryption failed (wrong master key or tampered envelope)');
  }
}

/** Check that decrypted bytes are a private key of the type the file name says. */
export function assertPlaintextType(type, plaintext) {
  if (type === 'slhdsa') {
    if (plaintext.length !== 64) throw new ToolError('SLH-DSA secret key must be 64 bytes');
    return;
  }
  let key;
  try {
    key = createPrivateKey({ key: plaintext.toString('utf8'), format: 'pem' });
  } catch {
    throw new ToolError(`${type}: plaintext is not a PEM private key`);
  }
  if (type === 'ecdsa' && (key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails?.namedCurve !== 'prime256v1')) {
    throw new ToolError('ecdsa: not an EC P-256 private key');
  }
  if (type === 'rsa' && key.asymmetricKeyType !== 'rsa') {
    throw new ToolError('rsa: not an RSA private key');
  }
}

/**
 * Re-encrypt one envelope: decrypt with the old key, check the type, encrypt
 * with the new key, decrypt the result again and require identical bytes.
 * `encrypt` is injectable so tests can simulate a faulty round trip.
 */
export function rewrapEnvelope(type, envelope, oldKey, newKey, encrypt = encryptEnvelope) {
  const plaintext = decryptEnvelope(envelope, oldKey);
  assertPlaintextType(type, plaintext);
  const rewrapped = encrypt(plaintext, newKey);
  const roundTrip = decryptEnvelope(rewrapped, newKey);
  if (roundTrip.length !== plaintext.length || !roundTrip.equals(plaintext)) {
    throw new ToolError('round trip under the new key does not reproduce the plaintext');
  }
  return rewrapped;
}

// ---------------------------------------------------------------------------
// rewrap
// ---------------------------------------------------------------------------

export function runRewrap({ src, dst, oldKekFile, newKekFile, excludeKeyIds = [], delta = false, encrypt }) {
  const oldKey = readKekFile(oldKekFile);
  const newKey = readKekFile(newKekFile);
  const excluded = new Set(excludeKeyIds);
  assertPrivateDir(dst);
  const { envelopes, unknown } = listEnvelopes(src);
  const existing = new Set(readdirSync(dst));
  if (existing.size > 0 && !delta) {
    throw new ToolError(`${dst}: destination is not empty (use --delta to add only missing names)`);
  }

  const counts = { ecdsa: 0, slhdsa: 0, rsa: 0 };
  const excludedNames = [];
  const skipped = [];
  const failures = [];
  // Every excluded keyId must exist in --src: a typo must not let a key be rewrapped silently.
  const srcKeyIds = new Set(envelopes.map((e) => e.keyId));
  for (const id of excluded) {
    if (!srcKeyIds.has(id)) failures.push(`--exclude-keyid ${id}: no envelope with this keyId in --src`);
  }
  if (failures.length > 0) return { counts, excluded: excludedNames, skipped, failures, unknown };
  for (const env of envelopes) {
    if (excluded.has(env.keyId)) {
      excludedNames.push(env.name);
      continue;
    }
    if (existing.has(env.name)) {
      skipped.push(env.name);
      continue;
    }
    try {
      const rewrapped = rewrapEnvelope(env.type, readFileSync(join(src, env.name), 'utf8').trim(), oldKey, newKey, encrypt);
      writeAtomic(join(dst, env.name), rewrapped);
      counts[env.type] += 1;
    } catch (err) {
      failures.push(`${env.name}: ${err instanceof ToolError ? err.message : 'error'}`);
    }
  }

  // Completeness: --dst must now hold exactly the non-excluded envelope names of --src,
  // so no key pair is left with one half. `verify` is still required before cut-over.
  const expected = new Set(envelopes.filter((e) => !excluded.has(e.keyId)).map((e) => e.name));
  const actual = new Set(listEnvelopes(dst).envelopes.map((e) => e.name));
  for (const name of expected) if (!actual.has(name)) failures.push(`${name}: missing from --dst after rewrap`);
  for (const name of actual) if (!expected.has(name)) failures.push(`${name}: present in --dst but not expected`);
  return { counts, excluded: excludedNames, skipped, failures, unknown };
}

// ---------------------------------------------------------------------------
// verify
// ---------------------------------------------------------------------------

function loadPubkeys(path) {
  const parsed = JSON.parse(readFileSync(path, 'utf8'));
  if (!Array.isArray(parsed) || parsed.length === 0) {
    throw new ToolError(`${path}: expected a non-empty JSON array of public-key rows`);
  }
  const rows = parsed;
  for (const r of rows) {
    if (!r || typeof r.keyId !== 'string' || typeof r.algorithm !== 'string' || typeof r.publicKey !== 'string') {
      throw new ToolError(`${path}: each row needs keyId, algorithm and publicKey`);
    }
  }
  return rows;
}

function spkiDer(pemOrKey) {
  return createPublicKey(pemOrKey).export({ type: 'spki', format: 'der' });
}

function checkAsymmetric(pem, row, hashAlg) {
  const priv = createPrivateKey({ key: pem, format: 'pem' });
  if (!spkiDer(priv).equals(spkiDer(row.publicKey))) throw new ToolError('public key does not match the database');
  const sig = createSign(hashAlg).update(PROBE).sign(priv);
  if (!createVerify(hashAlg).update(PROBE).verify(row.publicKey, sig)) {
    throw new ToolError('probe signature does not verify with the database public key');
  }
}

export function runVerify({ dir, kekFile, pubkeysFile, slhdsaSign = 'none' }) {
  if (!['all', 'signing', 'none'].includes(slhdsaSign)) throw new ToolError('--slhdsa-sign must be all, signing or none');
  const key = readKekFile(kekFile);
  const rows = loadPubkeys(pubkeysFile);
  const { envelopes, unknown } = listEnvelopes(dir);
  const files = new Set(envelopes.map((e) => e.name));
  const dbIds = new Set(rows.map((r) => r.keyId));

  let checked = 0;
  const failures = [];
  const missing = [];
  const read = (name) => decryptEnvelope(readFileSync(join(dir, name), 'utf8').trim(), key);

  for (const row of rows) {
    const needed = row.algorithm === 'RS256' ? [`${row.keyId}.rsa.enc`] : [`${row.keyId}.ecdsa.enc`, `${row.keyId}.slhdsa.enc`];
    const absent = needed.filter((n) => !files.has(n));
    if (absent.length) {
      missing.push(...absent);
      continue;
    }
    try {
      if (row.algorithm === 'RS256') {
        checkAsymmetric(read(`${row.keyId}.rsa.enc`).toString('utf8'), row, 'SHA256');
      } else if (row.algorithm === 'ES256') {
        checkAsymmetric(read(`${row.keyId}.ecdsa.enc`).toString('utf8'), row, 'SHA256');
        const sk = read(`${row.keyId}.slhdsa.enc`);
        if (sk.length !== 64) throw new ToolError('SLH-DSA secret key must be 64 bytes');
        const dbPk = Buffer.from(row.slhdsaPublicKey ?? '', 'base64');
        if (dbPk.length !== 32 || !sk.subarray(32, 64).equals(dbPk)) {
          throw new ToolError('SLH-DSA public key does not match the database');
        }
        const signing = row.status === 'ACTIVE' || row.status === 'ROTATED';
        if (slhdsaSign === 'all' || (slhdsaSign === 'signing' && signing)) {
          const sig = slh_dsa_sha2_128s.sign(PROBE, sk);
          if (!slh_dsa_sha2_128s.verify(sig, PROBE, dbPk)) {
            throw new ToolError('SLH-DSA probe signature does not verify with the database public key');
          }
        }
      } else {
        throw new ToolError(`unsupported algorithm ${row.algorithm}`);
      }
      checked += 1;
    } catch (err) {
      failures.push(`${row.keyId}: ${err instanceof ToolError ? err.message : 'error'}`);
    }
  }
  const orphans = envelopes.filter((e) => !dbIds.has(e.keyId)).map((e) => e.name);
  return { checked, failures, missing, orphans, unknown };
}

// ---------------------------------------------------------------------------
// live-check
// ---------------------------------------------------------------------------

/** Read KEY=VALUE pairs from an env file without exporting them anywhere. */
export function readEnvFile(path) {
  assertPrivateFile(path);
  const out = {};
  for (const line of readFileSync(path, 'utf8').split('\n')) {
    const m = /^\s*(?:export\s+)?([A-Z0-9_]+)\s*=\s*(.*)\s*$/.exec(line);
    if (!m) continue;
    let v = m[2];
    if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) v = v.slice(1, -1);
    out[m[1]] = v;
  }
  return out;
}

async function postJson(url, token, body) {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(30_000),
  });
  if (!res.ok) throw new ToolError(`${new URL(url).pathname} returned ${res.status}`);
  return res.json();
}

export async function runLiveCheck({ envFile, pubkeysFile, fetchJson = postJson }) {
  const env = readEnvFile(envFile);
  const ecdsaUrl = (env.ECDSA_SIGNER_URL ?? '').replace(/\/+$/, '');
  const ecdsaToken = env.ECDSA_SIGNER_TOKEN ?? '';
  const slhUrl = (env.SLH_DSA_SIGNER_URL ?? ecdsaUrl).replace(/\/+$/, '');
  const slhToken = env.SLH_DSA_SIGNER_TOKEN ?? ecdsaToken;
  if (!ecdsaUrl || !ecdsaToken) throw new ToolError(`${envFile}: ECDSA_SIGNER_URL and ECDSA_SIGNER_TOKEN are required`);

  const rows = loadPubkeys(pubkeysFile).filter((r) => r.status === 'ACTIVE' || r.status === 'ROTATED');
  const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT' })).toString('base64url');
  const payload = Buffer.from(JSON.stringify({ aud: 'qrauth:kek-live-check' })).toString('base64url');
  const jwsInput = `${header}.${payload}`;
  const root = Buffer.alloc(32, 0x5a);
  const message = 'qrauth-kek-live-check';

  let checked = 0;
  const failures = [];
  for (const row of rows) {
    try {
      if (row.algorithm === 'RS256') {
        const { signature } = await fetchJson(`${ecdsaUrl}/v1/sign-rsa-jws`, ecdsaToken, { keyId: row.keyId, canonicalInput: jwsInput });
        const ok = createVerify('SHA256').update(jwsInput).verify(row.publicKey, Buffer.from(String(signature), 'base64url'));
        if (!ok) throw new ToolError('RS256 signature does not verify');
      } else if (row.algorithm === 'ES256') {
        const { signature } = await fetchJson(`${ecdsaUrl}/v1/sign-ecdsa`, ecdsaToken, { keyId: row.keyId, message });
        const ok = createVerify('SHA256').update(ECDSA_CANONICAL_PREFIX + message).verify(row.publicKey, Buffer.from(String(signature), 'base64'));
        if (!ok) throw new ToolError('ES256 signature does not verify');
        const slh = await fetchJson(`${slhUrl}/v1/sign`, slhToken, { keyId: row.keyId, message: root.toString('base64') });
        const pk = Buffer.from(row.slhdsaPublicKey ?? '', 'base64');
        const sig = Buffer.from(String(slh.signature), 'base64');
        if (!slh_dsa_sha2_128s.verify(sig, Buffer.concat([MERKLE_ROOT_PREFIX, root]), pk)) {
          throw new ToolError('SLH-DSA signature does not verify');
        }
      } else {
        throw new ToolError(`unsupported algorithm ${row.algorithm}`);
      }
      checked += 1;
    } catch (err) {
      failures.push(`${row.keyId}: ${err instanceof ToolError ? err.message : 'error'}`);
    }
  }
  return { checked, failures };
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

export function parseArgs(argv) {
  const [mode, ...rest] = argv;
  const opts = { mode, excludeKeyIds: [], delta: false };
  const takes = new Set(['--src', '--dst', '--old-kek-file', '--new-kek-file', '--kek-file', '--dir', '--pubkeys', '--slhdsa-sign', '--env', '--exclude-keyid']);
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i];
    if (a === '--delta') {
      opts.delta = true;
      continue;
    }
    if (!takes.has(a) || i + 1 >= rest.length) throw new ToolError(`unknown or incomplete argument: ${a}`);
    const v = rest[++i];
    if (a === '--exclude-keyid') {
      if (!KEY_ID_RE.test(v)) throw new ToolError(`--exclude-keyid: not a keyId: ${v}`);
      opts.excludeKeyIds.push(v);
    } else {
      opts[a.slice(2).replace(/-([a-z])/g, (_, c) => c.toUpperCase())] = v;
    }
  }
  return opts;
}

function need(opts, ...names) {
  for (const n of names) if (!opts[n]) throw new ToolError(`missing --${n.replace(/[A-Z]/g, (c) => '-' + c.toLowerCase())}`);
}

async function main(argv) {
  const opts = parseArgs(argv);
  let failed = false;
  const log = (s) => process.stdout.write(s + '\n');
  if (opts.mode === 'rewrap') {
    need(opts, 'src', 'dst', 'oldKekFile', 'newKekFile');
    const r = runRewrap({ src: opts.src, dst: opts.dst, oldKekFile: opts.oldKekFile, newKekFile: opts.newKekFile, excludeKeyIds: opts.excludeKeyIds, delta: opts.delta });
    log(`rewrap: ecdsa ${r.counts.ecdsa}, slhdsa ${r.counts.slhdsa}, rsa ${r.counts.rsa}, excluded ${new Set(r.excluded.map((n) => n.slice(0, 36))).size} keyIds (${r.excluded.length} files), skipped ${r.skipped.length}, failures ${r.failures.length}`);
    if (r.unknown.length) log(`not envelopes (ignored): ${r.unknown.join(', ')}`);
    for (const f of r.failures) log(`FAIL ${f}`);
    failed = r.failures.length > 0;
  } else if (opts.mode === 'verify') {
    need(opts, 'dir', 'kekFile', 'pubkeys');
    const r = runVerify({ dir: opts.dir, kekFile: opts.kekFile, pubkeysFile: opts.pubkeys, slhdsaSign: opts.slhdsaSign ?? 'none' });
    log(`verify: ${r.checked} keys ok, ${r.failures.length} failed, ${r.missing.length} envelope files missing, ${r.orphans.length} envelope files with no database row`);
    for (const f of r.failures) log(`FAIL ${f}`);
    for (const m of r.missing) log(`MISSING ${m}`);
    for (const o of r.orphans) log(`ORPHAN ${o}`);
    failed = r.failures.length > 0 || r.missing.length > 0;
  } else if (opts.mode === 'live-check') {
    need(opts, 'env', 'pubkeys');
    const r = await runLiveCheck({ envFile: opts.env, pubkeysFile: opts.pubkeys });
    log(`live-check: ${r.checked} keys ok, ${r.failures.length} failed`);
    for (const f of r.failures) log(`FAIL ${f}`);
    failed = r.failures.length > 0;
  } else {
    throw new ToolError('usage: kek-rewrap.mjs rewrap|verify|live-check [options]');
  }
  return failed ? 1 : 0;
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  main(process.argv.slice(2)).then(
    (code) => process.exit(code),
    (err) => {
      // ToolError messages and file-system errors (code + path) are safe to
      // print; anything else is reported without detail.
      const detail =
        err instanceof ToolError ? err.message : err && typeof err.code === 'string' && err.path ? `${err.code}: ${err.path}` : 'unexpected error';
      process.stderr.write(`kek-rewrap: ${detail}\n`);
      process.exit(2);
    },
  );
}
