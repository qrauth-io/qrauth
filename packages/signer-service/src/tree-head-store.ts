import { createHmac, hkdfSync, timingSafeEqual } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { replaceFile, writeNewFile } from './durable-fs.js';

/**
 * Tree-head state (ADR-0009 D7): per log, the last head the signer signed.
 * Stored as one JSON file in the keys directory (the only path the systemd
 * unit can write), with an HMAC over its canonical form keyed from
 * SIGNER_MASTER_KEY, so a truncated or edited file is detected.
 *
 * Missing → tree_head_state_missing; unreadable, malformed or failing the
 * integrity check → tree_head_state_corrupt. Either way the signer refuses
 * every head until the operator runs genesis-init or reinit-from-head.
 */

export const TREE_HEAD_STATE_FILE = 'tree-head-state.json';
const STATE_VERSION = 1;
const MASTER_KEY_BYTES = 32;
const ROOT_BYTES = 32;
const KEY_ID_RE = /^[A-Za-z0-9._-]{1,128}$/;
const LOG_ID_RE = /^[^\s+\u0000-\u001f\u007f]{1,255}$/u;

export interface LogState {
  keyId: string;
  lastSize: number;
  lastRoot: Uint8Array;
  lastSignedAtMs: number;
}

export interface TreeHeadState {
  logs: Record<string, LogState>;
}

export type TreeHeadStateErrorCode = 'tree_head_state_missing' | 'tree_head_state_corrupt';

export class TreeHeadStateError extends Error {
  constructor(
    readonly code: TreeHeadStateErrorCode,
    message: string,
  ) {
    super(message);
  }
}

export class MasterKeyMissingError extends Error {}

/**
 * The tree-head key envelope and the state MAC need the real master key.
 * Unlike loadMasterKey, there is no per-process fallback: a random key would
 * make the state unreadable after every restart.
 */
export function requireMasterKey(): Buffer {
  const raw = process.env.SIGNER_MASTER_KEY;
  const bytes = raw ? Buffer.from(raw, 'base64') : Buffer.alloc(0);
  if (bytes.length !== MASTER_KEY_BYTES) {
    throw new MasterKeyMissingError('SIGNER_MASTER_KEY (base64 of 32 bytes) is required for tree heads');
  }
  return bytes;
}

export function isValidLogId(logId: unknown): logId is string {
  return typeof logId === 'string' && LOG_ID_RE.test(logId);
}

export function isValidKeyId(keyId: unknown): keyId is string {
  return typeof keyId === 'string' && KEY_ID_RE.test(keyId);
}

function statePath(keysDir: string): string {
  return join(keysDir, TREE_HEAD_STATE_FILE);
}

/** Canonical JSON body: fixed key order, logs sorted by id, roots in base64. */
function canonicalBody(state: TreeHeadState): string {
  const logs: Record<string, unknown> = {};
  for (const logId of Object.keys(state.logs).sort()) {
    const l = state.logs[logId];
    logs[logId] = {
      keyId: l.keyId,
      lastRoot: Buffer.from(l.lastRoot).toString('base64'),
      lastSignedAtMs: l.lastSignedAtMs,
      lastSize: l.lastSize,
    };
  }
  return JSON.stringify({ logs, version: STATE_VERSION });
}

function stateMac(body: string): string {
  const key = Buffer.from(hkdfSync('sha256', requireMasterKey(), 'qrauth:tree-head-state:v1', 'state-integrity', 32));
  return createHmac('sha256', key).update(body, 'utf8').digest('hex');
}

function serialize(state: TreeHeadState): string {
  const body = canonicalBody(state);
  const parsed = JSON.parse(body) as Record<string, unknown>;
  return `${JSON.stringify({ ...parsed, mac: stateMac(body) })}\n`;
}

function corrupt(reason: string): TreeHeadStateError {
  return new TreeHeadStateError('tree_head_state_corrupt', `tree-head state is corrupt: ${reason}`);
}

function isSafeIndex(v: unknown): v is number {
  return typeof v === 'number' && Number.isSafeInteger(v) && v >= 0;
}

function parseLog(raw: unknown): LogState {
  if (typeof raw !== 'object' || raw === null) throw corrupt('log entry is not an object');
  const l = raw as Record<string, unknown>;
  if (!isValidKeyId(l.keyId)) throw corrupt('bad keyId');
  if (!isSafeIndex(l.lastSize)) throw corrupt('bad lastSize');
  if (!isSafeIndex(l.lastSignedAtMs)) throw corrupt('bad lastSignedAtMs');
  if (typeof l.lastRoot !== 'string') throw corrupt('bad lastRoot');
  const lastRoot = Buffer.from(l.lastRoot, 'base64');
  if (lastRoot.length !== ROOT_BYTES || lastRoot.toString('base64') !== l.lastRoot) throw corrupt('bad lastRoot');
  return { keyId: l.keyId, lastSize: l.lastSize, lastRoot: new Uint8Array(lastRoot), lastSignedAtMs: l.lastSignedAtMs };
}

/** Read and check the state. Throws TreeHeadStateError or MasterKeyMissingError. */
export async function readTreeHeadState(keysDir: string): Promise<TreeHeadState> {
  let text: string;
  try {
    text = await readFile(statePath(keysDir), 'utf8');
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
      throw new TreeHeadStateError('tree_head_state_missing', 'tree-head state is missing; run genesis-init or reinit-from-head');
    }
    throw corrupt(`unreadable (${(err as NodeJS.ErrnoException).code ?? 'error'})`);
  }
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    throw corrupt('not JSON');
  }
  if (typeof raw !== 'object' || raw === null) throw corrupt('not an object');
  const r = raw as Record<string, unknown>;
  if (r.version !== STATE_VERSION) throw corrupt('unknown version');
  if (typeof r.mac !== 'string' || !/^[0-9a-f]{64}$/.test(r.mac)) throw corrupt('bad mac');
  if (typeof r.logs !== 'object' || r.logs === null || Array.isArray(r.logs)) throw corrupt('bad logs');
  const logs: Record<string, LogState> = {};
  for (const [logId, entry] of Object.entries(r.logs as Record<string, unknown>)) {
    if (!isValidLogId(logId)) throw corrupt('bad logId');
    logs[logId] = parseLog(entry);
  }
  const state = { logs };
  const expected = Buffer.from(stateMac(canonicalBody(state)), 'hex');
  if (!timingSafeEqual(expected, Buffer.from(r.mac, 'hex'))) throw corrupt('integrity check failed');
  return state;
}

/**
 * Write the state durably. `create` refuses to overwrite an existing file
 * (genesis); otherwise the file is replaced atomically. `beforeRename` is a
 * test hook (see replaceFile).
 */
export async function writeTreeHeadState(
  keysDir: string,
  state: TreeHeadState,
  opts: { create?: boolean; beforeRename?: () => void | Promise<void> } = {},
): Promise<void> {
  const contents = serialize(state);
  if (opts.create) {
    await writeNewFile(statePath(keysDir), contents);
    return;
  }
  await replaceFile(statePath(keysDir), contents, { beforeRename: opts.beforeRename });
}
