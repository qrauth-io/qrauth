/**
 * Operator commands for the platform tree-head key and state (ADR-0009 D7).
 * Run on the signer host as the `signer` user, from
 * /home/signer/vqr/packages/signer-service, with the service's env file:
 *
 *   node --env-file=../../deploy/signer.env dist/tree-head-cli.js <command>
 *
 * Commands (output is JSON on stdout):
 *   genesis-init [--log-id <origin>]   create the tree-head key and the
 *                                      genesis state (size 0). Once only.
 *   show-state                         print the stored state
 *   export-tree-head-pubkey            print the public key, its SHA-256
 *                                      fingerprint and the C2SP vkey
 *   reinit-from-head <file|->          recovery: replace the state with a
 *                                      head this signer signed, after
 *                                      verifying its signature
 *
 * See docs/ops/signer-tree-head.md.
 */
import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { TREE_HEAD_SIGNATURE_TYPE, TRUST_LOG_ORIGIN, sha256Hasher, treeHeadKeyId, treeHeadMessage } from '@qrauth/merkle-log';
import { selectSlhDsaImplementation, type SlhDsaImplementation } from './slh-dsa.js';
import {
  isValidKeyId,
  isValidLogId,
  readTreeHeadState,
  requireMasterKey,
  TREE_HEAD_STATE_FILE,
  TreeHeadStateError,
  writeTreeHeadState,
  type LogState,
} from './tree-head-store.js';
import {
  generateTreeHeadKey,
  listTreeHeadKeyIds,
  loadTreeHeadSecretKey,
  publicKeyFingerprint,
  publicKeyOf,
  TreeHeadKeyError,
} from './tree-head-key.js';

export class CliError extends Error {}

const b64 = (b: Uint8Array) => Buffer.from(b).toString('base64');

async function stateIfPresent(keysDir: string) {
  try {
    return await readTreeHeadState(keysDir);
  } catch (err) {
    if (err instanceof TreeHeadStateError && err.code === 'tree_head_state_missing') return null;
    throw err;
  }
}

/** Create the tree-head key and the genesis state (lastSize 0, empty-tree root). */
export async function genesisInit(keysDir: string, logId: string = TRUST_LOG_ORIGIN) {
  requireMasterKey();
  if (!isValidLogId(logId)) throw new CliError(`invalid log id ${JSON.stringify(logId)}`);
  // A corrupt state also blocks genesis: recovery goes through reinit-from-head.
  let existing;
  try {
    existing = await stateIfPresent(keysDir);
  } catch (err) {
    if (err instanceof TreeHeadStateError) throw new CliError(`${TREE_HEAD_STATE_FILE} exists but is corrupt; use reinit-from-head`);
    throw err;
  }
  if (existing) throw new CliError(`${TREE_HEAD_STATE_FILE} already exists; genesis runs once`);
  if ((await listTreeHeadKeyIds(keysDir)).length > 0) {
    throw new CliError('a tree-head key already exists without a state; use reinit-from-head');
  }
  const { keyId, publicKey } = await generateTreeHeadKey(keysDir);
  const genesis: LogState = { keyId, lastSize: 0, lastRoot: sha256Hasher.emptyRoot(), lastSignedAtMs: 0 };
  await writeTreeHeadState(keysDir, { logs: { [logId]: genesis } }, { create: true });
  return { logId, keyId, publicKey: b64(publicKey), fingerprintSha256: publicKeyFingerprint(publicKey) };
}

export async function showState(keysDir: string) {
  const { logs } = await readTreeHeadState(keysDir);
  return Object.fromEntries(
    Object.entries(logs).map(([logId, l]) => [
      logId,
      {
        keyId: l.keyId,
        lastSize: l.lastSize,
        lastRoot: b64(l.lastRoot),
        lastSignedAt: l.lastSignedAtMs === 0 ? null : new Date(l.lastSignedAtMs).toISOString(),
      },
    ]),
  );
}

/** The single tree-head key: the one the state names, else the only key file. */
async function currentKeyId(keysDir: string): Promise<{ keyId: string; logId: string }> {
  try {
    const { logs } = await readTreeHeadState(keysDir);
    const [logId, log] = Object.entries(logs)[0] ?? [];
    if (logId && log) return { keyId: log.keyId, logId };
  } catch (err) {
    if (!(err instanceof TreeHeadStateError)) throw err;
  }
  const ids = await listTreeHeadKeyIds(keysDir);
  if (ids.length !== 1) throw new CliError(`expected exactly one tree-head key, found ${ids.length}`);
  return { keyId: ids[0], logId: TRUST_LOG_ORIGIN };
}

export async function exportTreeHeadPublicKey(keysDir: string) {
  const { keyId, logId } = await currentKeyId(keysDir);
  const publicKey = publicKeyOf(await loadTreeHeadSecretKey(keysDir, keyId));
  const noteKeyId = Buffer.from(treeHeadKeyId(logId, publicKey)).toString('hex');
  return {
    keyId,
    algorithm: 'slh-dsa-sha2-128s',
    publicKey: b64(publicKey),
    fingerprintSha256: publicKeyFingerprint(publicKey),
    keyName: logId,
    noteKeyId,
    vkey: `${logId}+${noteKeyId}+${b64(Buffer.concat([TREE_HEAD_SIGNATURE_TYPE, publicKey]))}`,
  };
}

interface SignedHead {
  logId: string;
  treeSize: number;
  rootHash: Uint8Array;
  signedAtMs: number;
  keyId: string;
  signature: Uint8Array;
}

function parseSignedHead(text: string): SignedHead {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    throw new CliError('the head is not JSON');
  }
  const h = (typeof raw === 'object' && raw !== null ? raw : {}) as Record<string, unknown>;
  const keys = Object.keys(h).sort().join(',');
  if (keys !== 'keyId,logId,rootHash,signature,signedAtMs,treeSize') {
    throw new CliError('the head must have exactly: logId, treeSize, rootHash, signedAtMs, keyId, signature');
  }
  const safe = (v: unknown) => typeof v === 'number' && Number.isSafeInteger(v) && v >= 0;
  if (!isValidLogId(h.logId) || !safe(h.treeSize) || !safe(h.signedAtMs) || !isValidKeyId(h.keyId)) {
    throw new CliError('the head has an invalid field');
  }
  if (typeof h.rootHash !== 'string' || typeof h.signature !== 'string') throw new CliError('rootHash and signature are base64 strings');
  const rootHash = Buffer.from(h.rootHash, 'base64');
  if (rootHash.length !== 32 || rootHash.toString('base64') !== h.rootHash) throw new CliError('rootHash must be base64 of 32 bytes');
  return {
    logId: h.logId,
    treeSize: h.treeSize as number,
    rootHash: new Uint8Array(rootHash),
    signedAtMs: h.signedAtMs as number,
    keyId: h.keyId,
    signature: new Uint8Array(Buffer.from(h.signature, 'base64')),
  };
}

/**
 * Recovery: replace the state for the head's log with a head this signer
 * signed. The signature is verified with the local tree-head key first. A
 * valid current state is never moved backwards or to a different root at
 * the same size.
 */
export async function reinitFromHead(keysDir: string, headText: string, impl: SlhDsaImplementation): Promise<LogState> {
  requireMasterKey();
  const head = parseSignedHead(headText);
  let secret: Uint8Array;
  try {
    secret = await loadTreeHeadSecretKey(keysDir, head.keyId);
  } catch (err) {
    if (err instanceof TreeHeadKeyError) throw new CliError(`no local tree-head key ${head.keyId}`);
    throw err;
  }
  const message = treeHeadMessage(head);
  if (!impl.verify(head.signature, message, publicKeyOf(secret))) {
    throw new CliError('the head signature does not verify with the local tree-head key');
  }

  let current = null;
  try {
    current = await stateIfPresent(keysDir);
  } catch (err) {
    if (!(err instanceof TreeHeadStateError)) throw err; // corrupt: replaced below
  }
  const existing = current?.logs[head.logId];
  if (existing) {
    if (head.treeSize < existing.lastSize) {
      throw new CliError(`refusing to move the state backwards (${existing.lastSize} -> ${head.treeSize})`);
    }
    if (head.treeSize === existing.lastSize && Buffer.compare(Buffer.from(head.rootHash), Buffer.from(existing.lastRoot)) !== 0) {
      throw new CliError('refusing a different root at the stored size');
    }
  }
  const next: LogState = { keyId: head.keyId, lastSize: head.treeSize, lastRoot: head.rootHash, lastSignedAtMs: head.signedAtMs };
  await writeTreeHeadState(keysDir, { logs: { ...(current?.logs ?? {}), [head.logId]: next } });
  return next;
}

async function readInput(arg: string | undefined): Promise<string> {
  if (!arg) throw new CliError('reinit-from-head needs a file path or - for stdin');
  if (arg !== '-') return readFile(arg, 'utf8');
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) chunks.push(chunk as Buffer);
  return Buffer.concat(chunks).toString('utf8');
}

export async function main(argv: string[]): Promise<number> {
  const keysDir = process.env.SIGNER_KEYS_DIR ?? './keys';
  const [command, ...rest] = argv;
  const print = (value: unknown) => process.stdout.write(`${JSON.stringify(value, null, 2)}\n`);
  try {
    switch (command) {
      case 'genesis-init': {
        const i = rest.indexOf('--log-id');
        print(await genesisInit(keysDir, i >= 0 ? rest[i + 1] : TRUST_LOG_ORIGIN));
        return 0;
      }
      case 'show-state':
        print(await showState(keysDir));
        return 0;
      case 'export-tree-head-pubkey':
        print(await exportTreeHeadPublicKey(keysDir));
        return 0;
      case 'reinit-from-head': {
        const logger = { info: () => {}, error: (o: object, m: string) => process.stderr.write(`${m} ${JSON.stringify(o)}\n`) };
        const { implementation } = selectSlhDsaImplementation({ logger, mode: process.env.SIGNER_SLH_DSA_IMPL });
        const state = await reinitFromHead(keysDir, await readInput(rest[0]), implementation);
        print({ reinitialised: true, lastSize: state.lastSize, lastRoot: b64(state.lastRoot), keyId: state.keyId });
        return 0;
      }
      default:
        process.stderr.write('usage: tree-head-cli.js genesis-init [--log-id <origin>] | show-state | export-tree-head-pubkey | reinit-from-head <file|->\n');
        return 2;
    }
  } catch (err) {
    process.stderr.write(`error: ${err instanceof Error ? err.message : String(err)}\n`);
    return 1;
  }
}

const isEntryPoint = process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isEntryPoint) {
  main(process.argv.slice(2)).then((code) => process.exit(code));
}
