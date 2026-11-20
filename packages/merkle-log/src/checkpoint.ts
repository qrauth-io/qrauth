import { sha256 } from '@noble/hashes/sha2.js';
import { concatBytes, constantTimeEqual, isIndex } from './bytes.js';

/**
 * Trust Records tree heads (ADR-0009 D7, D9).
 *
 * - The signed message: "qrauth:tree-head:v1:" || logId || u64be(treeSize)
 *   || rootHash || u64be(signedAtMs), signed with the platform SLH-DSA key.
 * - The wire format: a C2SP tlog-checkpoint (c2sp.org/tlog-checkpoint, a
 *   c2sp.org/signed-note). The note text is origin, decimal tree size and
 *   base64 root. The log's signature line is
 *   `— <origin> base64(keyId || u64be(signedAtMs) || signature)`.
 *
 * The SLH-DSA signature covers the message above, not the note text, so it
 * uses signed-note signature type 0xff ("signature types without an
 * identifier byte assigned by this specification") followed by a long
 * identifier. Witness cosignature lines can be appended later without
 * changing anything here (out of scope for v1).
 */

/** Checkpoint origin and logId of the Trust Records log. */
export const TRUST_LOG_ORIGIN = 'qrauth.io/trust/v1';

/** Domain-separation prefix of the signed tree-head message. */
export const TREE_HEAD_DOMAIN_PREFIX = 'qrauth:tree-head:v1:';

/** signed-note signature type: 0xff followed by a collision-resistant identifier. */
export const TREE_HEAD_SIGNATURE_TYPE: Uint8Array = concatBytes(
  new Uint8Array([0xff]),
  new TextEncoder().encode('qrauth.io/tree-head/slh-dsa-sha2-128s/v1'),
);

const ROOT_BYTES = 32;
const KEY_ID_BYTES = 4;
const TIMESTAMP_BYTES = 8;
const EM_DASH = '—';

export class CheckpointError extends Error {}

export interface TreeHeadFields {
  logId: string;
  treeSize: number;
  rootHash: Uint8Array;
  signedAtMs: number;
}

export interface CheckpointHead {
  origin: string;
  treeSize: number;
  rootHash: Uint8Array;
}

export interface SignedCheckpointHead extends CheckpointHead {
  signedAtMs: number;
  signature: Uint8Array;
  publicKey: Uint8Array;
  /** Signature key name; defaults to the origin (C2SP recommendation). */
  keyName?: string;
}

export interface CheckpointSignature {
  keyName: string;
  keyId: Uint8Array;
  /** u64be timestamp at the start of the signature bytes, when present and safe. */
  signedAtMs: number | null;
  /** Signature bytes after the timestamp (or all bytes when there is none). */
  signature: Uint8Array;
}

export interface ParsedCheckpoint extends CheckpointHead {
  signatures: CheckpointSignature[];
}

/** Key names / origins: non-empty, no spaces, no '+', no control characters. */
function assertKeyName(name: string, what: string): void {
  if (name.length === 0 || /[\s+\u0000-\u001f\u007f]/u.test(name)) {
    throw new CheckpointError(`${what} must be non-empty, without spaces, '+' or control characters`);
  }
}

function u64be(value: number, what: string): Uint8Array {
  if (!isIndex(value)) throw new CheckpointError(`${what} must be a safe non-negative integer`);
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt(value));
  return out;
}

function readU64be(bytes: Uint8Array): number | null {
  const value = new DataView(bytes.buffer, bytes.byteOffset, 8).getBigUint64(0);
  return value <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(value) : null;
}

function assertRoot(rootHash: Uint8Array): void {
  if (rootHash.length !== ROOT_BYTES) throw new CheckpointError(`root hash must be ${ROOT_BYTES} bytes`);
}

function toBase64(bytes: Uint8Array): string {
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

/** Canonical (RFC 4648 §3.5) base64 only: decode, re-encode, compare. */
function fromBase64(text: string, what: string): Uint8Array {
  let binary: string;
  try {
    binary = atob(text);
  } catch {
    throw new CheckpointError(`${what} is not base64`);
  }
  const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
  if (toBase64(bytes) !== text) throw new CheckpointError(`${what} is not canonical base64`);
  return bytes;
}

/** The bytes the platform key signs for a tree head. */
export function treeHeadMessage(fields: TreeHeadFields): Uint8Array {
  assertKeyName(fields.logId, 'logId');
  assertRoot(fields.rootHash);
  const enc = new TextEncoder();
  return concatBytes(
    enc.encode(TREE_HEAD_DOMAIN_PREFIX),
    enc.encode(fields.logId),
    u64be(fields.treeSize, 'treeSize'),
    fields.rootHash,
    u64be(fields.signedAtMs, 'signedAtMs'),
  );
}

/** signed-note key ID: SHA-256(keyName || 0x0a || signature type || public key)[:4]. */
export function treeHeadKeyId(keyName: string, publicKey: Uint8Array): Uint8Array {
  assertKeyName(keyName, 'key name');
  const input = concatBytes(new TextEncoder().encode(keyName), new Uint8Array([0x0a]), TREE_HEAD_SIGNATURE_TYPE, publicKey);
  return sha256(input).subarray(0, KEY_ID_BYTES);
}

/** The checkpoint note text: origin, tree size and base64 root, each ending in "\n". */
export function checkpointNoteText(head: CheckpointHead): string {
  assertKeyName(head.origin, 'origin');
  assertRoot(head.rootHash);
  if (!isIndex(head.treeSize)) throw new CheckpointError('treeSize must be a safe non-negative integer');
  return `${head.origin}\n${head.treeSize}\n${toBase64(head.rootHash)}\n`;
}

/** A complete checkpoint: note text, blank line, the log's signature line. */
export function formatCheckpoint(head: SignedCheckpointHead): string {
  const keyName = head.keyName ?? head.origin;
  const keyId = treeHeadKeyId(keyName, head.publicKey);
  const sig = concatBytes(keyId, u64be(head.signedAtMs, 'signedAtMs'), head.signature);
  return `${checkpointNoteText(head)}\n${EM_DASH} ${keyName} ${toBase64(sig)}\n`;
}

function parseSignatureLine(line: string, ownKeyId: Uint8Array | undefined): CheckpointSignature {
  const match = /^— (\S+) (\S+)$/u.exec(line);
  if (!match) throw new CheckpointError('malformed signature line');
  const [, keyName, b64] = match;
  assertKeyName(keyName, 'key name');
  const bytes = fromBase64(b64, 'signature');
  if (bytes.length <= KEY_ID_BYTES) throw new CheckpointError('signature too short');
  const keyId = bytes.subarray(0, KEY_ID_BYTES);
  const rest = bytes.subarray(KEY_ID_BYTES);
  const own = ownKeyId !== undefined && constantTimeEqual(keyId, ownKeyId);
  if (rest.length > TIMESTAMP_BYTES) {
    const signedAtMs = readU64be(rest.subarray(0, TIMESTAMP_BYTES));
    if (own && signedAtMs === null) throw new CheckpointError('timestamp out of range');
    return { keyName, keyId: keyId.slice(), signedAtMs, signature: rest.slice(TIMESTAMP_BYTES) };
  }
  if (own) throw new CheckpointError('signature from the log key has no timestamp');
  return { keyName, keyId: keyId.slice(), signedAtMs: null, signature: rest.slice() };
}

/**
 * Parse a checkpoint strictly: exactly three note lines (no extension
 * lines), a decimal size without leading zeros, a canonical base64 32-byte
 * root, a blank line, then one or more signature lines. Signatures are not
 * verified here. Lines whose key ID equals `ownKeyId` must carry the log's
 * timestamp. Throws CheckpointError on anything else.
 */
export function parseCheckpoint(text: string, opts: { ownKeyId?: Uint8Array } = {}): ParsedCheckpoint {
  if (/[\u0000-\u0009\u000b-\u001f\u007f]/u.test(text)) throw new CheckpointError('control characters are not allowed');
  if (!text.endsWith('\n')) throw new CheckpointError('a checkpoint ends with a newline');
  const lines = text.slice(0, -1).split('\n');
  const blank = lines.lastIndexOf('');
  if (blank !== 3) throw new CheckpointError('expected exactly three note lines, a blank line and signature lines');
  const [origin, sizeText, rootText] = lines;
  assertKeyName(origin, 'origin');
  if (!/^(0|[1-9][0-9]*)$/.test(sizeText)) throw new CheckpointError('tree size must be an ASCII decimal without leading zeros');
  const treeSize = Number(sizeText);
  if (!isIndex(treeSize)) throw new CheckpointError('tree size is out of range');
  const rootHash = fromBase64(rootText, 'root hash');
  assertRoot(rootHash);
  const sigLines = lines.slice(blank + 1);
  if (sigLines.length === 0) throw new CheckpointError('a checkpoint needs at least one signature line');
  const signatures = sigLines.map((l) => parseSignatureLine(l, opts.ownKeyId));
  return { origin, treeSize, rootHash, signatures };
}
