import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import fc from 'fast-check';
import {
  CheckpointError,
  TREE_HEAD_DOMAIN_PREFIX,
  TREE_HEAD_SIGNATURE_TYPE,
  TRUST_LOG_ORIGIN,
  checkpointNoteText,
  formatCheckpoint,
  parseCheckpoint,
  sha256Hasher,
  treeHeadKeyId,
  treeHeadMessage,
} from '../src/index.js';

/**
 * C2SP tlog-checkpoint serialization of Trust Records tree heads and the
 * signed tree-head message (ADR-0009 D7).
 */

const root = createHash('sha256').update('root').digest();
const sig = new Uint8Array(7856).map((_, i) => i % 251);
const pub = new Uint8Array(32).map((_, i) => i);

describe('treeHeadMessage', () => {
  it('is prefix || logId || u64be(treeSize) || rootHash || u64be(signedAtMs)', () => {
    const msg = treeHeadMessage({ logId: TRUST_LOG_ORIGIN, treeSize: 0x0102, rootHash: root, signedAtMs: 1_700_000_000_123 });
    const expected = Buffer.concat([
      Buffer.from('qrauth:tree-head:v1:', 'utf8'),
      Buffer.from('qrauth.io/trust/v1', 'utf8'),
      Buffer.from('0000000000000102', 'hex'),
      root,
      Buffer.from((1_700_000_000_123).toString(16).padStart(16, '0'), 'hex'),
    ]);
    expect(Buffer.from(msg).equals(expected)).toBe(true);
    expect(TREE_HEAD_DOMAIN_PREFIX).toBe('qrauth:tree-head:v1:');
  });

  it('rejects bad sizes, timestamps, roots and log ids', () => {
    const ok = { logId: TRUST_LOG_ORIGIN, treeSize: 1, rootHash: root, signedAtMs: 1 };
    for (const bad of [
      { ...ok, treeSize: -1 }, { ...ok, treeSize: 2 ** 53 }, { ...ok, treeSize: 1.5 },
      { ...ok, signedAtMs: -1 }, { ...ok, rootHash: root.subarray(0, 31) },
      { ...ok, logId: '' }, { ...ok, logId: 'has space' }, { ...ok, logId: 'a+b' }, { ...ok, logId: 'a\nb' },
    ]) {
      expect(() => treeHeadMessage(bad), JSON.stringify({ ...bad, rootHash: bad.rootHash.length })).toThrow(CheckpointError);
    }
  });
});

describe('checkpoint note text', () => {
  it('is origin, decimal size and base64 root, each ending in a newline', () => {
    expect(checkpointNoteText({ origin: TRUST_LOG_ORIGIN, treeSize: 0, rootHash: sha256Hasher.emptyRoot() })).toBe(
      'qrauth.io/trust/v1\n0\n47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=\n',
    );
  });
});

describe('treeHeadKeyId', () => {
  it('is SHA-256(name || 0x0a || signature type || public key)[:4]', () => {
    const expected = createHash('sha256')
      .update(Buffer.concat([Buffer.from(TRUST_LOG_ORIGIN), Buffer.from([0x0a]), Buffer.from(TREE_HEAD_SIGNATURE_TYPE), pub]))
      .digest()
      .subarray(0, 4);
    expect(Buffer.from(treeHeadKeyId(TRUST_LOG_ORIGIN, pub)).equals(expected)).toBe(true);
    expect(TREE_HEAD_SIGNATURE_TYPE[0]).toBe(0xff);
  });
});

describe('formatCheckpoint / parseCheckpoint', () => {
  const head = { origin: TRUST_LOG_ORIGIN, treeSize: 42, rootHash: root, signedAtMs: 1_763_600_000_000, signature: sig, publicKey: pub };

  it('formats a signed note with one signature line and parses it back', () => {
    const text = formatCheckpoint(head);
    const lines = text.split('\n');
    expect(lines.slice(0, 4)).toEqual(['qrauth.io/trust/v1', '42', Buffer.from(root).toString('base64'), '']);
    expect(lines[4].startsWith('— qrauth.io/trust/v1 ')).toBe(true);
    expect(text.endsWith('\n')).toBe(true);

    const parsed = parseCheckpoint(text);
    expect(parsed.origin).toBe(TRUST_LOG_ORIGIN);
    expect(parsed.treeSize).toBe(42);
    expect(Buffer.from(parsed.rootHash).equals(root)).toBe(true);
    expect(parsed.signatures).toHaveLength(1);
    const [s] = parsed.signatures;
    expect(s.keyName).toBe(TRUST_LOG_ORIGIN);
    expect(Buffer.from(s.keyId).equals(Buffer.from(treeHeadKeyId(TRUST_LOG_ORIGIN, pub)))).toBe(true);
    expect(s.signedAtMs).toBe(head.signedAtMs);
    expect(Buffer.from(s.signature).equals(Buffer.from(sig))).toBe(true);
  });

  it('round-trips random heads', () => {
    fc.assert(
      fc.property(
        fc.nat({ max: Number.MAX_SAFE_INTEGER }),
        fc.uint8Array({ minLength: 32, maxLength: 32 }),
        fc.nat({ max: 2 ** 47 }),
        fc.uint8Array({ minLength: 1, maxLength: 64 }),
        (treeSize, rootHash, signedAtMs, signature) => {
          const parsed = parseCheckpoint(formatCheckpoint({ ...head, treeSize, rootHash, signedAtMs, signature }));
          expect(parsed.treeSize).toBe(treeSize);
          expect(Buffer.from(parsed.rootHash).equals(Buffer.from(rootHash))).toBe(true);
          expect(parsed.signatures[0].signedAtMs).toBe(signedAtMs);
        },
      ),
    );
  });

  it('keeps unknown signature lines (cosignatures) without interpreting them', () => {
    const text = formatCheckpoint(head) + '— witness.example/w1 ' + Buffer.from(new Uint8Array(76)).toString('base64') + '\n';
    const parsed = parseCheckpoint(text);
    expect(parsed.signatures.map((s) => s.keyName)).toEqual([TRUST_LOG_ORIGIN, 'witness.example/w1']);
  });

  it.each([
    ['no signature line', 'qrauth.io/trust/v1\n1\n' + Buffer.from(root).toString('base64') + '\n\n'],
    ['missing blank line', formatCheckpoint(head).replace('\n\n', '\n')],
    ['leading zero size', formatCheckpoint(head).replace('\n42\n', '\n042\n')],
    ['negative size', formatCheckpoint(head).replace('\n42\n', '\n-42\n')],
    ['non-canonical base64 root', formatCheckpoint(head).replace(Buffer.from(root).toString('base64'), Buffer.from(root).toString('base64').replace(/=$/, ''))],
    ['31-byte root', formatCheckpoint({ ...head, rootHash: root }).replace(Buffer.from(root).toString('base64'), Buffer.from(root.subarray(0, 31)).toString('base64'))],
    ['extension line', formatCheckpoint(head).replace('\n\n', '\nextension\n\n')],
    ['control character', formatCheckpoint(head).replace('qrauth.io', 'qrauth\tio')],
    ['no final newline', formatCheckpoint(head).slice(0, -1)],
    ['signature without em dash', formatCheckpoint(head).replace('— ', '- ')],
  ])('rejects %s', (_name, text) => {
    expect(() => parseCheckpoint(text)).toThrow(CheckpointError);
  });

  it('a signature line from our key that is too short to hold the timestamp is rejected', () => {
    const ownKeyId = treeHeadKeyId(TRUST_LOG_ORIGIN, pub);
    const shortLine = '— qrauth.io/trust/v1 ' + Buffer.concat([ownKeyId, new Uint8Array(6)]).toString('base64') + '\n';
    const text = checkpointNoteText(head) + '\n' + shortLine;
    expect(() => parseCheckpoint(text, { ownKeyId })).toThrow(CheckpointError);
    // the same bytes under another key ID are kept, uninterpreted
    const other = '— qrauth.io/trust/v1 ' + Buffer.concat([new Uint8Array(4), new Uint8Array(6)]).toString('base64') + '\n';
    expect(parseCheckpoint(checkpointNoteText(head) + '\n' + other, { ownKeyId }).signatures[0].signedAtMs).toBeNull();
  });
});
