/**
 * Trust Records schema (ADR-0009 D2) against a real Postgres: CHECK
 * constraints, append-only triggers, the dense leaf index under concurrent
 * appends, and log rows surviving the deletion of the QR code and the
 * organization they describe. No write path exists yet (TR-2), so rows are
 * inserted directly. Run by scripts/ci-verify.sh `db`.
 */
import { randomBytes } from 'node:crypto';

import { Prisma, PrismaClient } from '@prisma/client';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

const url = process.env.TEST_DATABASE_URL;
if (!url) throw new Error('TEST_DATABASE_URL is not set');
if (!/test/i.test(new URL(url).pathname)) throw new Error('TEST_DATABASE_URL must name a test database (the suite truncates tables)');

const CONCURRENCY = 50;
const poolUrl = new URL(url);
poolUrl.searchParams.set('connection_limit', String(CONCURRENCY + 5));
const db = new PrismaClient({ datasources: { db: { url: poolUrl.toString() } } });

const h32 = () => randomBytes(32);
type Tx = Prisma.TransactionClient | PrismaClient;

/**
 * Remove every Trust Records row. The triggers refuse DELETE and TRUNCATE,
 * so cleanup runs with triggers disabled, which only a superuser (the test
 * database owner) can do.
 */
async function wipeTrustTables(): Promise<void> {
  await db.$transaction([
    db.$executeRawUnsafe("SET LOCAL session_replication_role = 'replica'"),
    ...['trust_anchor_proofs', 'trust_tree_heads', 'trust_events', 'trust_log_leaves', 'trust_subjects'].map((t) =>
      db.$executeRawUnsafe(`DELETE FROM "${t}"`),
    ),
  ]);
}

async function nextLeafIndex(tx: Tx): Promise<bigint> {
  const [row] = await tx.$queryRaw<Array<{ next: bigint }>>`SELECT "trust_log_next_leaf_index"() AS next`;
  return row.next;
}

async function appendLeaf(tx: Tx, organizationId: string | null = 'org_1', kind: 'EVENT' | 'BATCH' | 'KEYSET' = 'BATCH') {
  const leafIndex = await nextLeafIndex(tx);
  return tx.trustLogLeaf.create({
    data: { leafIndex, kind, organizationId: kind === 'KEYSET' ? null : organizationId, body: h32(), leafHash: h32(), appendedAt: new Date() },
  });
}

async function appendEvent(subjectId: string, seq: number, prev: Uint8Array | null) {
  return db.$transaction(async (tx) => {
    const leaf = await appendLeaf(tx, 'org_1', 'EVENT');
    return tx.trustEvent.create({
      data: {
        subjectId, organizationId: 'org_1', seq, type: seq === 1 ? 'ISSUED' : 'UPDATED',
        actorType: 'SYSTEM', actorId: 'test', state: { status: 'ACTIVE' }, payload: { note: 'x' },
        salt: h32(), eventCommitment: h32(), prevEventCommitment: prev ? Buffer.from(prev) : null,
        occurredAt: new Date(), appendedAt: leaf.appendedAt, leafIndex: leaf.leafIndex,
      },
    });
  });
}

async function leafIndices(): Promise<bigint[]> {
  return (await db.trustLogLeaf.findMany({ select: { leafIndex: true }, orderBy: { leafIndex: 'asc' } })).map((l) => l.leafIndex);
}

const dense = (n: number) => Array.from({ length: n }, (_, i) => BigInt(i));

beforeAll(async () => {
  await wipeTrustTables();
});

beforeEach(async () => {
  await wipeTrustTables();
});

afterAll(async () => {
  await wipeTrustTables();
  await db.$disconnect();
});

describe('migration', () => {
  it('creates the five tables with their triggers', async () => {
    const triggers = await db.$queryRaw<Array<{ table: string; trigger: string }>>`
      SELECT c.relname AS "table", t.tgname AS "trigger"
      FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid
      WHERE NOT t.tgisinternal AND c.relname LIKE 'trust\\_%'
      ORDER BY 1, 2`;
    const byTable = triggers.reduce<Record<string, number>>((acc, t) => ({ ...acc, [t.table]: (acc[t.table] ?? 0) + 1 }), {});
    expect(Object.keys(byTable).sort()).toEqual([
      'trust_anchor_proofs', 'trust_events', 'trust_log_leaves', 'trust_subjects', 'trust_tree_heads',
    ]);
    // every table: row guard + TRUNCATE guard; leaves also the dense-index guard
    expect(byTable.trust_log_leaves).toBe(3);
    for (const t of ['trust_anchor_proofs', 'trust_events', 'trust_subjects', 'trust_tree_heads']) expect(byTable[t]).toBe(2);
  });

  it('uses timestamptz for every timestamp column', async () => {
    const cols = await db.$queryRaw<Array<{ table_name: string; column_name: string; data_type: string }>>`
      SELECT table_name, column_name, data_type FROM information_schema.columns
      WHERE table_name LIKE 'trust\\_%' AND data_type LIKE 'timestamp%'`;
    expect(cols.length).toBeGreaterThanOrEqual(9);
    for (const c of cols) expect(`${c.table_name}.${c.column_name}:${c.data_type}`).toMatch(/with time zone$/);
  });
});

describe('dense leaf index', () => {
  it('starts at 0 and allocates max + 1', async () => {
    for (let i = 0; i < 3; i++) await db.$transaction((tx) => appendLeaf(tx));
    expect(await leafIndices()).toEqual(dense(3));
  });

  it('refuses a gap, a duplicate and a first leaf other than 0', async () => {
    const leaf = (leafIndex: bigint) => ({ leafIndex, kind: 'BATCH' as const, organizationId: 'o', body: h32(), leafHash: h32(), appendedAt: new Date() });
    await expect(db.trustLogLeaf.create({ data: leaf(1n) })).rejects.toThrow(/dense/);
    await db.trustLogLeaf.create({ data: leaf(0n) });
    await expect(db.trustLogLeaf.create({ data: leaf(2n) })).rejects.toThrow(/dense/);
    await expect(db.trustLogLeaf.create({ data: leaf(0n) })).rejects.toThrow();
    expect(await leafIndices()).toEqual(dense(1));
  });

  it('a rolled-back append leaves no gap', async () => {
    await db.$transaction((tx) => appendLeaf(tx));
    await expect(
      db.$transaction(async (tx) => {
        await appendLeaf(tx);
        throw new Error('rollback');
      }),
    ).rejects.toThrow('rollback');
    await db.$transaction((tx) => appendLeaf(tx));
    expect(await leafIndices()).toEqual(dense(2));
  });

  it('accepts several consecutive leaves in one INSERT statement', async () => {
    const rows = [0, 1, 2].map((i) => ({ leafIndex: BigInt(i), kind: 'BATCH' as const, organizationId: 'o', body: h32(), leafHash: h32(), appendedAt: new Date() }));
    await db.trustLogLeaf.createMany({ data: rows });
    expect(await leafIndices()).toEqual(dense(3));
  });

  it(`${CONCURRENCY} parallel appends yield 0..${CONCURRENCY - 1} with no gap and no duplicate`, async () => {
    const results = await Promise.allSettled(
      Array.from({ length: CONCURRENCY }, () => db.$transaction((tx) => appendLeaf(tx), { timeout: 60_000, maxWait: 60_000 })),
    );
    const rejected = results.filter((r) => r.status === 'rejected');
    expect(rejected).toEqual([]);
    const indices = await leafIndices();
    expect(indices).toEqual(dense(CONCURRENCY));
    expect(new Set(indices.map(String)).size).toBe(CONCURRENCY);
  });
});

describe('append-only triggers', () => {
  it('trust_log_leaves refuses UPDATE, DELETE and TRUNCATE', async () => {
    const leaf = await db.$transaction((tx) => appendLeaf(tx));
    await expect(db.trustLogLeaf.update({ where: { leafIndex: leaf.leafIndex }, data: { body: h32() } })).rejects.toThrow(/append-only/);
    await expect(db.trustLogLeaf.delete({ where: { leafIndex: leaf.leafIndex } })).rejects.toThrow(/append-only/);
    await expect(db.$executeRawUnsafe('TRUNCATE "trust_log_leaves" CASCADE')).rejects.toThrow(/append-only/);
    expect(await leafIndices()).toEqual(dense(1));
  });

  it('trust_subjects refuses UPDATE and DELETE', async () => {
    const s = await db.trustSubject.create({ data: { organizationId: 'org_1', kind: 'QR_CODE', qrCodeId: 'qr_1' } });
    await expect(db.trustSubject.update({ where: { id: s.id }, data: { qrCodeId: 'qr_2' } })).rejects.toThrow(/append-only/);
    await expect(db.trustSubject.delete({ where: { id: s.id } })).rejects.toThrow(/append-only/);
  });

  it('trust_events refuses UPDATE and DELETE', async () => {
    const s = await db.trustSubject.create({ data: { organizationId: 'org_1', kind: 'QR_CODE', qrCodeId: 'qr_e' } });
    const e = await appendEvent(s.id, 1, null);
    await expect(db.trustEvent.update({ where: { id: e.id }, data: { type: 'REVOKED' } })).rejects.toThrow(/append-only/);
    await expect(db.trustEvent.delete({ where: { id: e.id } })).rejects.toThrow(/append-only/);
  });

  it('trust_events allows the D11 erasure: only payload and salt cleared, only under the maintenance flag', async () => {
    const s = await db.trustSubject.create({ data: { organizationId: 'org_1', kind: 'QR_CODE', qrCodeId: 'qr_gdpr' } });
    const e = await appendEvent(s.id, 1, null);
    const erase = (extra: Prisma.TrustEventUpdateInput = {}, flag = true) =>
      db.$transaction(async (tx) => {
        if (flag) await tx.$executeRawUnsafe("SET LOCAL qrauth.audit_maintenance = 'erasure'");
        return tx.trustEvent.update({ where: { id: e.id }, data: { payload: Prisma.DbNull, salt: null, ...extra } });
      });

    await expect(erase({}, false)).rejects.toThrow(/append-only/);
    await expect(erase({ actorId: 'someone-else' })).rejects.toThrow(/append-only/);
    const erased = await erase();
    expect(erased.payload).toBeNull();
    expect(erased.salt).toBeNull();
    expect(Buffer.from(erased.eventCommitment).equals(Buffer.from(e.eventCommitment))).toBe(true);
  });

  it('trust_tree_heads refuses UPDATE and DELETE', async () => {
    await db.trustTreeHead.create({ data: { treeSize: 0n, origin: 'qrauth.io/trust/v1', rootHash: h32(), signedAt: new Date(), keyId: 'k', signature: randomBytes(64) } });
    await expect(db.trustTreeHead.update({ where: { treeSize: 0n }, data: { keyId: 'other' } })).rejects.toThrow(/append-only/);
    await expect(db.trustTreeHead.delete({ where: { treeSize: 0n } })).rejects.toThrow(/append-only/);
  });

  it('trust_anchor_proofs allows only PENDING -> COMPLETE or FAILED', async () => {
    await db.trustTreeHead.create({ data: { treeSize: 5n, origin: 'qrauth.io/trust/v1', rootHash: h32(), signedAt: new Date(), keyId: 'k', signature: randomBytes(64) } });
    const pending = () => db.trustAnchorProof.create({
      data: { treeSize: 5n, kind: 'OTS', endpoint: 'https://calendar.example.test', digest: h32(), proof: randomBytes(40), submittedAt: new Date() },
    });

    const a = await pending();
    // the immutable columns cannot change, even on a valid transition
    await expect(db.trustAnchorProof.update({ where: { id: a.id }, data: { status: 'COMPLETE', attestedTime: new Date(), digest: h32() } })).rejects.toThrow(/PENDING/);
    // PENDING -> PENDING is not a transition
    await expect(db.trustAnchorProof.update({ where: { id: a.id }, data: { proof: randomBytes(50) } })).rejects.toThrow(/PENDING/);
    const done = await db.trustAnchorProof.update({
      where: { id: a.id },
      data: { status: 'COMPLETE', proof: randomBytes(200), upgradedAt: new Date(), attestedTime: new Date(), attestation: 'block 900000' },
    });
    expect(done.status).toBe('COMPLETE');
    // terminal states never change again
    await expect(db.trustAnchorProof.update({ where: { id: a.id }, data: { status: 'FAILED', error: 'x' } })).rejects.toThrow(/PENDING/);

    const b = await pending();
    await expect(db.trustAnchorProof.update({ where: { id: b.id }, data: { status: 'FAILED' } })).rejects.toThrow(/check constraint/i);
    await db.trustAnchorProof.update({ where: { id: b.id }, data: { status: 'FAILED', error: 'calendar unreachable' } });
    await expect(db.trustAnchorProof.delete({ where: { id: b.id } })).rejects.toThrow(/PENDING/);
  });

  it.each(['trust_subjects', 'trust_events', 'trust_tree_heads', 'trust_anchor_proofs'])('%s refuses TRUNCATE', async (table) => {
    await expect(db.$executeRawUnsafe(`TRUNCATE "${table}" CASCADE`)).rejects.toThrow(/append-only/);
  });
});

describe('CHECK constraints', () => {
  it('hashes, roots, commitments and digests are exactly 32 bytes', async () => {
    const short = randomBytes(31);
    await expect(db.$transaction(async (tx) => {
      const leafIndex = await nextLeafIndex(tx);
      return tx.trustLogLeaf.create({ data: { leafIndex, kind: 'BATCH', organizationId: 'o', body: h32(), leafHash: short, appendedAt: new Date() } });
    })).rejects.toThrow(/check constraint/i);
    await expect(db.trustTreeHead.create({ data: { treeSize: 1n, origin: 'qrauth.io/trust/v1', rootHash: short, signedAt: new Date(), keyId: 'k', signature: randomBytes(8) } })).rejects.toThrow(/check constraint/i);
  });

  it('platform leaves have no organization; EVENT and BATCH leaves have one', async () => {
    const insert = (kind: 'KEYSET' | 'BATCH', organizationId: string | null) => db.$transaction(async (tx) => {
      const leafIndex = await nextLeafIndex(tx);
      return tx.trustLogLeaf.create({ data: { leafIndex, kind, organizationId, body: h32(), leafHash: h32(), appendedAt: new Date() } });
    });
    await expect(insert('KEYSET', 'org_1')).rejects.toThrow(/check constraint/i);
    await expect(insert('BATCH', null)).rejects.toThrow(/check constraint/i);
    await insert('KEYSET', null);
  });

  it('seq starts at 1 without a previous commitment and later events chain to one', async () => {
    const s = await db.trustSubject.create({ data: { organizationId: 'org_1', kind: 'QR_CODE', qrCodeId: 'qr_chain' } });
    await expect(appendEvent(s.id, 1, h32())).rejects.toThrow(/check constraint/i);
    const first = await appendEvent(s.id, 1, null);
    await expect(appendEvent(s.id, 2, null)).rejects.toThrow(/check constraint/i);
    await appendEvent(s.id, 2, first.eventCommitment);
    await expect(appendEvent(s.id, 2, first.eventCommitment)).rejects.toThrow(/Unique constraint/);
  });

  it('a QR_CODE subject names its code', async () => {
    await expect(db.trustSubject.create({ data: { organizationId: 'org_1', kind: 'QR_CODE' } })).rejects.toThrow(/check constraint/i);
  });
});

describe('log data outlives the code and the organization', () => {
  it('deleting the QR code and then its organization leaves subject, event and leaf intact', async () => {
    const org = await db.organization.create({ data: { name: 'Trust Org', slug: `trust-org-${Date.now()}`, email: 'trust@records.test' } });
    const key = await db.signingKey.create({ data: { organizationId: org.id, publicKey: 'pk', keyId: `key-trust-${org.id}` } });
    const code = await db.qRCode.create({
      data: { token: `tr${Date.now()}`, organizationId: org.id, signingKeyId: key.id, destinationUrl: 'https://trust.example.test/', signature: 's', algVersion: 'test' },
    });
    const subject = await db.trustSubject.create({ data: { organizationId: org.id, kind: 'QR_CODE', qrCodeId: code.id } });
    const event = await appendEvent(subject.id, 1, null);

    await db.qRCode.delete({ where: { id: code.id } });
    await db.$executeRawUnsafe('DELETE FROM "organizations" WHERE "id" = $1', org.id);

    expect(await db.qRCode.findUnique({ where: { id: code.id } })).toBeNull();
    expect((await db.trustSubject.findUniqueOrThrow({ where: { id: subject.id } })).qrCodeId).toBe(code.id);
    expect((await db.trustEvent.findUniqueOrThrow({ where: { id: event.id } })).leafIndex).toBe(event.leafIndex);
    expect(await db.trustLogLeaf.findUnique({ where: { leafIndex: event.leafIndex } })).not.toBeNull();
  });
});
