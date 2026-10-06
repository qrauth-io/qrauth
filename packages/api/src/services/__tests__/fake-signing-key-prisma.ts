import { randomUUID } from 'node:crypto';
import type { PrismaClient, SigningKey } from '@prisma/client';

/**
 * In-memory Prisma double covering exactly the SigningKey query surface the
 * signing service, the cleanup-worker rotation steps, and the OIDC key-health
 * helper use. Mirrors the fake-Prisma pattern in
 * `packages/protocol-tests/src/batch-signer.test.ts`.
 *
 * Deliberately NOT a generic Prisma mock: unknown filter fields throw so a
 * query-shape change in production code fails tests loudly instead of
 * silently matching everything.
 */

type Status = 'ACTIVE' | 'ROTATED' | 'REVOKED';

export interface SeedKeyInput {
  organizationId: string;
  algorithm: 'ES256' | 'RS256';
  status?: Status;
  createdAt?: Date;
  rotatedAt?: Date | null;
  revokedAt?: Date | null;
  keyId?: string;
  publicKey?: string;
}

interface WhereClause {
  id?: string;
  keyId?: string;
  organizationId?: string;
  algorithm?: string | { in: string[] };
  status?: Status | { in: Status[] };
  createdAt?: { lt: Date };
  rotatedAt?: { lt?: Date; gte?: Date };
  organization?: { slug: string };
  /** Prisma OR semantics: the row must match at least one sub-clause. */
  OR?: WhereClause[];
}

function matchScalar(value: string, filter: string | { in: string[] } | undefined): boolean {
  if (filter === undefined) return true;
  if (typeof filter === 'string') return value === filter;
  if (Array.isArray(filter.in)) return filter.in.includes(value);
  throw new Error(`fake-signing-key-prisma: unsupported scalar filter ${JSON.stringify(filter)}`);
}

export class FakeSigningKeyPrisma {
  rows: SigningKey[] = [];

  /** organizationId → slug, for `organization: { slug }` filters. */
  orgSlugs = new Map<string, string>();

  seedOrg(organizationId: string, slug: string): void {
    this.orgSlugs.set(organizationId, slug);
  }

  seedKey(input: SeedKeyInput): SigningKey {
    const row: SigningKey = {
      id: randomUUID(),
      organizationId: input.organizationId,
      publicKey: input.publicKey ?? `-----FAKE PUBLIC KEY ${randomUUID()}-----`,
      keyId: input.keyId ?? randomUUID(),
      algorithm: input.algorithm,
      status: input.status ?? 'ACTIVE',
      createdAt: input.createdAt ?? new Date(),
      rotatedAt: input.rotatedAt ?? null,
      revokedAt: input.revokedAt ?? null,
      slhdsaPublicKey: input.algorithm === 'ES256' ? 'ZmFrZS1zbGhkc2E=' : null,
      slhdsaAlgorithm: input.algorithm === 'ES256' ? 'slh-dsa-sha2-128s' : null,
    } as SigningKey;
    this.rows.push(row);
    return row;
  }

  activeKeys(organizationId?: string): SigningKey[] {
    return this.rows.filter(
      (r) => r.status === 'ACTIVE' && (!organizationId || r.organizationId === organizationId),
    );
  }

  private match(row: SigningKey, where: WhereClause): boolean {
    for (const field of Object.keys(where)) {
      if (!['id', 'keyId', 'organizationId', 'algorithm', 'status', 'createdAt', 'rotatedAt', 'organization', 'OR'].includes(field)) {
        throw new Error(`fake-signing-key-prisma: unsupported where field "${field}"`);
      }
    }
    if (where.id !== undefined && row.id !== where.id) return false;
    if (where.keyId !== undefined && row.keyId !== where.keyId) return false;
    if (where.organizationId !== undefined && row.organizationId !== where.organizationId) return false;
    if (!matchScalar(row.algorithm, where.algorithm)) return false;
    if (!matchScalar(row.status, where.status)) return false;
    if (where.createdAt?.lt !== undefined && !(row.createdAt < where.createdAt.lt)) return false;
    if (where.rotatedAt !== undefined) {
      const { lt, gte } = where.rotatedAt;
      if (lt !== undefined && (row.rotatedAt === null || !(row.rotatedAt < lt))) return false;
      if (gte !== undefined && (row.rotatedAt === null || !(row.rotatedAt >= gte))) return false;
    }
    if (where.organization !== undefined) {
      if (this.orgSlugs.get(row.organizationId) !== where.organization.slug) return false;
    }
    if (where.OR !== undefined) {
      if (!where.OR.some((sub) => this.match(row, sub))) return false;
    }
    return true;
  }

  private sorted(rows: SigningKey[], orderBy?: { createdAt?: 'asc' | 'desc' }): SigningKey[] {
    if (!orderBy?.createdAt) return rows;
    const dir = orderBy.createdAt === 'desc' ? -1 : 1;
    return [...rows].sort((a, b) => dir * (a.createdAt.getTime() - b.createdAt.getTime()));
  }

  readonly signingKey = {
    findFirst: async (args: { where: WhereClause; orderBy?: { createdAt?: 'asc' | 'desc' } }) =>
      this.sorted(this.rows.filter((r) => this.match(r, args.where)), args.orderBy)[0] ?? null,

    findUnique: async (args: { where: { keyId?: string; id?: string } }) =>
      this.rows.find(
        (r) =>
          (args.where.keyId !== undefined && r.keyId === args.where.keyId) ||
          (args.where.id !== undefined && r.id === args.where.id),
      ) ?? null,

    findMany: async (args: { where: WhereClause; orderBy?: { createdAt?: 'asc' | 'desc' } }) =>
      this.sorted(this.rows.filter((r) => this.match(r, args.where)), args.orderBy),

    create: async (args: { data: Record<string, unknown> }) => {
      const data = args.data as Partial<SigningKey> & {
        organizationId: string;
        publicKey: string;
        keyId: string;
        algorithm: string;
        status: Status;
      };
      const row: SigningKey = {
        id: randomUUID(),
        organizationId: data.organizationId,
        publicKey: data.publicKey,
        keyId: data.keyId,
        algorithm: data.algorithm,
        status: data.status,
        createdAt: new Date(),
        rotatedAt: null,
        revokedAt: null,
        slhdsaPublicKey: data.slhdsaPublicKey ?? null,
        slhdsaAlgorithm: data.slhdsaAlgorithm ?? null,
      } as SigningKey;
      this.rows.push(row);
      return row;
    },

    update: async (args: { where: { id: string }; data: Partial<SigningKey> }) => {
      const idx = this.rows.findIndex((r) => r.id === args.where.id);
      if (idx === -1) throw new Error(`fake-signing-key-prisma: no row with id ${args.where.id}`);
      const updated = { ...this.rows[idx], ...args.data } as SigningKey;
      this.rows = this.rows.map((r, i) => (i === idx ? updated : r));
      return updated;
    },

    updateMany: async (args: { where: WhereClause; data: Partial<SigningKey> }) => {
      let count = 0;
      this.rows = this.rows.map((r) => {
        if (!this.match(r, args.where)) return r;
        count += 1;
        return { ...r, ...args.data } as SigningKey;
      });
      return { count };
    },
  };

  readonly organization = {
    // Only consulted by the signing-key.created webhook enqueue; returning
    // null takes its (swallowed) "no endpoint configured" path.
    findUnique: async () => null,
  };

  async $transaction<T>(fn: (tx: this) => Promise<T>): Promise<T> {
    return fn(this);
  }

  asPrisma(): PrismaClient {
    return this as unknown as PrismaClient;
  }
}
