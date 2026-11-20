import { vi } from 'vitest';

/**
 * Hand-built Prisma mocks for routes and services that write QR codes:
 * every such write runs in `prisma.$transaction` and records an edit-history
 * revision (services/qr-revisions.ts). This adds what that needs to a mock:
 *
 * - `$transaction(fn)` runs `fn` with the same mock as `tx`;
 * - `$queryRaw` (the row lock) resolves [];
 * - `qRCodeRevision.create` / `createMany` / `groupBy` (no prior revisions);
 * - `auditLog.create` (audit entries for fields outside the edit history);
 * - `orgPolicy.findUnique` (no organization policy: the defaults).
 *
 * A `$transaction`, `$queryRaw` or `orgPolicy` the base mock already has is kept. The
 * returned object shares the base's model mocks, so assertions on them hold.
 */
export function withRevisionMocks<T extends object>(base: T) {
  const qRCodeRevision = {
    create: vi.fn(async ({ data }: { data: Record<string, unknown> }) => data),
    createMany: vi.fn(async ({ data }: { data: unknown[] }) => ({ count: data.length })),
    groupBy: vi.fn(async (_args: unknown): Promise<Array<{ qrCodeId: string; _max: { revision: number | null } }>> => []),
  };
  const auditLog = { create: vi.fn(async ({ data }: { data: Record<string, unknown> }) => data) };
  const mock = {
    auditLog,
    $queryRaw: vi.fn(async (..._args: unknown[]): Promise<unknown[]> => []),
    $transaction: vi.fn(async (work: (tx: unknown) => Promise<unknown>) => work(mock)),
    orgPolicy: { findUnique: vi.fn(async (_args: unknown): Promise<unknown> => null) },
    ...base,
    qRCodeRevision,
  };
  return mock;
}

/** The `data` of each audit entry recorded with `auditLog.create`. */
export function recordedAudits(mock: { auditLog: { create: { mock: { calls: Array<[{ data: Record<string, unknown> }]> } } } }) {
  return mock.auditLog.create.mock.calls.map(([args]) => args.data);
}

/** The `data` of each revision recorded with `qRCodeRevision.create`. */
export function recordedRevisions(mock: { qRCodeRevision: { create: { mock: { calls: Array<[{ data: Record<string, unknown> }]> } } } }) {
  return mock.qRCodeRevision.create.mock.calls.map(([args]) => args.data);
}
