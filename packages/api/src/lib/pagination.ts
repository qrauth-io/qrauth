/**
 * Zero-based offset for a 1-based page number — the `LIMIT`/`OFFSET` helper
 * shared by the list endpoints. Replaces the inline `(page - 1) * pageSize`
 * that was copy-pasted across routes.
 */
export function paginationSkip(page: number, pageSize: number): number {
  return (page - 1) * pageSize;
}
