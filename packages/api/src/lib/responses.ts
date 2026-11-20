/**
 * Canonical 404 "Not Found" response envelope — the shape handlers were
 * sending inline: `{ statusCode: 404, error: 'Not Found', message }`. Building
 * it here keeps the envelope consistent and the message in one standard form.
 *
 *   notFoundError('QR code', token) -> { ..., message: 'QR code "abc" not found.' }
 *   notFoundError('QR code')        -> { ..., message: 'QR code not found.' }
 *
 * Use with Fastify: `return reply.status(404).send(notFoundError('QR code', id));`
 */
export function notFoundError(resource: string, id?: string | number) {
  const message = id === undefined ? `${resource} not found.` : `${resource} "${id}" not found.`;
  return { statusCode: 404, error: 'Not Found', message } as const;
}
