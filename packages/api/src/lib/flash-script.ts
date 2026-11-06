import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { FastifyInstance } from 'fastify';

/**
 * The trust-flash script (public/sdk/verify-flash.js), served under a
 * content-hashed name so browsers and the CDN can cache it for a year.
 *
 * The hash is computed from the file at startup, so a change to the script
 * changes the URL the verify page references without any hand-maintained
 * version. The unhashed /sdk/verify-flash.js stays served by @fastify/static
 * (max-age=0) for any HTML that still references it.
 */

/** Same file the static plugin serves; this module sits one level below src/ or dist/. */
const SOURCE_FILE = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'public', 'sdk', 'verify-flash.js');

/** Hex characters of the SHA-256 kept in the file name. */
const HASH_LENGTH = 16;

export const FLASH_SCRIPT_CACHE_CONTROL = 'public, max-age=31536000, immutable';

export interface FlashScript {
  /** Public URL path, e.g. /sdk/verify-flash.0123456789abcdef.js */
  path: string;
  body: Buffer;
}

export function buildFlashScript(body: Buffer): FlashScript {
  const hash = createHash('sha256').update(body).digest('hex').slice(0, HASH_LENGTH);
  return { path: `/sdk/verify-flash.${hash}.js`, body };
}

export const FLASH_SCRIPT: FlashScript = buildFlashScript(readFileSync(SOURCE_FILE));

/** GET (and HEAD) for the hashed path. The verify page references only this path. */
export function registerFlashScriptRoute(app: FastifyInstance, script: FlashScript = FLASH_SCRIPT): void {
  app.get(script.path, async (_request, reply) =>
    reply
      .type('application/javascript; charset=utf-8')
      .header('Cache-Control', FLASH_SCRIPT_CACHE_CONTROL)
      .send(script.body),
  );
}
