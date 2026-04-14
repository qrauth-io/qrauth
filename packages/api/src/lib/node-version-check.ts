/**
 * Runtime Node.js version assertion (ALGORITHM.md §15.3).
 *
 * Imported as the first side-effecting module in `server.ts` so it runs
 * before anything else evaluates. ESM imports are processed depth-first,
 * so this file's top-level code is the first thing the process executes
 * once module resolution completes. If the running Node is older than the
 * minimum we support, fail loud at startup rather than silently degrading
 * inside one of the cryptographic primitives we rely on.
 *
 * Why this matters specifically for QRAuth: the post-quantum signing path
 * uses SHA3-256 via `createHash('sha3-256')` and HMAC-SHA3-256 for the
 * symmetric MAC fast path. Both rely on OpenSSL 3 + Node 22's stable
 * crypto surface. Older runtimes can crash deep inside the noble
 * post-quantum library or produce a confusing "unsupported algorithm"
 * error far from the actual root cause.
 */

export const MIN_NODE_MAJOR = 22;

/**
 * Pure check exported for testing — returns null when the version is
 * acceptable, or an error message string when it is not. The side-effect
 * branch below uses this to decide whether to exit the process.
 */
export function checkNodeVersion(versionString: string): string | null {
  const major = Number.parseInt(versionString.split('.')[0] ?? '0', 10);
  if (Number.isNaN(major) || major < MIN_NODE_MAJOR) {
    return (
      `[qrauth] Refusing to start: Node.js ${versionString} is below the minimum supported version (${MIN_NODE_MAJOR}.x).\n` +
      '         The QRAuth API depends on SHA3-256 and other crypto primitives stabilized in Node 22+.\n' +
      '         Upgrade Node, then retry. See https://nodejs.org/en/about/previous-releases'
    );
  }
  return null;
}

const failureMessage = checkNodeVersion(process.versions.node);
if (failureMessage !== null) {
  // Use process.stderr.write directly — pino isn't loaded yet at this
  // point in startup, and we want the message to land regardless of
  // whether stdout is a TTY or a pipe.
  process.stderr.write(`\n${failureMessage}\n\n`);
  process.exit(1);
}
