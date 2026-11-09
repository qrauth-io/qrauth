/**
 * Global flags shared by every command. `apiUrl` is already resolved
 * (flag → env → default) by the time a command runs.
 */
export interface GlobalOpts {
  json: boolean;
  org?: string;
  apiUrl: string;
}

/**
 * Emit a command result. With `--json`, print the machine-readable payload and
 * nothing else; otherwise run `human` to print a friendly view. Keeping all
 * output behind this helper guarantees `--json` produces clean, parseable
 * stdout on every command.
 */
export function emit<T>(data: T, opts: { json: boolean }, human: (data: T) => void): void {
  if (opts.json) {
    process.stdout.write(JSON.stringify(data) + '\n');
  } else {
    human(data);
  }
}

/** Print an error and exit non-zero. Honours `--json` for machine consumers. */
export function fail(message: string, opts: { json: boolean }, code?: string): never {
  if (opts.json) {
    process.stdout.write(JSON.stringify({ error: code ?? 'ERROR', message }) + '\n');
  } else {
    process.stderr.write(`Error: ${message}\n`);
  }
  process.exit(1);
}
