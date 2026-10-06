import type {
  MacSignerClient,
  RegisterSessionResult,
  SignResult,
  VerifyResult,
} from './index.js';

/**
 * The `MAC_BACKEND=local` client. Every call returns `circuit_open` so the
 * dual-derive wrapper treats it uniformly as "skip shadow, continue with
 * local derivation". This keeps consumer code single-path: the route and
 * service do not branch on backend mode — they just fire the client and
 * the stats collector folds the no-op frames into the `fallback_seconds`
 * accounting.
 */
export class NoopMacSignerClient implements MacSignerClient {
  async registerSession(): Promise<RegisterSessionResult> {
    return { ok: false, reason: 'circuit_open' };
  }

  async sign(): Promise<SignResult> {
    return { ok: false, reason: 'circuit_open' };
  }

  async verify(): Promise<VerifyResult> {
    return { ok: false, reason: 'circuit_open' };
  }
}
