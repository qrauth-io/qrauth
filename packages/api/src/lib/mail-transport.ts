import { createTransport, type Transporter } from 'nodemailer';

/**
 * Mail transport selection for lib/email.ts.
 *
 * Test mode is NODE_ENV=test (vitest, CI E2E) or ENABLE_TEST_HOOKS=1 outside
 * production. The E2E suite needs the /_test/* hooks, so ENABLE_TEST_HOOKS=1
 * marks an E2E API even when its .env says NODE_ENV=development. Production
 * is excluded, as it is for the hooks themselves (config.server
 * .testHooksEnabled), so a stray flag cannot change production mail.
 *
 * In test mode:
 * - SMTP_HOST on this machine (127.0.0.1, ::1, localhost): mail goes to it
 *   over SMTP. This is the E2E mail sink (packages/e2e/support/smtp-sink.mjs,
 *   127.0.0.1:2525), which tests/mail-smoke.spec.ts reads back.
 * - SMTP_HOST unset or any other host: mail is captured. Nothing leaves the
 *   machine; each message is logged at debug level as "mail captured".
 *
 * Outside test mode nothing changes: SMTP_HOST set sends through it;
 * unset logs mail in development and stops production at startup.
 */

const LOCAL_SMTP_HOSTS = new Set(['127.0.0.1', '::1', '[::1]', 'localhost']);
const DEFAULT_SMTP_PORT = '587';
const IMPLICIT_TLS_PORT = '465';

export interface MailTransportEnv {
  NODE_ENV: 'development' | 'test' | 'production';
  ENABLE_TEST_HOOKS: boolean;
  SMTP_HOST?: string;
  SMTP_PORT?: string;
  SMTP_USER?: string;
  SMTP_PASS?: string;
}

/** smtp: send through SMTP_HOST. capture: test mode, nothing sent. log: development without SMTP_HOST. */
export type MailTransportKind = 'smtp' | 'capture' | 'log';

export type DebugLog = (message: string) => void;

/** True for an SMTP host on this machine: 127.0.0.1, ::1 or localhost. */
export function isLocalSmtpHost(host: string): boolean {
  return LOCAL_SMTP_HOSTS.has(host.trim().toLowerCase());
}

/** NODE_ENV=test, or ENABLE_TEST_HOOKS=1 outside production. */
export function isTestMode(env: Pick<MailTransportEnv, 'NODE_ENV' | 'ENABLE_TEST_HOOKS'>): boolean {
  return env.NODE_ENV === 'test' || (env.NODE_ENV !== 'production' && env.ENABLE_TEST_HOOKS);
}

/** Which transport the API uses for this environment. Throws for production without SMTP_HOST. */
export function selectMailTransport(env: MailTransportEnv): MailTransportKind {
  const host = env.SMTP_HOST?.trim() ?? '';
  if (isTestMode(env)) return isLocalSmtpHost(host) ? 'smtp' : 'capture';
  if (host) return 'smtp';
  // Production must not drop mail silently (password resets, invites, reports).
  if (env.NODE_ENV === 'production') {
    throw new Error(
      '[email] SMTP_HOST is not set in production. Refusing to start with a no-op mail transport. ' +
        'Configure SMTP_HOST/SMTP_PORT/SMTP_USER/SMTP_PASS.',
    );
  }
  return 'log';
}

function smtpTransport(env: MailTransportEnv): Transporter {
  const port = env.SMTP_PORT || DEFAULT_SMTP_PORT;
  return createTransport({
    host: env.SMTP_HOST?.trim(),
    port: parseInt(port, 10),
    secure: port === IMPLICIT_TLS_PORT,
    auth: { user: env.SMTP_USER, pass: env.SMTP_PASS },
  });
}

/** JSON transport (nothing sent) that logs each message at debug level. */
function captureTransport(debug: DebugLog): Transporter {
  const transporter = createTransport({ jsonTransport: true });
  transporter.use('compile', (mail, done) => {
    const { to, subject } = mail.data;
    debug(`[email] mail captured (test mode, not sent): to=${JSON.stringify(to)} subject=${JSON.stringify(subject)}`);
    done();
  });
  return transporter;
}

/** The transporter lib/email.ts sends with. */
export function createMailTransport(env: MailTransportEnv, debug: DebugLog = console.debug): Transporter {
  const kind = selectMailTransport(env);
  if (kind === 'smtp') return smtpTransport(env);
  if (kind === 'capture') return captureTransport(debug);
  console.warn(
    '[email] SMTP_HOST not set — using jsonTransport (emails will be logged, not sent). ' +
      'Set SMTP_HOST to enable real delivery.',
  );
  return createTransport({ jsonTransport: true });
}
