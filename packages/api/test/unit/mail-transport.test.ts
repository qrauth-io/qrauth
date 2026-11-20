/**
 * Unit tests for mail transport selection (lib/mail-transport.ts). In test
 * mode (NODE_ENV=test, or ENABLE_TEST_HOOKS=1 outside production) mail goes
 * to a local SMTP host (the E2E sink) or is captured; development and
 * production send through SMTP_HOST as configured.
 */
import { describe, it, expect, vi } from 'vitest';

import {
  createMailTransport,
  isLocalSmtpHost,
  isTestMode,
  selectMailTransport,
  type MailTransportEnv,
} from '../../src/lib/mail-transport.js';

const REMOTE = 'smtp.example.invalid';
const unitTest = { NODE_ENV: 'test', ENABLE_TEST_HOOKS: false } as const;
const e2eDev = { NODE_ENV: 'development', ENABLE_TEST_HOOKS: true } as const;
const development = { NODE_ENV: 'development', ENABLE_TEST_HOOKS: false } as const;
const production = { NODE_ENV: 'production', ENABLE_TEST_HOOKS: false } as const;

const message = { from: 'a@example.com', to: 'b@example.com', subject: 'Hello', text: 'Body' };

/** Name of the nodemailer transport behind a transporter (SMTP or JSONTransport). */
const transportName = (env: MailTransportEnv): string =>
  (createMailTransport(env, () => {}) as unknown as { transporter: { name: string } }).transporter.name;

describe('isLocalSmtpHost', () => {
  it('accepts 127.0.0.1, ::1 and localhost, ignoring case and surrounding space', () => {
    for (const host of ['127.0.0.1', '::1', '[::1]', 'localhost', 'LOCALHOST', ' 127.0.0.1 ']) {
      expect(isLocalSmtpHost(host), host).toBe(true);
    }
  });

  it('rejects any other host', () => {
    for (const host of ['smtp.example.com', 'localhost.example.com', '127.0.0.2', '10.0.0.1', '0.0.0.0', 'mail.localhost', '']) {
      expect(isLocalSmtpHost(host), host).toBe(false);
    }
  });
});

describe('isTestMode', () => {
  it('is true under NODE_ENV=test and with ENABLE_TEST_HOOKS=1 in development', () => {
    expect(isTestMode(unitTest)).toBe(true);
    expect(isTestMode(e2eDev)).toBe(true);
  });

  it('is false in plain development and in production, even with ENABLE_TEST_HOOKS=1', () => {
    expect(isTestMode(development)).toBe(false);
    expect(isTestMode({ NODE_ENV: 'production', ENABLE_TEST_HOOKS: true })).toBe(false);
  });
});

describe('selectMailTransport', () => {
  it('captures mail in test mode when SMTP_HOST is remote or unset', () => {
    expect(selectMailTransport({ ...unitTest, SMTP_HOST: REMOTE })).toBe('capture');
    expect(selectMailTransport({ ...e2eDev, SMTP_HOST: REMOTE })).toBe('capture');
    expect(selectMailTransport({ ...unitTest })).toBe('capture');
    expect(selectMailTransport({ ...unitTest, SMTP_HOST: '' })).toBe('capture');
  });

  it('sends to a local SMTP host in test mode (the E2E mail sink)', () => {
    expect(selectMailTransport({ ...unitTest, SMTP_HOST: '127.0.0.1' })).toBe('smtp');
    expect(selectMailTransport({ ...e2eDev, SMTP_HOST: 'localhost' })).toBe('smtp');
  });

  it('sends through any configured host in production', () => {
    expect(selectMailTransport({ ...production, SMTP_HOST: REMOTE })).toBe('smtp');
    expect(selectMailTransport({ NODE_ENV: 'production', ENABLE_TEST_HOOKS: true, SMTP_HOST: REMOTE })).toBe('smtp');
  });

  it('leaves development as before: configured host sends, no host logs', () => {
    expect(selectMailTransport({ ...development, SMTP_HOST: REMOTE })).toBe('smtp');
    expect(selectMailTransport({ ...development })).toBe('log');
  });

  it('refuses to start production without SMTP_HOST', () => {
    expect(() => selectMailTransport({ ...production })).toThrow(/SMTP_HOST is not set in production/);
  });
});

describe('createMailTransport', () => {
  it('test mode + remote host: nothing is sent and "mail captured" is logged at debug', async () => {
    const debug = vi.fn();
    const transporter = createMailTransport({ ...unitTest, SMTP_HOST: REMOTE, SMTP_PORT: '587' }, debug);

    // An SMTP transport would fail to resolve the .invalid host; capture resolves locally.
    const info = await transporter.sendMail(message);

    expect((transporter as unknown as { transporter: { name: string } }).transporter.name).toBe('JSONTransport');
    expect(JSON.parse(info.message as unknown as string).subject).toBe('Hello');
    expect(debug).toHaveBeenCalledTimes(1);
    expect(debug.mock.calls[0][0]).toMatch(/^\[email\] mail captured/);
    expect(debug.mock.calls[0][0]).toContain('Hello');
  });

  it('test mode + local host: SMTP to that host and port', () => {
    const transporter = createMailTransport({ ...unitTest, SMTP_HOST: '127.0.0.1', SMTP_PORT: '2525' }, () => {});
    const options = transporter.options as { host?: string; port?: number };
    expect(transportName({ ...unitTest, SMTP_HOST: '127.0.0.1' })).toBe('SMTP');
    expect(options.host).toBe('127.0.0.1');
    expect(options.port).toBe(2525);
  });

  it('production + remote host: SMTP to that host', () => {
    const transporter = createMailTransport({ ...production, SMTP_HOST: REMOTE, SMTP_PORT: '465' }, () => {});
    const options = transporter.options as { host?: string; port?: number; secure?: boolean };
    expect(transportName({ ...production, SMTP_HOST: REMOTE })).toBe('SMTP');
    expect(options.host).toBe(REMOTE);
    expect(options.port).toBe(465);
    expect(options.secure).toBe(true);
  });

  it('development is unaffected: remote host uses SMTP, no host logs without capture messages', async () => {
    expect(transportName({ ...development, SMTP_HOST: REMOTE })).toBe('SMTP');

    const debug = vi.fn();
    const transporter = createMailTransport({ ...development }, debug);
    await transporter.sendMail(message);
    expect((transporter as unknown as { transporter: { name: string } }).transporter.name).toBe('JSONTransport');
    expect(debug).not.toHaveBeenCalled();
  });
});
