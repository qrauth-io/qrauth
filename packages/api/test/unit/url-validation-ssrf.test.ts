import { describe, it, expect } from 'vitest';
import { isSafeWebhookUrl } from '../../src/lib/url-validation.js';

/**
 * Pentest INJ-001: the webhook SSRF validator must reject private/reserved
 * destinations even when expressed as IPv4-mapped IPv6, bracketed IPv6, or
 * link-local/unique-local IPv6 — the bypasses that defeated the previous
 * `isIP()`-gated implementation.
 */
describe('isSafeWebhookUrl — SSRF defenses', () => {
  it('rejects IPv4-mapped IPv6 metadata address (dotted)', () => {
    expect(isSafeWebhookUrl('http://[::ffff:169.254.169.254]/latest/meta-data/').safe).toBe(false);
  });

  it('rejects IPv4-mapped IPv6 loopback (hex form)', () => {
    // URL parser normalizes ::ffff:127.0.0.1 to ::ffff:7f00:1
    expect(isSafeWebhookUrl('http://[::ffff:7f00:1]/').safe).toBe(false);
  });

  it('rejects IPv4-mapped IPv6 RFC-1918', () => {
    expect(isSafeWebhookUrl('http://[::ffff:192.168.1.1]/').safe).toBe(false);
  });

  it('rejects IPv6 link-local (fe80::/10)', () => {
    expect(isSafeWebhookUrl('http://[fe80::1]/').safe).toBe(false);
  });

  it('rejects IPv6 unique-local (fc00::/7)', () => {
    expect(isSafeWebhookUrl('http://[fd00::1]/').safe).toBe(false);
  });

  it('rejects IPv6 loopback ::1', () => {
    expect(isSafeWebhookUrl('http://[::1]/').safe).toBe(false);
  });

  it('rejects bare metadata IPv4', () => {
    expect(isSafeWebhookUrl('http://169.254.169.254/').safe).toBe(false);
  });

  it('rejects RFC-1918 / loopback / CGNAT IPv4', () => {
    for (const u of ['http://10.0.0.5/', 'http://172.16.0.1/', 'http://192.168.0.1/', 'http://127.0.0.1/', 'http://100.64.0.1/']) {
      expect(isSafeWebhookUrl(u).safe, u).toBe(false);
    }
  });

  it('rejects loopback hostnames and non-http(s) schemes', () => {
    expect(isSafeWebhookUrl('http://localhost/').safe).toBe(false);
    expect(isSafeWebhookUrl('http://x.localhost/').safe).toBe(false);
    expect(isSafeWebhookUrl('file:///etc/passwd').safe).toBe(false);
    expect(isSafeWebhookUrl('gopher://10.0.0.1/').safe).toBe(false);
  });

  it('allows legitimate public https endpoints', () => {
    expect(isSafeWebhookUrl('https://hooks.example.com/qrauth').safe).toBe(true);
    expect(isSafeWebhookUrl('http://93.184.216.34/hook').safe).toBe(true);
  });
});

/**
 * Pentest INJ-001 (regression guard): alternate IPv4 encodings. The WHATWG URL
 * parser canonicalizes decimal/octal/hex integer hosts and strips a trailing
 * dot, so these all reach `isIP() === 4` and the IPv4 range checks — they are
 * NOT validator bypasses. These tests pin that behavior: if a future refactor
 * swaps the WHATWG parser for a looser one, the bypass would resurface here.
 */
describe('isSafeWebhookUrl — alternate IPv4 encodings still rejected', () => {
  it('rejects decimal-integer loopback (2130706433 -> 127.0.0.1)', () => {
    expect(isSafeWebhookUrl('http://2130706433/').safe).toBe(false);
  });

  it('rejects octal-encoded loopback (0177.0.0.1 -> 127.0.0.1)', () => {
    expect(isSafeWebhookUrl('http://0177.0.0.1/').safe).toBe(false);
  });

  it('rejects hex-encoded loopback and metadata (0x7f000001, 0xa9fea9fe)', () => {
    expect(isSafeWebhookUrl('http://0x7f000001/').safe).toBe(false);
    expect(isSafeWebhookUrl('http://0xa9fea9fe/').safe).toBe(false);
  });

  it('rejects the unspecified address 0.0.0.0', () => {
    expect(isSafeWebhookUrl('http://0.0.0.0/').safe).toBe(false);
  });

  it('rejects a trailing-dot metadata host (169.254.169.254.)', () => {
    expect(isSafeWebhookUrl('http://169.254.169.254./').safe).toBe(false);
  });

  it('parses the real host out of userinfo, rejecting an internal host-part', () => {
    // `user@host` — the authority host is what gets connected to.
    expect(isSafeWebhookUrl('http://expected.com@169.254.169.254/').safe).toBe(false);
    // ...and a public real host is allowed even with an internal-looking userinfo.
    expect(isSafeWebhookUrl('http://169.254.169.254@expected.com/').safe).toBe(true);
  });
});
