import { randomBytes } from 'node:crypto';
import { esc } from './utils.js';

/**
 * "Report this code" pages, linked from every verify page state. A plain HTML
 * form that posts back to /v/:token/report; the only script is the optional
 * Cloudflare Turnstile widget. Callers set `request.cspOverride` from
 * reportPageCsp() with the returned nonce.
 */

export interface ReportPage {
  html: string;
  nonce: string;
}

const TURNSTILE_ORIGIN = 'https://challenges.cloudflare.com';

const REASON_LABELS: Array<[string, string]> = [
  ['phishing', 'Phishing: it asks for passwords, payment or personal details'],
  ['malware', 'Malware: it downloads or installs something harmful'],
  ['impersonation', 'Impersonation: it pretends to be another organization'],
  ['spam', 'Spam'],
  ['other', 'Something else'],
];

export function reportPageCsp(nonce: string, withTurnstile: boolean): string {
  const turnstile = withTurnstile ? ` ${TURNSTILE_ORIGIN}` : '';
  return [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}'${turnstile}`,
    `style-src 'self' 'nonce-${nonce}'`,
    ...(withTurnstile ? [`frame-src ${TURNSTILE_ORIGIN}`, `connect-src 'self' ${TURNSTILE_ORIGIN}`] : ["connect-src 'self'"]),
    "img-src 'self' data:",
    "object-src 'none'",
    "frame-ancestors 'none'",
    "base-uri 'self'",
    "form-action 'self'",
  ].join('; ');
}

function shell(nonce: string, title: string, body: string, head = ''): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="robots" content="noindex">
  <title>${esc(title)} | QRAuth</title>
  <style nonce="${nonce}">
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif; background: #FAFAF9; color: #262626; display: flex; justify-content: center; padding: 24px 16px; }
    .card { width: 100%; max-width: 440px; background: #fff; border: 1px solid rgba(15,15,15,0.08); border-radius: 14px; padding: 24px; }
    h1 { font-size: 20px; margin-bottom: 6px; }
    p { font-size: 14px; color: #525252; line-height: 1.5; margin-bottom: 16px; }
    fieldset { border: none; margin-bottom: 16px; }
    legend, label.field { display: block; font-size: 13px; font-weight: 600; margin-bottom: 8px; }
    .reason { display: flex; gap: 8px; align-items: flex-start; font-size: 14px; margin-bottom: 8px; }
    textarea, input[type=email] { width: 100%; font: inherit; font-size: 14px; padding: 10px 12px; border: 1px solid rgba(15,15,15,0.15); border-radius: 10px; margin-bottom: 16px; }
    textarea { min-height: 96px; resize: vertical; }
    button { width: 100%; padding: 12px; border: none; border-radius: 10px; background: #334155; color: #fff; font-size: 15px; font-weight: 600; cursor: pointer; }
    .error { background: rgba(244,63,94,0.08); border: 1px solid rgba(244,63,94,0.22); color: #B91C1C; border-radius: 10px; padding: 10px 12px; font-size: 13px; margin-bottom: 16px; }
    .turnstile { margin-bottom: 16px; }
    .back { display: inline-block; margin-top: 16px; font-size: 13px; color: #4F46E5; text-decoration: none; }
    .hint { font-size: 12px; color: #737373; margin-top: -10px; margin-bottom: 16px; }
  </style>
  ${head}
</head>
<body>
  <div class="card">${body}</div>
</body>
</html>`;
}

export interface ReportFormOptions {
  token: string;
  /** Turnstile site key, or null when the check is off. */
  siteKey: string | null;
  error?: string;
  values?: { reason?: string; comment?: string; reporterEmail?: string };
}

export function renderReportForm(opts: ReportFormOptions): ReportPage {
  const nonce = randomBytes(16).toString('base64');
  const token = encodeURIComponent(opts.token);
  const v = opts.values ?? {};
  const reasons = REASON_LABELS.map(
    ([value, label]) => `
      <label class="reason"><input type="radio" name="reason" value="${value}" required${v.reason === value ? ' checked' : ''}> <span>${esc(label)}</span></label>`,
  ).join('');
  const turnstileHead = opts.siteKey
    ? `<script nonce="${nonce}" src="${TURNSTILE_ORIGIN}/turnstile/v0/api.js" async defer></script>`
    : '';
  const body = `
    <h1>Report this code</h1>
    <p>Tell QRAuth what is wrong with QR code <strong>${esc(opts.token)}</strong>. We review every report.</p>
    ${opts.error ? `<div class="error">${esc(opts.error)}</div>` : ''}
    <form method="post" action="/v/${token}/report">
      <fieldset>
        <legend>What is the problem?</legend>
        ${reasons}
      </fieldset>
      <label class="field" for="comment">Details (optional)</label>
      <textarea id="comment" name="comment" maxlength="500">${esc(v.comment ?? '')}</textarea>
      <label class="field" for="reporterEmail">Your email (optional)</label>
      <input id="reporterEmail" type="email" name="reporterEmail" maxlength="254" value="${esc(v.reporterEmail ?? '')}">
      <div class="hint">Only used if we need to ask you about this report.</div>
      ${opts.siteKey ? `<div class="turnstile cf-turnstile" data-sitekey="${esc(opts.siteKey)}"></div>` : ''}
      <button type="submit">Send report</button>
    </form>
    <a class="back" href="/v/${token}">Back to the code</a>`;
  return { html: shell(nonce, 'Report this code', body, turnstileHead), nonce };
}

export function renderReportReceived(rawToken: string): ReportPage {
  const nonce = randomBytes(16).toString('base64');
  const body = `
    <h1>Thank you</h1>
    <p>Your report has been received. If this code is harmful, it will be disabled.</p>
    <a class="back" href="/v/${encodeURIComponent(rawToken)}">Back to the code</a>`;
  return { html: shell(nonce, 'Report received', body), nonce };
}

/** A refusal (rate limit, failed security check) shown as a page. */
export function renderReportProblem(rawToken: string, message: string): ReportPage {
  const nonce = randomBytes(16).toString('base64');
  const body = `
    <h1>Report not sent</h1>
    <div class="error">${esc(message)}</div>
    <a class="back" href="/v/${encodeURIComponent(rawToken)}/report">Try again</a>`;
  return { html: shell(nonce, 'Report not sent', body), nonce };
}
