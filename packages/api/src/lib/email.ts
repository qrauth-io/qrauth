import { createTransport, type Transporter } from 'nodemailer';
import { config } from './config.js';

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

let transporter: Transporter;

if (!process.env.SMTP_HOST) {
  // In production we refuse to start silently dropping mail — that was
  // previously a trap where password resets, invites, and daily reports
  // all vanished without any error. Fail loud.
  if (config.server.isProd) {
    throw new Error(
      '[email] SMTP_HOST is not set in production. Refusing to start with a no-op mail transport. ' +
        'Configure SMTP_HOST/SMTP_PORT/SMTP_USER/SMTP_PASS, or explicitly set EMAIL_DISABLED=1 to opt out.',
    );
  }
  // Dev/test: keep the console-logging fallback so local work doesn't need SMTP.
  console.warn(
    '[email] SMTP_HOST not set — using jsonTransport (emails will be logged, not sent). ' +
      'Set SMTP_HOST to enable real delivery.',
  );
  transporter = createTransport({
    jsonTransport: true,
  });
} else {
  transporter = createTransport({
    host: process.env.SMTP_HOST,
    port: parseInt(process.env.SMTP_PORT || '587', 10),
    secure: process.env.SMTP_PORT === '465',
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS,
    },
  });
}

const FROM_ADDRESS = process.env.EMAIL_FROM || 'QRAuth <noreply@qrauth.io>';

// ---------------------------------------------------------------------------
// Shared layout helpers (private)
// ---------------------------------------------------------------------------

const DASHBOARD_URL = process.env.WEBAUTHN_ORIGIN || 'http://localhost:8081';

/** Escape user-controlled strings before injecting into HTML email templates. */
function esc(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function emailLayout(content: string): string {
  return `
    <div style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;max-width:480px;margin:0 auto;padding:40px 20px;">
      ${content}
      <hr style="border:none;border-top:1px solid #f0f0f0;margin:24px 0;">
      <p style="color:#c4cdd5;font-size:11px;">Sent by QRAuth — Identity Verification Platform</p>
    </div>`;
}

function ctaButton(href: string, label: string, bg = '#00A76F'): string {
  return `<a href="${href}" style="display:inline-block;padding:12px 32px;background:${bg};color:white;text-decoration:none;border-radius:8px;font-weight:600;margin:24px 0;">${label}</a>`;
}

function heading(text: string): string {
  return `<h2 style="color:#1B2A4A;margin-bottom:16px;">${text}</h2>`;
}

function paragraph(text: string): string {
  return `<p style="color:#637381;font-size:14px;line-height:1.6;">${text}</p>`;
}

function smallText(text: string): string {
  return `<p style="color:#919eab;font-size:12px;line-height:1.5;">${text}</p>`;
}

function alertBanner(text: string, color: string, bg: string): string {
  return `<div style="padding:12px 16px;background:${bg};border-left:4px solid ${color};border-radius:4px;margin-bottom:24px;"><strong style="color:${color};">${text}</strong></div>`;
}

function infoRow(label: string, value: string): string {
  return `<tr><td style="color:#919eab;padding:4px 0;">${label}</td><td style="font-weight:600;color:#212b36;">${value}</td></tr>`;
}

function infoTable(rows: string): string {
  return `<table style="width:100%;font-size:14px;margin:16px 0;">${rows}</table>`;
}

// ---------------------------------------------------------------------------
// Email templates
// ---------------------------------------------------------------------------

export async function sendPasswordResetEmail(to: string, resetToken: string): Promise<void> {
  const resetUrl = `${DASHBOARD_URL}/auth/jwt/reset-password?token=${resetToken}`;

  const info = await transporter.sendMail({
    from: FROM_ADDRESS,
    to,
    subject: 'Reset your QRAuth password',
    html: emailLayout(`
      ${heading('Reset Your Password')}
      ${paragraph('We received a request to reset your QRAuth account password. Click the button below to set a new password.')}
      ${ctaButton(resetUrl, 'Reset Password')}
      ${smallText("This link expires in 1 hour. If you didn't request this, you can safely ignore this email.")}
    `),
    text: `Reset your QRAuth password: ${resetUrl}\n\nThis link expires in 1 hour. If you didn't request this, ignore this email.`,
  });

  if (config.server.isDev) {
    const parsed = JSON.parse(info.message);
    console.log(`[email] Password reset email for ${to}:`);
    console.log(`  Subject: ${parsed.subject}`);
    console.log(`  Reset URL: ${resetUrl}`);
  }
}

export async function sendInvitationEmail(
  to: string,
  inviterName: string,
  orgName: string,
  role: string,
  inviteToken: string,
): Promise<void> {
  const acceptUrl = `${DASHBOARD_URL}/auth/jwt/sign-up?invite=${inviteToken}`;

  const info = await transporter.sendMail({
    from: FROM_ADDRESS,
    to,
    subject: `${inviterName} invited you to ${orgName} on QRAuth`,
    html: emailLayout(`
      ${heading("You've Been Invited")}
      ${paragraph(`<strong>${esc(inviterName)}</strong> invited you to join <strong>${esc(orgName)}</strong> on QRAuth as a <strong>${role}</strong>.`)}
      ${ctaButton(acceptUrl, 'Accept Invitation')}
      ${smallText('This invitation expires in 72 hours.')}
    `),
    text: `${inviterName} invited you to join ${orgName} on QRAuth as a ${role}.\n\nAccept: ${acceptUrl}\n\nThis invitation expires in 72 hours.`,
  });

  if (config.server.isDev) {
    const parsed = JSON.parse(info.message);
    console.log(`[email] Invitation email for ${to}:`);
    console.log(`  Subject: ${parsed.subject}`);
    console.log(`  Accept URL: ${acceptUrl}`);
  }
}

export async function sendFraudAlertEmail(
  to: string,
  orgName: string,
  incident: { type: string; severity: string; qrCodeToken: string },
): Promise<void> {
  const severityColor = incident.severity === 'CRITICAL' ? '#D32F2F'
    : incident.severity === 'HIGH' ? '#FF5630'
    : incident.severity === 'MEDIUM' ? '#FFAB00'
    : '#637381';

  const info = await transporter.sendMail({
    from: FROM_ADDRESS,
    to,
    subject: `[${incident.severity}] Fraud alert for ${orgName} — QR code ${incident.qrCodeToken}`,
    html: emailLayout(`
      ${alertBanner(`${incident.severity} — ${incident.type.replace(/_/g, ' ')}`, severityColor, '#FFF3E0')}
      ${paragraph(`A fraud incident has been detected for your organization <strong>${orgName}</strong>.`)}
      ${infoTable(
        infoRow('QR Code', `<span style="font-family:monospace;">${incident.qrCodeToken}</span>`) +
        infoRow('Type', incident.type.replace(/_/g, ' ')) +
        infoRow('Severity', `<span style="color:${severityColor};">${incident.severity}</span>`)
      )}
      ${ctaButton(`${DASHBOARD_URL}/dashboard/fraud`, 'View in Dashboard', '#1B2A4A')}
    `),
    text: `[${incident.severity}] Fraud alert for ${orgName}\n\nQR Code: ${incident.qrCodeToken}\nType: ${incident.type}\nSeverity: ${incident.severity}\n\nView in dashboard: ${DASHBOARD_URL}/dashboard/fraud`,
  });

  if (config.server.isDev) {
    const parsed = JSON.parse(info.message);
    console.log(`[email] Fraud alert email for ${to}:`);
    console.log(`  Subject: ${parsed.subject}`);
  }
}

export async function sendDailyReportEmail(
  to: string,
  title: string,
  sections: Array<{ heading: string; content: string }>,
  severity: string,
): Promise<void> {
  const severityColor = severity === 'critical' ? '#C62828' : severity === 'warning' ? '#E65100' : '#1B5E20';
  const severityBg = severity === 'critical' ? '#FFEBEE' : severity === 'warning' ? '#FFF3E0' : '#E8F5E9';

  const sectionsHtml = sections.map((s) =>
    `<div style="margin-bottom:20px;">
      <h3 style="color:#1B2A4A;font-size:16px;margin:0 0 8px;">${s.heading}</h3>
      <p style="color:#637381;font-size:14px;line-height:1.6;margin:0;white-space:pre-wrap;">${s.content}</p>
    </div>`
  ).join('');

  // Daily report uses a wider layout (600px) and a custom footer; we inline
  // the outer wrapper manually rather than using emailLayout() so that the
  // max-width and footer text ("AI Security Analyst") remain unchanged.
  const info = await transporter.sendMail({
    from: FROM_ADDRESS,
    to,
    subject: `[QRAuth ${severity.toUpperCase()}] ${title}`,
    html: `
      <div style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;max-width:600px;margin:0 auto;padding:40px 20px;">
        ${alertBanner(`${severity.toUpperCase()} — ${title}`, severityColor, severityBg)}
        ${sectionsHtml}
        <hr style="border:none;border-top:1px solid #f0f0f0;margin:24px 0;">
        <p style="color:#c4cdd5;font-size:11px;">Generated by QRAuth AI Security Analyst</p>
      </div>
    `,
  });

  if (config.server.isDev) {
    console.log(`[email] Daily report sent to ${to}: ${title}`);
    console.log(info);
  }
}

// ---------------------------------------------------------------------------
// Email 1: Welcome + Email Verification
// ---------------------------------------------------------------------------

export async function sendWelcomeVerificationEmail(
  to: string,
  userName: string,
  orgName: string,
  verifyToken: string,
): Promise<void> {
  const verifyUrl = `${DASHBOARD_URL}/api/v1/auth/verify-email/${verifyToken}`;

  const info = await transporter.sendMail({
    from: FROM_ADDRESS,
    to,
    subject: `Welcome to QRAuth, ${userName}!`,
    html: emailLayout(`
      ${heading(`Welcome, ${userName}!`)}
      ${paragraph(`You've created <strong>${orgName}</strong> on QRAuth. Please verify your email address to activate your account.`)}
      ${ctaButton(verifyUrl, 'Verify Email Address')}
      ${paragraph('Once verified, you can get started right away:')}
      <ul style="color:#637381;font-size:14px;line-height:1.8;padding-left:20px;margin:0 0 16px;">
        <li>Create your first signed QR code</li>
        <li>Invite your team members</li>
        <li>Verify your domain for a trusted badge</li>
      </ul>
      ${smallText("If you didn't create this account, you can safely ignore this email.")}
    `),
    text: `Welcome to QRAuth, ${userName}!\n\nYou've created ${orgName}. Verify your email: ${verifyUrl}\n\nGet started:\n- Create your first signed QR code\n- Invite your team members\n- Verify your domain for a trusted badge\n\nIf you didn't create this account, ignore this email.`,
  });

  if (config.server.isDev) {
    const parsed = JSON.parse(info.message);
    console.log(`[email] Welcome verification email for ${to}:`);
    console.log(`  Subject: ${parsed.subject}`);
    console.log(`  Verify URL: ${verifyUrl}`);
  }
}

// ---------------------------------------------------------------------------
// Email 2: Password Changed
// ---------------------------------------------------------------------------

export async function sendPasswordChangedEmail(
  to: string,
  userName: string,
): Promise<void> {
  const resetUrl = `${DASHBOARD_URL}/auth/jwt/forgot-password`;
  const timestamp = new Date().toUTCString();

  const info = await transporter.sendMail({
    from: FROM_ADDRESS,
    to,
    subject: 'Your QRAuth password has been changed',
    html: emailLayout(`
      ${alertBanner('Security notice: your password has been changed', '#1B2A4A', '#EEF2FF')}
      ${paragraph(`Hi <strong>${esc(userName)}</strong>,`)}
      ${paragraph(`Your QRAuth account password was successfully changed on <strong>${timestamp}</strong>.`)}
      ${paragraph("If you didn't make this change, please reset your password immediately or contact support.")}
      ${ctaButton(resetUrl, 'Reset Password Now', '#D32F2F')}
      ${smallText('If this was you, no further action is needed.')}
    `),
    text: `Hi ${userName},\n\nYour QRAuth password was changed on ${timestamp}.\n\nIf you didn't make this change, reset your password immediately: ${resetUrl}\n\nIf this was you, no action is needed.`,
  });

  if (config.server.isDev) {
    const parsed = JSON.parse(info.message);
    console.log(`[email] Password changed email for ${to}:`);
    console.log(`  Subject: ${parsed.subject}`);
  }
}

// ---------------------------------------------------------------------------
// Email 3: Suspicious Login
// ---------------------------------------------------------------------------

export async function sendSuspiciousLoginEmail(
  to: string,
  userName: string,
  details: {
    country?: string;
    city?: string;
    device?: string;
    browser?: string;
    os?: string;
    time: string;
  },
): Promise<void> {
  const changePasswordUrl = `${DASHBOARD_URL}/auth/jwt/forgot-password`;
  const location = [details.city, details.country].filter(Boolean).join(', ') || 'Unknown location';

  const info = await transporter.sendMail({
    from: FROM_ADDRESS,
    to,
    subject: 'New sign-in to your QRAuth account',
    html: emailLayout(`
      ${alertBanner('A new sign-in was detected on your account', '#FF8C00', '#FFF8EC')}
      ${paragraph(`Hi <strong>${esc(userName)}</strong>, we noticed a new sign-in to your QRAuth account.`)}
      ${infoTable(
        infoRow('Location', location) +
        infoRow('Device', details.device || 'Unknown') +
        infoRow('Browser', details.browser || 'Unknown') +
        (details.os ? infoRow('OS', details.os) : '') +
        infoRow('Time', details.time)
      )}
      ${paragraph('If this was you, no action is needed. If you did not sign in, change your password immediately.')}
      ${ctaButton(changePasswordUrl, 'Change Password', '#D32F2F')}
    `),
    text: `Hi ${userName},\n\nA new sign-in was detected on your QRAuth account.\n\nLocation: ${location}\nDevice: ${details.device || 'Unknown'}\nBrowser: ${details.browser || 'Unknown'}\nTime: ${details.time}\n\nIf this was you, no action needed. If not, change your password: ${changePasswordUrl}`,
  });

  if (config.server.isDev) {
    const parsed = JSON.parse(info.message);
    console.log(`[email] Suspicious login email for ${to}:`);
    console.log(`  Subject: ${parsed.subject}`);
    console.log(`  Location: ${location}`);
  }
}

// ---------------------------------------------------------------------------
// Email 4: KYC Approved
// ---------------------------------------------------------------------------

export async function sendKycApprovedEmail(
  to: string,
  orgName: string,
): Promise<void> {
  const info = await transporter.sendMail({
    from: FROM_ADDRESS,
    to,
    subject: `${orgName} has been verified on QRAuth`,
    html: emailLayout(`
      ${alertBanner('Organization identity verified', '#00A76F', '#E6F9F3')}
      ${heading('Verification Approved')}
      ${paragraph(`<strong>${orgName}</strong> has been successfully verified on QRAuth. Your organization identity is now confirmed.`)}
      ${paragraph('You have unlocked the following benefits:')}
      <ul style="color:#637381;font-size:14px;line-height:1.8;padding-left:20px;margin:0 0 16px;">
        <li>Higher trust score on all QR code scans</li>
        <li>Verified badge displayed on your QR verification pages</li>
        <li>Custom domain support for branded verification</li>
      </ul>
      ${ctaButton(`${DASHBOARD_URL}/dashboard`, 'Go to Dashboard')}
    `),
    text: `${orgName} has been verified on QRAuth.\n\nYou have unlocked:\n- Higher trust score\n- Verified badge on QR verification pages\n- Custom domain support\n\nGo to dashboard: ${DASHBOARD_URL}/dashboard`,
  });

  if (config.server.isDev) {
    const parsed = JSON.parse(info.message);
    console.log(`[email] KYC approved email for ${to}:`);
    console.log(`  Subject: ${parsed.subject}`);
  }
}

// ---------------------------------------------------------------------------
// Email 5: KYC Rejected
// ---------------------------------------------------------------------------

export async function sendKycRejectedEmail(
  to: string,
  orgName: string,
  reason: string,
): Promise<void> {
  const settingsUrl = `${DASHBOARD_URL}/dashboard/settings`;

  const info = await transporter.sendMail({
    from: FROM_ADDRESS,
    to,
    subject: `KYC review update for ${orgName}`,
    html: emailLayout(`
      ${alertBanner('Organization verification was not approved', '#FF5630', '#FFF3F0')}
      ${heading('Verification Update')}
      ${paragraph(`We were unable to verify <strong>${esc(orgName)}</strong> at this time.`)}
      <div style="padding:12px 16px;background:#F9FAFB;border:1px solid #f0f0f0;border-radius:4px;margin:16px 0;">
        <p style="color:#637381;font-size:14px;margin:0;"><strong>Reason:</strong> ${esc(reason)}</p>
      </div>
      ${paragraph('You can resubmit with updated information. Please review the reason above and ensure all submitted documents are clear and valid.')}
      ${ctaButton(settingsUrl, 'Resubmit Verification', '#1B2A4A')}
    `),
    text: `KYC review update for ${orgName}\n\nWe were unable to verify your organization at this time.\n\nReason: ${reason}\n\nYou can resubmit with updated information: ${settingsUrl}`,
  });

  if (config.server.isDev) {
    const parsed = JSON.parse(info.message);
    console.log(`[email] KYC rejected email for ${to}:`);
    console.log(`  Subject: ${parsed.subject}`);
  }
}

// ---------------------------------------------------------------------------
// Email 6: Member Removed
// ---------------------------------------------------------------------------

export async function sendMemberRemovedEmail(
  to: string,
  userName: string,
  orgName: string,
): Promise<void> {
  const info = await transporter.sendMail({
    from: FROM_ADDRESS,
    to,
    subject: `You've been removed from ${orgName}`,
    html: emailLayout(`
      ${heading(`Removed from ${orgName}`)}
      ${paragraph(`Hi <strong>${esc(userName)}</strong>, you have been removed from <strong>${orgName}</strong> on QRAuth.`)}
      ${paragraph('You no longer have access to this organization\'s QR codes, analytics, or settings.')}
      ${smallText('If you believe this was a mistake, contact your organization administrator.')}
    `),
    text: `Hi ${userName},\n\nYou have been removed from ${orgName} on QRAuth. You no longer have access to this organization.\n\nIf you believe this was a mistake, contact your organization administrator.`,
  });

  if (config.server.isDev) {
    const parsed = JSON.parse(info.message);
    console.log(`[email] Member removed email for ${to}:`);
    console.log(`  Subject: ${parsed.subject}`);
  }
}

// ---------------------------------------------------------------------------
// Email 7: Role Changed
// ---------------------------------------------------------------------------

export async function sendRoleChangedEmail(
  to: string,
  userName: string,
  orgName: string,
  newRole: string,
): Promise<void> {
  const roleDescriptions: Record<string, string> = {
    OWNER: 'Full control over the organization, billing, and all settings.',
    ADMIN: 'Can manage members, QR codes, and organization settings.',
    MANAGER: 'Can create and manage QR codes and view analytics.',
    MEMBER: 'Can create QR codes and view their own analytics.',
    VIEWER: 'Read-only access to QR codes and analytics.',
  };
  const roleDescription = roleDescriptions[newRole] ?? 'Your permissions have been updated.';

  const info = await transporter.sendMail({
    from: FROM_ADDRESS,
    to,
    subject: `Your role in ${orgName} has been updated`,
    html: emailLayout(`
      ${heading('Your Role Has Changed')}
      ${paragraph(`Hi <strong>${esc(userName)}</strong>, your role in <strong>${orgName}</strong> has been updated.`)}
      ${infoTable(
        infoRow('Organization', orgName) +
        infoRow('New Role', `<strong>${newRole}</strong>`)
      )}
      ${paragraph(roleDescription)}
      ${ctaButton(`${DASHBOARD_URL}/dashboard`, 'Go to Dashboard')}
    `),
    text: `Hi ${userName},\n\nYour role in ${orgName} has been changed to ${newRole}.\n\n${roleDescription}\n\nGo to dashboard: ${DASHBOARD_URL}/dashboard`,
  });

  if (config.server.isDev) {
    const parsed = JSON.parse(info.message);
    console.log(`[email] Role changed email for ${to}:`);
    console.log(`  Subject: ${parsed.subject}`);
    console.log(`  New role: ${newRole}`);
  }
}

// ---------------------------------------------------------------------------
// Email 8: API Key Created
// ---------------------------------------------------------------------------

export async function sendApiKeyCreatedEmail(
  to: string,
  orgName: string,
  createdBy: string,
  keyPrefix: string,
  keyLabel: string | null,
): Promise<void> {
  const apiKeysUrl = `${DASHBOARD_URL}/dashboard/api-keys`;

  const info = await transporter.sendMail({
    from: FROM_ADDRESS,
    to,
    subject: `New API key created for ${orgName}`,
    html: emailLayout(`
      ${alertBanner('A new API key has been created for your organization', '#1B2A4A', '#EEF2FF')}
      ${paragraph(`An API key was created for <strong>${orgName}</strong>.`)}
      ${infoTable(
        infoRow('Created by', createdBy) +
        infoRow('Key prefix', `<span style="font-family:monospace;">${keyPrefix}...</span>`) +
        (keyLabel ? infoRow('Label', keyLabel) : '')
      )}
      ${paragraph('If you did not authorize this key, revoke it immediately to prevent unauthorized API access.')}
      ${ctaButton(apiKeysUrl, 'Manage API Keys', '#D32F2F')}
    `),
    text: `New API key created for ${orgName}\n\nCreated by: ${createdBy}\nKey prefix: ${keyPrefix}...\n${keyLabel ? `Label: ${keyLabel}\n` : ''}\nIf you didn't authorize this, revoke it immediately: ${apiKeysUrl}`,
  });

  if (config.server.isDev) {
    const parsed = JSON.parse(info.message);
    console.log(`[email] API key created email for ${to}:`);
    console.log(`  Subject: ${parsed.subject}`);
    console.log(`  Key prefix: ${keyPrefix}`);
  }
}

// ---------------------------------------------------------------------------
// Email 9: API Key Revoked
// ---------------------------------------------------------------------------

export async function sendApiKeyRevokedEmail(
  to: string,
  orgName: string,
  revokedBy: string,
  keyPrefix: string,
  keyLabel: string | null,
): Promise<void> {
  const info = await transporter.sendMail({
    from: FROM_ADDRESS,
    to,
    subject: `API key revoked for ${orgName}`,
    html: emailLayout(`
      ${heading('API Key Revoked')}
      ${paragraph(`An API key for <strong>${orgName}</strong> has been revoked.`)}
      ${infoTable(
        infoRow('Revoked by', revokedBy) +
        infoRow('Key prefix', `<span style="font-family:monospace;">${keyPrefix}...</span>`) +
        (keyLabel ? infoRow('Label', keyLabel) : '')
      )}
      ${paragraph('Applications using this key will no longer be able to authenticate. If this was unintentional, a new key can be generated from the dashboard.')}
      ${ctaButton(`${DASHBOARD_URL}/dashboard/api-keys`, 'Manage API Keys', '#1B2A4A')}
    `),
    text: `API key revoked for ${orgName}\n\nRevoked by: ${revokedBy}\nKey prefix: ${keyPrefix}...\n${keyLabel ? `Label: ${keyLabel}\n` : ''}\nApplications using this key will no longer be able to authenticate.`,
  });

  if (config.server.isDev) {
    const parsed = JSON.parse(info.message);
    console.log(`[email] API key revoked email for ${to}:`);
    console.log(`  Subject: ${parsed.subject}`);
    console.log(`  Key prefix: ${keyPrefix}`);
  }
}

// ---------------------------------------------------------------------------
// Email 10: Signing Key Rotated
// ---------------------------------------------------------------------------

export async function sendSigningKeyRotatedEmail(
  to: string,
  orgName: string,
  rotatedBy: string,
  newKeyId: string,
): Promise<void> {
  const info = await transporter.sendMail({
    from: FROM_ADDRESS,
    to,
    subject: `Signing key rotated for ${orgName}`,
    html: emailLayout(`
      ${alertBanner('A new signing key has been activated', '#1B2A4A', '#EEF2FF')}
      ${paragraph(`The signing key for <strong>${orgName}</strong> has been rotated. A new key is now active.`)}
      ${infoTable(
        infoRow('New key ID', `<span style="font-family:monospace;">${newKeyId}</span>`) +
        infoRow('Rotated by', rotatedBy)
      )}
      ${paragraph('Existing QR codes signed with the previous key remain valid. New QR codes will be signed with the updated key.')}
      ${ctaButton(`${DASHBOARD_URL}/dashboard/settings`, 'View Signing Keys', '#1B2A4A')}
    `),
    text: `Signing key rotated for ${orgName}\n\nNew key ID: ${newKeyId}\nRotated by: ${rotatedBy}\n\nExisting QR codes signed with the previous key remain valid.`,
  });

  if (config.server.isDev) {
    const parsed = JSON.parse(info.message);
    console.log(`[email] Signing key rotated email for ${to}:`);
    console.log(`  Subject: ${parsed.subject}`);
    console.log(`  New key ID: ${newKeyId}`);
  }
}

// ---------------------------------------------------------------------------
// Email 11: Domain Verified
// ---------------------------------------------------------------------------

export async function sendDomainVerifiedEmail(
  to: string,
  orgName: string,
  domain: string,
): Promise<void> {
  const info = await transporter.sendMail({
    from: FROM_ADDRESS,
    to,
    subject: `Domain ${domain} verified for ${orgName}`,
    html: emailLayout(`
      ${alertBanner(`${domain} has been verified`, '#00A76F', '#E6F9F3')}
      ${heading('Domain Verified')}
      ${paragraph(`Your domain <strong>${domain}</strong> has been verified for <strong>${orgName}</strong>.`)}
      ${paragraph(`QR codes linking to <strong>${domain}</strong> will now display a verified badge on the scan confirmation page, giving your users greater confidence in the authenticity of your codes.`)}
      ${ctaButton(`${DASHBOARD_URL}/dashboard`, 'Go to Dashboard')}
    `),
    text: `Domain ${domain} verified for ${orgName}\n\nQR codes linking to ${domain} will now display a verified badge.\n\nGo to dashboard: ${DASHBOARD_URL}/dashboard`,
  });

  if (config.server.isDev) {
    const parsed = JSON.parse(info.message);
    console.log(`[email] Domain verified email for ${to}:`);
    console.log(`  Subject: ${parsed.subject}`);
    console.log(`  Domain: ${domain}`);
  }
}

// ---------------------------------------------------------------------------
// Email 12: Plan Changed
// ---------------------------------------------------------------------------

const PLAN_RANK: Record<string, number> = { FREE: 0, PRO: 1, ENTERPRISE: 2 };

export async function sendPlanChangedEmail(
  to: string,
  orgName: string,
  oldPlan: string,
  newPlan: string,
): Promise<void> {
  const isUpgrade = (PLAN_RANK[newPlan] ?? 0) > (PLAN_RANK[oldPlan] ?? 0);

  const bannerText = isUpgrade
    ? `${orgName} has been upgraded to ${newPlan}`
    : `${orgName} plan has changed to ${newPlan}`;
  const bannerColor = isUpgrade ? '#00A76F' : '#FFAB00';
  const bannerBg = isUpgrade ? '#E6F9F3' : '#FFF8EC';

  const bodyParagraph = isUpgrade
    ? `Your plan has been upgraded from <strong>${oldPlan}</strong> to <strong>${newPlan}</strong>. You now have access to expanded limits and features.`
    : `Your plan has been changed from <strong>${oldPlan}</strong> to <strong>${newPlan}</strong>. Your updated limits will take effect at the start of the next billing cycle.`;

  const info = await transporter.sendMail({
    from: FROM_ADDRESS,
    to,
    subject: `${orgName} plan changed to ${newPlan}`,
    html: emailLayout(`
      ${alertBanner(bannerText, bannerColor, bannerBg)}
      ${paragraph(bodyParagraph)}
      ${infoTable(
        infoRow('Previous plan', oldPlan) +
        infoRow('New plan', `<strong>${newPlan}</strong>`)
      )}
      ${isUpgrade
        ? paragraph('Thank you for upgrading. If you have any questions about your new plan, contact our support team.')
        : paragraph('If you have questions about your plan change or believe this was made in error, contact our support team.')}
      ${ctaButton(`${DASHBOARD_URL}/dashboard`, 'Go to Dashboard')}
    `),
    text: `${orgName} plan changed to ${newPlan}\n\nPrevious plan: ${oldPlan}\nNew plan: ${newPlan}\n\n${isUpgrade ? 'You now have access to expanded limits and features.' : 'Your updated limits will take effect at the start of the next billing cycle.'}\n\nDashboard: ${DASHBOARD_URL}/dashboard`,
  });

  if (config.server.isDev) {
    const parsed = JSON.parse(info.message);
    console.log(`[email] Plan changed email for ${to}:`);
    console.log(`  Subject: ${parsed.subject}`);
    console.log(`  ${oldPlan} → ${newPlan} (${isUpgrade ? 'upgrade' : 'downgrade'})`);
  }
}
