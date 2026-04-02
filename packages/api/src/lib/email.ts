import { createTransport, type Transporter } from 'nodemailer';
import { config } from './config.js';

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

let transporter: Transporter;

if (config.server.isDev || !process.env.SMTP_HOST) {
  // Development: log emails to console instead of sending
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

const FROM_ADDRESS = process.env.EMAIL_FROM || 'vQR <noreply@vqr.io>';

// ---------------------------------------------------------------------------
// Email templates
// ---------------------------------------------------------------------------

export async function sendPasswordResetEmail(to: string, resetToken: string): Promise<void> {
  const resetUrl = `${process.env.WEBAUTHN_ORIGIN || 'http://localhost:8081'}/auth/jwt/reset-password?token=${resetToken}`;

  const info = await transporter.sendMail({
    from: FROM_ADDRESS,
    to,
    subject: 'Reset your vQR password',
    html: `
      <div style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;max-width:480px;margin:0 auto;padding:40px 20px;">
        <h2 style="color:#1B2A4A;margin-bottom:16px;">Reset Your Password</h2>
        <p style="color:#637381;font-size:14px;line-height:1.6;">
          We received a request to reset your vQR account password. Click the button below to set a new password.
        </p>
        <a href="${resetUrl}" style="display:inline-block;padding:12px 32px;background:#00A76F;color:white;text-decoration:none;border-radius:8px;font-weight:600;margin:24px 0;">
          Reset Password
        </a>
        <p style="color:#919eab;font-size:12px;line-height:1.5;">
          This link expires in 1 hour. If you didn't request this, you can safely ignore this email.
        </p>
        <hr style="border:none;border-top:1px solid #f0f0f0;margin:24px 0;">
        <p style="color:#c4cdd5;font-size:11px;">Sent by vQR — Verified QR Code Security Platform</p>
      </div>
    `,
    text: `Reset your vQR password: ${resetUrl}\n\nThis link expires in 1 hour. If you didn't request this, ignore this email.`,
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
  const acceptUrl = `${process.env.WEBAUTHN_ORIGIN || 'http://localhost:8081'}/auth/jwt/sign-up?invite=${inviteToken}`;

  const info = await transporter.sendMail({
    from: FROM_ADDRESS,
    to,
    subject: `${inviterName} invited you to ${orgName} on vQR`,
    html: `
      <div style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;max-width:480px;margin:0 auto;padding:40px 20px;">
        <h2 style="color:#1B2A4A;margin-bottom:16px;">You've Been Invited</h2>
        <p style="color:#637381;font-size:14px;line-height:1.6;">
          <strong>${inviterName}</strong> invited you to join <strong>${orgName}</strong> on vQR as a <strong>${role}</strong>.
        </p>
        <a href="${acceptUrl}" style="display:inline-block;padding:12px 32px;background:#00A76F;color:white;text-decoration:none;border-radius:8px;font-weight:600;margin:24px 0;">
          Accept Invitation
        </a>
        <p style="color:#919eab;font-size:12px;line-height:1.5;">
          This invitation expires in 72 hours.
        </p>
        <hr style="border:none;border-top:1px solid #f0f0f0;margin:24px 0;">
        <p style="color:#c4cdd5;font-size:11px;">Sent by vQR — Verified QR Code Security Platform</p>
      </div>
    `,
    text: `${inviterName} invited you to join ${orgName} on vQR as a ${role}.\n\nAccept: ${acceptUrl}\n\nThis invitation expires in 72 hours.`,
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
    html: `
      <div style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;max-width:480px;margin:0 auto;padding:40px 20px;">
        <div style="padding:12px 16px;background:#FFF3E0;border-left:4px solid ${severityColor};border-radius:4px;margin-bottom:24px;">
          <strong style="color:${severityColor};">${incident.severity} — ${incident.type.replace(/_/g, ' ')}</strong>
        </div>
        <p style="color:#637381;font-size:14px;line-height:1.6;">
          A fraud incident has been detected for your organization <strong>${orgName}</strong>.
        </p>
        <table style="width:100%;font-size:14px;margin:16px 0;">
          <tr><td style="color:#919eab;padding:4px 0;">QR Code</td><td style="font-family:monospace;font-weight:600;">${incident.qrCodeToken}</td></tr>
          <tr><td style="color:#919eab;padding:4px 0;">Type</td><td>${incident.type.replace(/_/g, ' ')}</td></tr>
          <tr><td style="color:#919eab;padding:4px 0;">Severity</td><td style="color:${severityColor};font-weight:600;">${incident.severity}</td></tr>
        </table>
        <a href="${process.env.WEBAUTHN_ORIGIN || 'http://localhost:8081'}/dashboard/fraud" style="display:inline-block;padding:12px 32px;background:#1B2A4A;color:white;text-decoration:none;border-radius:8px;font-weight:600;margin:16px 0;">
          View in Dashboard
        </a>
        <hr style="border:none;border-top:1px solid #f0f0f0;margin:24px 0;">
        <p style="color:#c4cdd5;font-size:11px;">Sent by vQR — Verified QR Code Security Platform</p>
      </div>
    `,
    text: `[${incident.severity}] Fraud alert for ${orgName}\n\nQR Code: ${incident.qrCodeToken}\nType: ${incident.type}\nSeverity: ${incident.severity}\n\nView in dashboard: ${process.env.WEBAUTHN_ORIGIN || 'http://localhost:8081'}/dashboard/fraud`,
  });

  if (config.server.isDev) {
    const parsed = JSON.parse(info.message);
    console.log(`[email] Fraud alert email for ${to}:`);
    console.log(`  Subject: ${parsed.subject}`);
  }
}
