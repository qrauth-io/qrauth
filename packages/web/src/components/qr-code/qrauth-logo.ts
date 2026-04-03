// Inline SVG data URI for the QRAuth shield logo.
// The shield conveys security/trust and is embedded in the centre of every QR code.
// Using a data URI avoids an extra network request and works in both <img> and qrcode.react's imageSettings.

const SVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 120 120" fill="none">
  <!-- Shield body -->
  <path d="M60 8L16 28v32c0 28 18.7 54.2 44 60 25.3-5.8 44-32 44-60V28L60 8z" fill="#1B2A4A"/>
  <!-- Shield inner highlight -->
  <path d="M60 16L24 33v25c0 23.5 15.3 45.5 36 50.4 20.7-4.9 36-26.9 36-50.4V33L60 16z" fill="#263B66"/>
  <!-- Checkmark circle -->
  <circle cx="60" cy="56" r="24" fill="#00A76F"/>
  <!-- Checkmark -->
  <path d="M50 56l7 7 13-14" stroke="#fff" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/>
  <!-- QRAuth text -->
  <text x="60" y="100" text-anchor="middle" font-family="Arial,Helvetica,sans-serif" font-weight="800" font-size="16" fill="#fff" letter-spacing="1">QRAuth</text>
</svg>`;

export const QRAUTH_LOGO_SVG_DATA_URI = `data:image/svg+xml;base64,${btoa(SVG)}`;
