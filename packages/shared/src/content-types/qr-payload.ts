/**
 * Builds the correct QR code payload string for a given content type.
 *
 * - url       → destination URL
 * - vcard     → vCard 3.0 text
 * - event     → iCalendar VEVENT text
 * - coupon    → redemption URL (or verification placeholder)
 * - pdf       → verification placeholder
 * - feedback  → verification placeholder
 */
export function buildQRPayload(
  contentType: string,
  content: Record<string, any>,
  verificationUrl = 'https://qrauth.io/v/preview',
): string {
  switch (contentType) {
    case 'url':
      return content.destinationUrl || verificationUrl;

    case 'vcard':
      return buildVCardPayload(content);

    case 'event':
      return buildEventPayload(content);

    case 'coupon':
      return content.redemptionUrl || verificationUrl;

    default:
      return verificationUrl;
  }
}

function buildVCardPayload(content: Record<string, any>): string {
  const firstName: string = content.firstName ?? '';
  const lastName: string = content.lastName ?? '';
  const fullName = [firstName, lastName].filter(Boolean).join(' ');
  const address = content.address as Record<string, string> | undefined;

  const lines: string[] = [
    'BEGIN:VCARD',
    'VERSION:3.0',
    `FN:${fullName}`,
    `N:${lastName};${firstName};;;`,
  ];

  if (content.title) lines.push(`TITLE:${content.title}`);
  if (content.company) lines.push(`ORG:${content.company}`);
  if (content.email) lines.push(`EMAIL:${content.email}`);
  if (content.phone) lines.push(`TEL;TYPE=WORK:${content.phone}`);
  if (content.mobile) lines.push(`TEL;TYPE=CELL:${content.mobile}`);
  if (content.website) lines.push(`URL:${content.website}`);
  if (address && Object.values(address).some(Boolean)) {
    lines.push(
      `ADR:;;${address.street ?? ''};${address.city ?? ''};${address.state ?? ''};${address.zip ?? ''};${address.country ?? ''}`,
    );
  }
  if (content.summary) {
    lines.push(`NOTE:${String(content.summary).replace(/\n/g, '\\n')}`);
  }
  lines.push('END:VCARD');

  return lines.join('\r\n');
}

function buildEventPayload(content: Record<string, any>): string {
  const formatDt = (val: string | undefined): string => {
    if (!val) return '';
    // Accept ISO strings and convert to iCal basic format YYYYMMDDTHHMMSS
    return val.replace(/[-:]/g, '').replace(/\.\d{3}/, '').replace('Z', '');
  };

  const lines: string[] = [
    'BEGIN:VCALENDAR',
    'VERSION:2.0',
    'BEGIN:VEVENT',
  ];

  if (content.title) lines.push(`SUMMARY:${content.title}`);
  if (content.description) lines.push(`DESCRIPTION:${content.description.replace(/\n/g, '\\n')}`);
  if (content.startDate) lines.push(`DTSTART:${formatDt(content.startDate)}`);
  if (content.endDate) lines.push(`DTEND:${formatDt(content.endDate)}`);
  if (content.location || content.address) {
    lines.push(`LOCATION:${[content.location, content.address].filter(Boolean).join(', ')}`);
  }
  if (content.organizer) lines.push(`ORGANIZER:${content.organizer}`);

  lines.push('END:VEVENT', 'END:VCALENDAR');

  return lines.join('\r\n');
}
