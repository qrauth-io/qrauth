import PDFDocument from 'pdfkit';
import { RENDERER_VERSION, type DrawList } from '@qrauth/shared/qr-render';

import { mmToPoints } from './print-size.js';

/**
 * Vector PDF export (ADR-0005 D7, PR 6): walks the renderer's draw list
 * with pdfkit. Every path (modules, eyes, frame, outlined frame text) is a
 * PDF path filled with its sRGB colour (DeviceRGB, no CMYK conversion); the
 * logo is the one raster, embedded from its normalised PNG. The code itself
 * is never embedded as an image.
 *
 * Deterministic: equal inputs give equal bytes. CreationDate (in the Info
 * dictionary and the XMP packet) is a fixed constant, there is no ModDate,
 * and pdfkit derives the file ID from the Info dictionary (Title carries the
 * token), so the strong ETag holds for PDFs. Metadata names QRAuth as
 * Producer, QRAuth and the renderer version as Creator, and the token in
 * the Title; no internal ids.
 */

/**
 * A fixed CreationDate: pdfkit stamps the current time by default (and
 * derives the file ID from it), which would make every render differ.
 */
const FIXED_CREATION_DATE = new Date(Date.UTC(2026, 9, 30));

export const PDF_PRODUCER = 'QRAuth';
/** Creator names the renderer version (ADR-0005 D8: the geometry version travels with the export). */
export const PDF_CREATOR = `QRAuth qrauth-qr/${RENDERER_VERSION}`;

export interface PdfPage {
  /** Artwork width on the page, in mm. */
  readonly sizeMm: number;
  /** Margin on every side, in mm. */
  readonly marginMm: number;
  /** Document title (the code's token), no internal ids. */
  readonly title: string;
}

/** Renders `list` as a one-page PDF: the page is the artwork plus `marginMm` on every side. */
export function drawListToPdf(list: DrawList, page: PdfPage): Promise<Buffer> {
  const scale = mmToPoints(page.sizeMm) / list.width;
  const margin = mmToPoints(page.marginMm);
  const pageWidth = list.width * scale + 2 * margin;
  const pageHeight = list.height * scale + 2 * margin;

  const doc = new PDFDocument({
    size: [pageWidth, pageHeight],
    margin: 0,
    autoFirstPage: true,
    // 1.4: the logo's alpha channel is a soft mask (SMask), a PDF 1.4 feature.
    pdfVersion: '1.4',
    compress: true,
    info: {
      Title: page.title,
      Producer: PDF_PRODUCER,
      Creator: PDF_CREATOR,
      CreationDate: FIXED_CREATION_DATE,
    },
  });

  const chunks: Buffer[] = [];
  const done = new Promise<Buffer>((resolve, reject) => {
    doc.on('data', (chunk: Buffer) => chunks.push(chunk));
    doc.on('end', () => resolve(Buffer.concat(chunks)));
    doc.on('error', reject);
  });

  doc.save();
  doc.translate(margin, margin).scale(scale);
  for (const item of list.items) {
    if (item.kind === 'image') {
      doc.image(Buffer.from(item.bytes), item.x, item.y, {
        fit: [item.width, item.height],
        align: 'center',
        valign: 'center',
      });
    } else if (item.d !== '') {
      doc.path(item.d).fill(item.fill, item.fillRule === 'evenodd' ? 'even-odd' : 'non-zero');
    }
  }
  doc.restore();
  doc.end();
  return done;
}
