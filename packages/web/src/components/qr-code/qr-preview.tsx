import type { QRStyle } from './qr-style-picker';

import { QRCodeSVG } from 'qrcode.react';

import Box from '@mui/material/Box';
import Typography from '@mui/material/Typography';

import { QRAUTH_LOGO_SVG_DATA_URI } from './qrauth-logo';

// ----------------------------------------------------------------------

type Props = {
  value: string;
  style: QRStyle;
  size?: number;
  token?: string;
};

export function QRPreview({ value, style, size = 260, token }: Props) {
  const previewUrl = value || 'https://qrauth.io/v/preview';

  return (
    <Box sx={{ textAlign: 'center' }}>
      <Box
        sx={{
          p: 3,
          mx: 'auto',
          width: 'fit-content',
          borderRadius: 2,
          bgcolor: style.bgColor,
          border: '1px solid',
          borderColor: 'divider',
          boxShadow: (theme) => theme.shadows[3],
          transition: 'all 0.3s ease',
        }}
      >
        <QRCodeSVG
          value={previewUrl}
          size={size}
          level="H"
          marginSize={1}
          fgColor={style.fgColor}
          bgColor={style.bgColor}
          {...(style.showLogo && {
            imageSettings: {
              src: QRAUTH_LOGO_SVG_DATA_URI,
              x: undefined,
              y: undefined,
              height: Math.round(size * 0.22),
              width: Math.round(size * 0.22),
              excavate: true,
            },
          })}
        />
      </Box>

      {style.captionText && (
        <Typography
          variant="body2"
          color="text.secondary"
          sx={{ mt: 0.5, display: 'block' }}
        >
          {style.captionText}
        </Typography>
      )}
    </Box>
  );
}
