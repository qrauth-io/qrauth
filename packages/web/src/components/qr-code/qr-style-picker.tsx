import { useCallback } from 'react';

import Box from '@mui/material/Box';
import Stack from '@mui/material/Stack';
import TextField from '@mui/material/TextField';
import Typography from '@mui/material/Typography';
import ButtonBase from '@mui/material/ButtonBase';
import { alpha, useTheme } from '@mui/material/styles';

import { ColorPicker } from 'src/components/color-utils';

// ----------------------------------------------------------------------

export type QRStyle = {
  templateId: string;
  fgColor: string;
  bgColor: string;
  showLogo: boolean;
  captionText: string;
};

export const QR_TEMPLATES: {
  id: string;
  label: string;
  fgColor: string;
  bgColor: string;
}[] = [
  { id: 'classic', label: 'Classic', fgColor: '#000000', bgColor: '#FFFFFF' },
  { id: 'dark', label: 'Dark', fgColor: '#FFFFFF', bgColor: '#1B2A4A' },
  { id: 'ocean', label: 'Ocean', fgColor: '#003768', bgColor: '#E3F2FD' },
  { id: 'forest', label: 'Forest', fgColor: '#1B5E20', bgColor: '#E8F5E9' },
  { id: 'sunset', label: 'Sunset', fgColor: '#BF360C', bgColor: '#FFF3E0' },
  { id: 'royal', label: 'Royal', fgColor: '#4A148C', bgColor: '#F3E5F5' },
  { id: 'slate', label: 'Slate', fgColor: '#37474F', bgColor: '#ECEFF1' },
  { id: 'midnight', label: 'Midnight', fgColor: '#E0E0E0', bgColor: '#212121' },
];

const FG_COLORS = [
  '#000000', '#1B2A4A', '#003768', '#1B5E20',
  '#BF360C', '#4A148C', '#37474F', '#880E4F',
  '#01579B', '#004D40', '#E65100', '#311B92',
];

const BG_COLORS = [
  '#FFFFFF', '#F5F5F5', '#E3F2FD', '#E8F5E9',
  '#FFF3E0', '#F3E5F5', '#ECEFF1', '#FFF8E1',
  '#E0F2F1', '#FCE4EC', '#1B2A4A', '#212121',
];

// ----------------------------------------------------------------------

type Props = {
  value: QRStyle;
  onChange: (style: QRStyle) => void;
};

export function QRStylePicker({ value, onChange }: Props) {
  const theme = useTheme();

  const handleTemplateSelect = useCallback(
    (templateId: string) => {
      const t = QR_TEMPLATES.find((tpl) => tpl.id === templateId);
      if (t) {
        onChange({ ...value, templateId: t.id, fgColor: t.fgColor, bgColor: t.bgColor });
      }
    },
    [onChange, value]
  );

  return (
    <Stack spacing={3}>
      {/* Templates */}
      <Box>
        <Typography variant="subtitle2" sx={{ mb: 1.5 }}>
          Template
        </Typography>
        <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1.5 }}>
          {QR_TEMPLATES.map((t) => {
            const selected = value.templateId === t.id;
            return (
              <ButtonBase
                key={t.id}
                onClick={() => handleTemplateSelect(t.id)}
                sx={{
                  p: 0.5,
                  borderRadius: 1.5,
                  flexDirection: 'column',
                  border: '2px solid',
                  borderColor: selected ? 'primary.main' : 'transparent',
                  bgcolor: selected ? alpha(theme.palette.primary.main, 0.08) : 'transparent',
                  transition: 'all 0.2s',
                  '&:hover': { bgcolor: alpha(theme.palette.primary.main, 0.04) },
                }}
              >
                <Box
                  sx={{
                    width: 56,
                    height: 56,
                    borderRadius: 1,
                    bgcolor: t.bgColor,
                    border: '1px solid',
                    borderColor: 'divider',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                  }}
                >
                  {/* Mini QR grid preview */}
                  <Box
                    sx={{
                      display: 'grid',
                      gridTemplateColumns: 'repeat(5, 1fr)',
                      gap: '2px',
                      width: 30,
                      height: 30,
                    }}
                  >
                    {[1,1,1,0,1, 1,0,1,1,0, 1,1,0,1,1, 0,1,1,0,1, 1,0,1,1,1].map((cell, i) => (
                      <Box
                        key={i}
                        sx={{
                          borderRadius: '1px',
                          bgcolor: cell ? t.fgColor : 'transparent',
                        }}
                      />
                    ))}
                  </Box>
                </Box>
                <Typography variant="caption" sx={{ mt: 0.5, fontWeight: selected ? 700 : 400 }}>
                  {t.label}
                </Typography>
              </ButtonBase>
            );
          })}
        </Box>
      </Box>

      {/* Foreground color */}
      <Box>
        <Typography variant="subtitle2" sx={{ mb: 1 }}>
          QR Color
        </Typography>
        <ColorPicker
          value={value.fgColor}
          onChange={(color) => onChange({ ...value, fgColor: color as string, templateId: 'custom' })}
          options={FG_COLORS}
          size={32}
        />
      </Box>

      {/* Background color */}
      <Box>
        <Typography variant="subtitle2" sx={{ mb: 1 }}>
          Background
        </Typography>
        <ColorPicker
          value={value.bgColor}
          onChange={(color) => onChange({ ...value, bgColor: color as string, templateId: 'custom' })}
          options={BG_COLORS}
          size={32}
        />
      </Box>

      {/* Logo toggle */}
      <Box>
        <Typography variant="subtitle2" sx={{ mb: 1 }}>
          Security Badge
        </Typography>
        <Stack direction="row" spacing={1}>
          {[true, false].map((show) => (
            <ButtonBase
              key={String(show)}
              onClick={() => onChange({ ...value, showLogo: show })}
              sx={{
                px: 2,
                py: 1,
                borderRadius: 1,
                border: '2px solid',
                borderColor: value.showLogo === show ? 'primary.main' : 'divider',
                bgcolor: value.showLogo === show ? alpha(theme.palette.primary.main, 0.08) : 'transparent',
                transition: 'all 0.2s',
              }}
            >
              <Typography variant="body2" fontWeight={value.showLogo === show ? 700 : 400}>
                {show ? 'With vQR Badge' : 'No Badge'}
              </Typography>
            </ButtonBase>
          ))}
        </Stack>
      </Box>

      {/* Caption text */}
      <Box>
        <Typography variant="subtitle2" sx={{ mb: 1 }}>
          Caption Text
        </Typography>
        <TextField
          fullWidth
          size="small"
          value={value.captionText}
          onChange={(e) => onChange({ ...value, captionText: e.target.value })}
          placeholder="vQR Verified"
          helperText="Displayed below the QR code"
        />
      </Box>
    </Stack>
  );
}
