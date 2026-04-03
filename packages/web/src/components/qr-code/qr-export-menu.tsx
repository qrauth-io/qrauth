import type { RefObject } from 'react';
import type { IconifyProps } from 'src/components/iconify';

import { useState, useCallback } from 'react';

import Menu from '@mui/material/Menu';
import Stack from '@mui/material/Stack';
import Button from '@mui/material/Button';
import MenuItem from '@mui/material/MenuItem';
import MenuList from '@mui/material/MenuList';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';

import { Iconify } from 'src/components/iconify';
import { useSnackbar } from 'src/components/snackbar';

import {
  printQR,
  exportAsSVG,
  exportAsPNG,
  exportAsPDF,
  exportAsJPEG,
  exportAsWebP,
} from './qr-export';

// ----------------------------------------------------------------------

type Props = {
  containerRef: RefObject<HTMLElement | null>;
  token?: string;
  captionText?: string;
  bgColor?: string;
};

type ExportOption = {
  label: string;
  subtitle: string;
  icon: IconifyProps['icon'];
  action: () => Promise<void>;
};

export function QRExportMenu({ containerRef, token, captionText, bgColor = '#FFFFFF' }: Props) {
  const { showSuccess, showError } = useSnackbar();
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);
  const filename = `qrauth-${token || 'code'}`;

  const handleExport = useCallback(
    async (fn: () => Promise<void>, label: string) => {
      try {
        await fn();
        showSuccess(`Exported as ${label}`);
      } catch (err: any) {
        showError(err.message || `Failed to export as ${label}`);
      }
      setAnchorEl(null);
    },
    [showSuccess, showError]
  );

  const container = containerRef.current;

  const exportOptions: ExportOption[] = container
    ? [
        {
          label: 'SVG (Vector)',
          subtitle: 'Best for print & scaling',
          icon: 'solar:file-text-bold',
          action: () => exportAsSVG(container, filename),
        },
        {
          label: 'PNG (High-Res)',
          subtitle: '1024x1024px, transparent',
          icon: 'solar:gallery-add-bold',
          action: () => exportAsPNG(container, filename, bgColor, 1024),
        },
        {
          label: 'PNG (Extra Large)',
          subtitle: '2048x2048px',
          icon: 'solar:gallery-wide-bold',
          action: () => exportAsPNG(container, filename, bgColor, 2048),
        },
        {
          label: 'JPEG',
          subtitle: '1024x1024px',
          icon: 'solar:camera-add-bold',
          action: () => exportAsJPEG(container, filename, bgColor, 1024),
        },
        {
          label: 'WebP',
          subtitle: '1024x1024px, modern format',
          icon: 'solar:export-bold',
          action: () => exportAsWebP(container, filename, bgColor, 1024),
        },
        {
          label: 'PDF',
          subtitle: 'Print-ready document',
          icon: 'solar:bill-list-bold',
          action: () => exportAsPDF(container, filename, bgColor, captionText, token),
        },
      ]
    : [];

  return (
    <Stack direction="row" spacing={1}>
      <Button
        variant="outlined"
        startIcon={<Iconify icon="solar:printer-minimalistic-bold" />}
        onClick={() => {
          if (container) {
            printQR(container, bgColor, captionText, token).catch((err: any) =>
              showError(err.message || 'Print failed')
            );
          }
        }}
      >
        Print
      </Button>

      <Button
        variant="contained"
        startIcon={<Iconify icon="solar:download-bold" />}
        onClick={(e) => setAnchorEl(e.currentTarget)}
      >
        Export As...
      </Button>

      <Menu
        anchorEl={anchorEl}
        open={Boolean(anchorEl)}
        onClose={() => setAnchorEl(null)}
        slotProps={{ paper: { sx: { width: 260 } } }}
      >
        <MenuList>
          {exportOptions.map((opt) => (
            <MenuItem key={opt.label} onClick={() => handleExport(opt.action, opt.label)}>
              <ListItemIcon>
                <Iconify icon={opt.icon} />
              </ListItemIcon>
              <ListItemText
                primary={opt.label}
                secondary={opt.subtitle}
                slotProps={{
                  primary: { variant: 'body2', fontWeight: 600 } as any,
                  secondary: { variant: 'caption' } as any,
                }}
              />
            </MenuItem>
          ))}
        </MenuList>
      </Menu>
    </Stack>
  );
}
