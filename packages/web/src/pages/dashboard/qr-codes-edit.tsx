import type { QRStyle } from 'src/components/qr-code';

import { useRef, useState, useEffect, useCallback } from 'react';

import Box from '@mui/material/Box';
import Card from '@mui/material/Card';
import Stack from '@mui/material/Stack';
import Alert from '@mui/material/Alert';
import Button from '@mui/material/Button';
import Divider from '@mui/material/Divider';
import TextField from '@mui/material/TextField';
import CardHeader from '@mui/material/CardHeader';
import Typography from '@mui/material/Typography';
import CardContent from '@mui/material/CardContent';
import CircularProgress from '@mui/material/CircularProgress';

import { paths } from 'src/routes/paths';
import { useParams, useRouter } from 'src/routes/hooks';

import axios, { endpoints } from 'src/lib/axios';

import { useSnackbar } from 'src/components/snackbar';
import { QRPreview, QRExportMenu, QRStylePicker } from 'src/components/qr-code';

// ----------------------------------------------------------------------

const DEFAULT_STYLE: QRStyle = {
  templateId: 'classic',
  fgColor: '#000000',
  bgColor: '#FFFFFF',
  showLogo: true,
  captionText: 'vQR Verified',
};

export default function QRCodesEditPage() {
  const { token } = useParams();
  const router = useRouter();
  const { showSuccess, showError } = useSnackbar();
  const qrRef = useRef<HTMLDivElement>(null);

  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [qrCode, setQrCode] = useState<any>(null);
  const [destinationUrl, setDestinationUrl] = useState('');
  const [label, setLabel] = useState('');
  const [qrStyle, setQrStyle] = useState<QRStyle>(DEFAULT_STYLE);

  const fetchQR = useCallback(async () => {
    try {
      const res = await axios.get(endpoints.qrcodes.details(token!));
      const data = res.data;
      setQrCode(data);
      setDestinationUrl(data.destinationUrl);
      setLabel(data.label || '');
    } catch (err: any) {
      showError(err.message || 'Failed to load QR code');
    } finally {
      setLoading(false);
    }
  }, [token, showError]);

  useEffect(() => {
    if (token) fetchQR();
  }, [token, fetchQR]);

  const handleSave = async () => {
    setSaving(true);
    try {
      const payload: any = {};
      if (destinationUrl !== qrCode.destinationUrl) payload.destinationUrl = destinationUrl;
      if (label !== (qrCode.label || '')) payload.label = label || undefined;

      if (Object.keys(payload).length > 0) {
        await axios.patch(endpoints.qrcodes.details(token!), payload);
        showSuccess('QR code updated successfully');
        fetchQR(); // Reload to get new signature
      } else {
        showSuccess('No changes to save');
      }
    } catch (err: any) {
      showError(err.message || 'Failed to update QR code');
    } finally {
      setSaving(false);
    }
  };

  if (loading) {
    return (
      <Box sx={{ textAlign: 'center', py: 10 }}>
        <CircularProgress />
      </Box>
    );
  }

  if (!qrCode) {
    return <Alert severity="error">QR code not found</Alert>;
  }

  const verificationUrl = `${window.location.origin}/v/${qrCode.token}`;

  return (
    <>
      <Box sx={{ mb: 3, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <Typography variant="h4">Edit QR Code</Typography>
        <Button variant="outlined" onClick={() => router.push(paths.dashboard.qrcodes.root)}>
          Back to QR Codes
        </Button>
      </Box>

      <Stack direction={{ xs: 'column', md: 'row' }} spacing={3}>
        {/* Left — Edit form + Style */}
        <Stack spacing={3} sx={{ flex: 1, minWidth: 0 }}>
          <Card>
            <CardHeader title="QR Code Details" />
            <CardContent>
              <Stack spacing={3}>
                <TextField
                  label="Destination URL"
                  value={destinationUrl}
                  onChange={(e) => setDestinationUrl(e.target.value)}
                  fullWidth
                  slotProps={{ inputLabel: { shrink: true } }}
                />
                <TextField
                  label="Label"
                  value={label}
                  onChange={(e) => setLabel(e.target.value)}
                  fullWidth
                  slotProps={{ inputLabel: { shrink: true } }}
                />

                <Divider />

                <Box>
                  <Typography variant="subtitle2" color="text.secondary">
                    Token
                  </Typography>
                  <Typography variant="body1" sx={{ fontFamily: 'monospace' }}>
                    {qrCode.token}
                  </Typography>
                </Box>

                <Box>
                  <Typography variant="subtitle2" color="text.secondary">
                    Signature
                  </Typography>
                  <Typography
                    variant="caption"
                    sx={{ fontFamily: 'monospace', wordBreak: 'break-all', color: 'text.disabled' }}
                  >
                    {qrCode.signature}
                  </Typography>
                </Box>

                <Button
                  variant="contained"
                  size="large"
                  onClick={handleSave}
                  disabled={saving}
                >
                  {saving ? 'Saving...' : 'Save Changes'}
                </Button>
              </Stack>
            </CardContent>
          </Card>

          <Card>
            <CardHeader title="Appearance" />
            <CardContent>
              <QRStylePicker value={qrStyle} onChange={setQrStyle} />
            </CardContent>
          </Card>
        </Stack>

        {/* Right — Live preview + Export */}
        <Box
          sx={{
            width: { xs: '100%', md: 360 },
            position: { md: 'sticky' },
            top: { md: 88 },
            alignSelf: 'flex-start',
          }}
        >
          <Card sx={{ p: 4 }}>
            <Typography variant="subtitle1" sx={{ mb: 2, textAlign: 'center' }}>
              Preview
            </Typography>
            <Box ref={qrRef}>
              <QRPreview
                value={verificationUrl}
                style={qrStyle}
                size={260}
                token={qrCode.token}
              />
            </Box>
            <Stack spacing={1} sx={{ mt: 3 }} alignItems="center">
              <QRExportMenu
                containerRef={qrRef}
                token={qrCode.token}
                captionText={qrStyle.captionText}
                bgColor={qrStyle.bgColor}
              />
            </Stack>
          </Card>
        </Box>
      </Stack>
    </>
  );
}
