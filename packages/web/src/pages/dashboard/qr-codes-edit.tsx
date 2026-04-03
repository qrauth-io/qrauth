import type { QRStyle } from 'src/components/qr-code';

import { getContentType } from '@qrauth/shared';
import { useRef, useState, useEffect, useCallback } from 'react';

import Box from '@mui/material/Box';
import Card from '@mui/material/Card';
import Chip from '@mui/material/Chip';
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

import { formatDateTime } from 'src/utils/format-date';

import axios, { endpoints } from 'src/lib/axios';

import { useSnackbar } from 'src/components/snackbar';
import { ContentForm } from 'src/components/content-form';
import { QRPreview, QRExportMenu, QRStylePicker } from 'src/components/qr-code';

// Reuse the preview components from create page
import { ContentPagePreview } from './qr-codes-create';

// ----------------------------------------------------------------------

const DEFAULT_STYLE: QRStyle = {
  templateId: 'classic',
  fgColor: '#000000',
  bgColor: '#FFFFFF',
  showLogo: true,
  captionText: 'QRAuth Verified',
};

export default function QRCodesEditPage() {
  const { token } = useParams();
  const router = useRouter();
  const { showSuccess, showError } = useSnackbar();
  const qrRef = useRef<HTMLDivElement>(null);

  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [qrCode, setQrCode] = useState<any>(null);
  const [contentValues, setContentValues] = useState<Record<string, any>>({});
  const [qrStyle, setQrStyle] = useState<QRStyle>(DEFAULT_STYLE);
  const [previewTab, setPreviewTab] = useState<'qr' | 'page'>('page');

  const contentType = qrCode?.contentType || 'url';
  const typeDef = getContentType(contentType);

  const fetchQR = useCallback(async () => {
    try {
      const res = await axios.get(endpoints.qrcodes.details(token!));
      const data = res.data;
      setQrCode(data);

      // Populate content values from stored content or URL fields
      if (data.contentType === 'url' || !data.contentType) {
        setContentValues({ destinationUrl: data.destinationUrl, label: data.label || '' });
      } else if (data.content) {
        setContentValues({ ...data.content, label: data.label || '' });
      }
    } catch (err: unknown) {
      showError((err as Error).message || 'Failed to load QR code');
    } finally {
      setLoading(false);
    }
  }, [token, showError]);

  useEffect(() => {
    if (token) fetchQR();
  }, [token, fetchQR]);

  const handleContentChange = (name: string, value: any) => {
    setContentValues((prev) => ({ ...prev, [name]: value }));
    setSaved(false);
  };

  const handleSave = async () => {
    setSaving(true);
    try {
      const payload: any = {
        label: contentValues.label || contentValues.firstName || contentValues.title || contentValues.name || undefined,
      };

      if (contentType === 'url') {
        payload.destinationUrl = contentValues.destinationUrl;
      }

      // Note: content updates for non-URL types would need an API extension
      // For now, we save the label and destinationUrl

      await axios.patch(endpoints.qrcodes.details(token!), payload);
      showSuccess('QR code saved');
      setSaved(true);
      fetchQR();
    } catch (err: unknown) {
      showError((err as Error).message || 'Failed to save');
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
      <Box sx={{ mb: 3, display: 'flex', alignItems: 'center', gap: 2 }}>
        <Button variant="text" onClick={() => router.push(paths.dashboard.qrcodes.root)}>
          ← Back
        </Button>
        <Typography variant="h4">
          {typeDef?.label || 'Edit QR Code'}
        </Typography>
        <Chip label={contentType} size="small" variant="outlined" />
      </Box>

      {saved && (
        <Alert severity="success" sx={{ mb: 3 }}>
          QR code saved successfully. Use the export and print options on the right to download or print.
        </Alert>
      )}

      <Stack direction={{ xs: 'column', md: 'row' }} spacing={3}>
        {/* Left — Content form + meta + style */}
        <Stack spacing={3} sx={{ flex: 1, minWidth: 0 }}>
          {/* Content */}
          <Card>
            <CardHeader title="Content" subheader={typeDef?.description} />
            <CardContent>
              {contentType === 'url' ? (
                <Stack spacing={2}>
                  <TextField
                    label="Destination URL"
                    value={contentValues.destinationUrl || ''}
                    onChange={(e) => handleContentChange('destinationUrl', e.target.value)}
                    fullWidth
                    slotProps={{ inputLabel: { shrink: true } }}
                  />
                  <TextField
                    label="Label"
                    value={contentValues.label || ''}
                    onChange={(e) => handleContentChange('label', e.target.value)}
                    fullWidth
                    slotProps={{ inputLabel: { shrink: true } }}
                  />
                </Stack>
              ) : typeDef ? (
                <ContentForm
                  fields={typeDef.fields}
                  values={contentValues}
                  onChange={handleContentChange}
                />
              ) : (
                <Typography color="text.secondary">Unknown content type</Typography>
              )}
            </CardContent>
          </Card>

          {/* Location */}
          <Card>
            <CardHeader title="Location Binding" subheader="Optional — bind to a physical location" />
            <CardContent>
              <Stack direction="row" spacing={2}>
                <TextField
                  label="Latitude"
                  type="number"
                  value={qrCode.latitude || ''}
                  size="small"
                  fullWidth
                  disabled
                  slotProps={{ inputLabel: { shrink: true } }}
                />
                <TextField
                  label="Longitude"
                  type="number"
                  value={qrCode.longitude || ''}
                  size="small"
                  fullWidth
                  disabled
                  slotProps={{ inputLabel: { shrink: true } }}
                />
                <TextField
                  label="Radius (m)"
                  type="number"
                  value={qrCode.radiusM || 50}
                  size="small"
                  fullWidth
                  disabled
                  slotProps={{ inputLabel: { shrink: true } }}
                />
              </Stack>
            </CardContent>
          </Card>

          {/* Meta info */}
          <Card>
            <CardHeader title="Details" />
            <CardContent>
              <Stack spacing={1.5}>
                <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
                  <Typography variant="body2" color="text.secondary">Token</Typography>
                  <Typography variant="body2" sx={{ fontFamily: 'monospace', fontWeight: 600 }}>{qrCode.token}</Typography>
                </Box>
                <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
                  <Typography variant="body2" color="text.secondary">Status</Typography>
                  <Chip label={qrCode.status} size="small" color={qrCode.status === 'ACTIVE' ? 'success' : 'default'} />
                </Box>
                <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
                  <Typography variant="body2" color="text.secondary">Created</Typography>
                  <Typography variant="body2">{formatDateTime(qrCode.createdAt)}</Typography>
                </Box>
                <Divider />
                <Box>
                  <Typography variant="caption" color="text.disabled" sx={{ fontFamily: 'monospace', wordBreak: 'break-all' }}>
                    Sig: {qrCode.signature?.slice(0, 40)}...
                  </Typography>
                </Box>
              </Stack>
            </CardContent>
          </Card>

          {/* Style */}
          <Card>
            <CardHeader title="QR Code Style" />
            <CardContent>
              <QRStylePicker value={qrStyle} onChange={setQrStyle} />
            </CardContent>
          </Card>

          <Button
            fullWidth
            variant="contained"
            size="large"
            onClick={handleSave}
            disabled={saving}
            sx={{ bgcolor: '#00A76F', '&:hover': { bgcolor: '#007B55' } }}
          >
            {saving ? 'Saving...' : 'Save Changes'}
          </Button>
        </Stack>

        {/* Right — Tabbed preview + export */}
        <Box
          sx={{
            width: { xs: '100%', md: 380 },
            position: { md: 'sticky' },
            top: { md: 88 },
            alignSelf: 'flex-start',
          }}
        >
          <Card>
            {/* Tabs */}
            <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
              <Stack direction="row">
                <Button
                  fullWidth
                  variant="text"
                  onClick={() => setPreviewTab('qr')}
                  sx={{
                    py: 1.5, borderRadius: 0, borderBottom: '2px solid',
                    borderColor: previewTab === 'qr' ? 'primary.main' : 'transparent',
                    color: previewTab === 'qr' ? 'primary.main' : 'text.secondary',
                    fontWeight: previewTab === 'qr' ? 700 : 400,
                  }}
                >
                  QR Code
                </Button>
                <Button
                  fullWidth
                  variant="text"
                  onClick={() => setPreviewTab('page')}
                  sx={{
                    py: 1.5, borderRadius: 0, borderBottom: '2px solid',
                    borderColor: previewTab === 'page' ? 'primary.main' : 'transparent',
                    color: previewTab === 'page' ? 'primary.main' : 'text.secondary',
                    fontWeight: previewTab === 'page' ? 700 : 400,
                  }}
                >
                  Page Preview
                </Button>
              </Stack>
            </Box>

            {/* QR — always rendered for export ref, hidden when on page tab */}
            <Box sx={{ p: 3, display: previewTab === 'qr' ? 'block' : 'none' }} ref={qrRef}>
              <QRPreview
                value={verificationUrl}
                style={qrStyle}
                size={260}
                token={qrCode.token}
              />
            </Box>
            {previewTab === 'page' && (
              <Box sx={{ height: 520, overflow: 'auto', bgcolor: '#f5f5f5' }}>
                <ContentPagePreview type={contentType} content={contentValues} />
              </Box>
            )}
          </Card>

          {/* Export — always visible */}
          <Card sx={{ p: 2, mt: 2 }}>
            <QRExportMenu
              containerRef={qrRef}
              token={qrCode.token}
              captionText={qrStyle.captionText}
              bgColor={qrStyle.bgColor}
            />
          </Card>
        </Box>
      </Stack>
    </>
  );
}
