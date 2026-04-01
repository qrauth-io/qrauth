import type { QRStyle } from 'src/components/qr-code';

import * as z from 'zod';
import { useRef, useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';

import Box from '@mui/material/Box';
import Card from '@mui/material/Card';
import Stack from '@mui/material/Stack';
import Alert from '@mui/material/Alert';
import Button from '@mui/material/Button';
import Divider from '@mui/material/Divider';
import CardHeader from '@mui/material/CardHeader';
import Typography from '@mui/material/Typography';
import CardContent from '@mui/material/CardContent';

import { paths } from 'src/routes/paths';
import { useRouter } from 'src/routes/hooks';

import axios, { endpoints } from 'src/lib/axios';

import { useSnackbar } from 'src/components/snackbar';
import { Form, Field } from 'src/components/hook-form';
import { QRPreview, QRExportMenu, QRStylePicker } from 'src/components/qr-code';

// ----------------------------------------------------------------------

const CreateQRSchema = z.object({
  destinationUrl: z.string().url('Must be a valid URL'),
  label: z.string().optional(),
  latitude: z.coerce.number().min(-90).max(90).optional().or(z.literal('')),
  longitude: z.coerce.number().min(-180).max(180).optional().or(z.literal('')),
  radiusM: z.coerce.number().min(1).max(1000).optional().or(z.literal('')),
});

type CreateQRInput = z.infer<typeof CreateQRSchema>;

const DEFAULT_STYLE: QRStyle = {
  templateId: 'classic',
  fgColor: '#000000',
  bgColor: '#FFFFFF',
  showLogo: true,
  captionText: 'vQR Verified',
};

// ----------------------------------------------------------------------

export default function QRCodesCreatePage() {
  const router = useRouter();
  const { showSuccess, showError } = useSnackbar();
  const [createdQR, setCreatedQR] = useState<any>(null);
  const [qrStyle, setQrStyle] = useState<QRStyle>(DEFAULT_STYLE);
  const qrRef = useRef<HTMLDivElement>(null);

  const methods = useForm<CreateQRInput>({
    resolver: zodResolver(CreateQRSchema as any),
    defaultValues: {
      destinationUrl: '',
      label: '',
      latitude: '' as any,
      longitude: '' as any,
      radiusM: 50 as any,
    },
  });

  const {
    watch,
    handleSubmit,
    formState: { isSubmitting },
  } = methods;

  const watchedUrl = watch('destinationUrl');

  const onSubmit = handleSubmit(async (data) => {
    try {
      const payload: any = { destinationUrl: data.destinationUrl };

      if (data.label) payload.label = data.label;

      if (
        data.latitude !== '' &&
        data.longitude !== '' &&
        data.latitude !== undefined &&
        data.longitude !== undefined
      ) {
        payload.location = {
          lat: Number(data.latitude),
          lng: Number(data.longitude),
          radiusM: data.radiusM !== '' && data.radiusM !== undefined ? Number(data.radiusM) : 50,
        };
      }

      const res = await axios.post(endpoints.qrcodes.create, payload);
      setCreatedQR(res.data);
      showSuccess(`QR code created! Token: ${res.data.token}`);
    } catch (error: any) {
      console.error(error);
      showError(error.message || 'Failed to create QR code');
    }
  });

  // ---------------------------------------------------------------------------
  // Success state — show the final QR code
  // ---------------------------------------------------------------------------

  if (createdQR) {
    return (
      <>
        <Typography variant="h4" sx={{ mb: 3 }}>
          QR Code Created
        </Typography>

        <Stack direction={{ xs: 'column', md: 'row' }} spacing={3}>
          {/* QR Code visual */}
          <Card
            sx={{ p: 4, minWidth: 340, display: 'flex', flexDirection: 'column', alignItems: 'center' }}
          >
            <Box ref={qrRef}>
              <QRPreview
                value={createdQR.verification_url}
                style={qrStyle}
                size={280}
                token={createdQR.token}
              />
            </Box>
            <Box sx={{ mt: 2 }}>
              <QRExportMenu
                containerRef={qrRef}
                token={createdQR.token}
                captionText={qrStyle.captionText}
                bgColor={qrStyle.bgColor}
              />
            </Box>
          </Card>

          {/* Details */}
          <Card sx={{ flex: 1 }}>
            <CardHeader title="Verification Details" />
            <CardContent>
              <Stack spacing={2}>
                <Alert severity="success">
                  Signed with ECDSA-P256 and registered on the transparency log.
                </Alert>

                <Box>
                  <Typography variant="subtitle2" color="text.secondary">
                    Verification URL
                  </Typography>
                  <Typography
                    variant="body2"
                    sx={{ fontFamily: 'monospace', wordBreak: 'break-all' }}
                  >
                    {createdQR.verification_url}
                  </Typography>
                </Box>

                {createdQR.label && (
                  <Box>
                    <Typography variant="subtitle2" color="text.secondary">
                      Label
                    </Typography>
                    <Typography variant="body1">{createdQR.label}</Typography>
                  </Box>
                )}

                <Divider />

                <Box>
                  <Typography variant="subtitle2" color="text.secondary">
                    Digital Signature
                  </Typography>
                  <Typography
                    variant="caption"
                    sx={{
                      fontFamily: 'monospace',
                      wordBreak: 'break-all',
                      color: 'text.disabled',
                    }}
                  >
                    {createdQR.signature}
                  </Typography>
                </Box>

                <Box>
                  <Typography variant="subtitle2" color="text.secondary">
                    Transparency Log
                  </Typography>
                  <Typography variant="body1">Entry #{createdQR.transparency_log_index}</Typography>
                </Box>

                <Stack direction="row" spacing={2} sx={{ mt: 2 }}>
                  <Button variant="contained" onClick={() => setCreatedQR(null)}>
                    Create Another
                  </Button>
                  <Button
                    variant="outlined"
                    onClick={() => router.push(paths.dashboard.qrcodes.root)}
                  >
                    Back to QR Codes
                  </Button>
                </Stack>
              </Stack>
            </CardContent>
          </Card>
        </Stack>
      </>
    );
  }

  // ---------------------------------------------------------------------------
  // Create form with live preview
  // ---------------------------------------------------------------------------

  return (
    <>
      <Typography variant="h4" sx={{ mb: 3 }}>
        Create QR Code
      </Typography>

      <Form methods={methods} onSubmit={onSubmit}>
        <Stack direction={{ xs: 'column', md: 'row' }} spacing={3}>
          {/* Left — Form */}
          <Stack spacing={3} sx={{ flex: 1, minWidth: 0 }}>
            <Card>
              <CardHeader title="QR Code Details" />
              <CardContent>
                <Stack spacing={3}>
                  <Field.Text
                    name="destinationUrl"
                    label="Destination URL"
                    placeholder="https://example.com/pay"
                    slotProps={{ inputLabel: { shrink: true } }}
                  />
                  <Field.Text
                    name="label"
                    label="Label (optional)"
                    placeholder="Parking Zone A - Main Street"
                    slotProps={{ inputLabel: { shrink: true } }}
                  />

                  <Divider />

                  <Typography variant="subtitle2" color="text.secondary">
                    Location Binding (optional)
                  </Typography>
                  <Stack direction="row" spacing={2}>
                    <Field.Text
                      name="latitude"
                      label="Latitude"
                      type="number"
                      slotProps={{ inputLabel: { shrink: true } }}
                    />
                    <Field.Text
                      name="longitude"
                      label="Longitude"
                      type="number"
                      slotProps={{ inputLabel: { shrink: true } }}
                    />
                    <Field.Text
                      name="radiusM"
                      label="Radius (m)"
                      type="number"
                      slotProps={{ inputLabel: { shrink: true } }}
                    />
                  </Stack>
                </Stack>
              </CardContent>
            </Card>

            {/* Style picker */}
            <Card>
              <CardHeader title="Appearance" />
              <CardContent>
                <QRStylePicker value={qrStyle} onChange={setQrStyle} />
              </CardContent>
            </Card>

            <Button
              fullWidth
              variant="contained"
              size="large"
              type="submit"
              loading={isSubmitting}
              loadingIndicator="Signing..."
            >
              Generate Signed QR Code
            </Button>
          </Stack>

          {/* Right — Live preview */}
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
                Live Preview
              </Typography>
              <Box ref={qrRef}>
                <QRPreview
                  value={watchedUrl || 'https://vqr.io/v/preview'}
                  style={qrStyle}
                  size={260}
                />
              </Box>
            </Card>
            <Card sx={{ p: 2, mt: 2 }}>
              <QRExportMenu
                containerRef={qrRef}
                captionText={qrStyle.captionText}
                bgColor={qrStyle.bgColor}
              />
            </Card>
          </Box>
        </Stack>
      </Form>
    </>
  );
}
