import type { QRStyle } from 'src/components/qr-code';

import { useRef, useState } from 'react';
import { getContentType } from '@vqr/shared';

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
import { ContentForm } from 'src/components/content-form';
import { ContentTypePicker } from 'src/components/content-type-picker';
import { QRPreview, QRExportMenu, QRStylePicker } from 'src/components/qr-code';

// ----------------------------------------------------------------------

const DEFAULT_STYLE: QRStyle = {
  templateId: 'classic',
  fgColor: '#000000',
  bgColor: '#FFFFFF',
  showLogo: true,
  captionText: 'vQR Verified',
};

// ----------------------------------------------------------------------

function VCardPreview({ content }: { content: Record<string, any> }) {
  const fullName =
    [content.firstName, content.lastName].filter(Boolean).join(' ') || 'Your Name';
  const initial = fullName.charAt(0).toUpperCase();

  return (
    <Box
      sx={{
        fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
        fontSize: 13,
      }}
    >
      {/* Verified bar */}
      <Box
        sx={{
          px: 2,
          py: 1,
          bgcolor: '#00A76F',
          color: 'white',
          display: 'flex',
          alignItems: 'center',
          gap: 1,
          fontSize: 12,
          fontWeight: 600,
        }}
      >
        <span>&#10003;</span> Verified by vQR
      </Box>

      {/* Contact card */}
      <Box sx={{ p: 3, textAlign: 'center' }}>
        {content.photoUrl ? (
          <Box
            component="img"
            src={content.photoUrl}
            sx={{
              width: 64,
              height: 64,
              borderRadius: '50%',
              objectFit: 'cover',
              mx: 'auto',
              mb: 1,
              border: '2px solid #f0f0f0',
            }}
            onError={(e: any) => {
              e.target.style.display = 'none';
            }}
          />
        ) : (
          <Box
            sx={{
              width: 64,
              height: 64,
              borderRadius: '50%',
              mx: 'auto',
              mb: 1,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              bgcolor: '#E3F2FD',
              color: '#0D47A1',
              fontSize: 24,
              fontWeight: 700,
            }}
          >
            {initial}
          </Box>
        )}
        <Typography variant="subtitle1" fontWeight={800} sx={{ color: '#1B2A4A' }}>
          {fullName}
        </Typography>
        {content.title && (
          <Typography variant="caption" color="text.secondary" display="block">
            {content.title}
          </Typography>
        )}
        {content.company && (
          <Typography variant="caption" color="text.secondary" display="block">
            {content.company}
          </Typography>
        )}
        {content.summary && (
          <Typography variant="caption" color="text.secondary" display="block" sx={{ mt: 1 }}>
            {content.summary}
          </Typography>
        )}
      </Box>

      {/* Contact fields */}
      <Box sx={{ px: 2 }}>
        {content.email && (
          <Box
            sx={{
              display: 'flex',
              alignItems: 'center',
              gap: 1.5,
              py: 1.5,
              borderBottom: '1px solid #f5f5f5',
            }}
          >
            <Box
              sx={{
                width: 32,
                height: 32,
                borderRadius: 1,
                bgcolor: '#E3F2FD',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontSize: 14,
              }}
            >
              &#9993;
            </Box>
            <Box>
              <Typography variant="caption" color="text.secondary" display="block">
                Email
              </Typography>
              <Typography variant="body2" sx={{ color: '#0D47A1' }}>
                {content.email}
              </Typography>
            </Box>
          </Box>
        )}
        {content.phone && (
          <Box
            sx={{
              display: 'flex',
              alignItems: 'center',
              gap: 1.5,
              py: 1.5,
              borderBottom: '1px solid #f5f5f5',
            }}
          >
            <Box
              sx={{
                width: 32,
                height: 32,
                borderRadius: 1,
                bgcolor: '#E8F5E9',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontSize: 14,
              }}
            >
              &#9742;
            </Box>
            <Box>
              <Typography variant="caption" color="text.secondary" display="block">
                Phone
              </Typography>
              <Typography variant="body2">{content.phone}</Typography>
            </Box>
          </Box>
        )}
        {content.mobile && (
          <Box
            sx={{
              display: 'flex',
              alignItems: 'center',
              gap: 1.5,
              py: 1.5,
              borderBottom: '1px solid #f5f5f5',
            }}
          >
            <Box
              sx={{
                width: 32,
                height: 32,
                borderRadius: 1,
                bgcolor: '#E8F5E9',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontSize: 14,
              }}
            >
              &#128241;
            </Box>
            <Box>
              <Typography variant="caption" color="text.secondary" display="block">
                Mobile
              </Typography>
              <Typography variant="body2">{content.mobile}</Typography>
            </Box>
          </Box>
        )}
        {content.website && (
          <Box
            sx={{
              display: 'flex',
              alignItems: 'center',
              gap: 1.5,
              py: 1.5,
              borderBottom: '1px solid #f5f5f5',
            }}
          >
            <Box
              sx={{
                width: 32,
                height: 32,
                borderRadius: 1,
                bgcolor: '#FFF3E0',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontSize: 14,
              }}
            >
              &#127760;
            </Box>
            <Box>
              <Typography variant="caption" color="text.secondary" display="block">
                Website
              </Typography>
              <Typography variant="body2" sx={{ color: '#0D47A1' }}>
                {content.website}
              </Typography>
            </Box>
          </Box>
        )}
      </Box>

      {/* Save contact button */}
      <Box sx={{ p: 2, mt: 1 }}>
        <Box
          sx={{
            py: 1.5,
            textAlign: 'center',
            bgcolor: '#1B2A4A',
            color: 'white',
            borderRadius: 1.5,
            fontWeight: 600,
            fontSize: 14,
          }}
        >
          Save Contact
        </Box>
      </Box>

      {/* Footer */}
      <Box
        sx={{
          p: 1.5,
          textAlign: 'center',
          borderTop: '1px solid #f0f0f0',
          fontSize: 10,
          color: '#919eab',
        }}
      >
        Secured by <strong>vQR</strong>
      </Box>
    </Box>
  );
}

// ----------------------------------------------------------------------

export default function QRCodesCreatePage() {
  const router = useRouter();
  const { showSuccess, showError } = useSnackbar();
  const qrRef = useRef<HTMLDivElement>(null);

  // Steps: 'type' → 'content' → 'done'
  const [step, setStep] = useState<'type' | 'content' | 'done'>('type');
  const [selectedType, setSelectedType] = useState<string | null>(null);
  const [contentValues, setContentValues] = useState<Record<string, any>>({});
  const [qrStyle, setQrStyle] = useState<QRStyle>(DEFAULT_STYLE);
  const [createdQR, setCreatedQR] = useState<any>(null);
  const [creating, setCreating] = useState(false);
  const [previewTab, setPreviewTab] = useState<'qr' | 'page'>('qr');

  const typeDef = selectedType ? getContentType(selectedType) : null;

  const handleContentChange = (name: string, value: any) => {
    setContentValues((prev) => ({ ...prev, [name]: value }));
  };

  const handleCreate = async () => {
    if (!selectedType || !typeDef) return;
    setCreating(true);
    try {
      const payload: any = {
        contentType: selectedType,
        label:
          contentValues.label ||
          contentValues.firstName ||
          contentValues.title ||
          contentValues.name ||
          undefined,
      };

      if (selectedType === 'url') {
        payload.destinationUrl = contentValues.destinationUrl;
      } else {
        payload.content = contentValues;
        // For non-URL types, destinationUrl is auto-generated by the API
        payload.destinationUrl = 'https://placeholder.vqr.io'; // API will override
      }

      const res = await axios.post(endpoints.qrcodes.create, payload);
      setCreatedQR(res.data);
      setStep('done');
      showSuccess(`${typeDef.label} QR code created!`);
    } catch (error: any) {
      showError(error.message || 'Failed to create QR code');
    } finally {
      setCreating(false);
    }
  };

  // ---------------------------------------------------------------------------
  // Success state
  // ---------------------------------------------------------------------------
  if (step === 'done' && createdQR) {
    return (
      <>
        <Typography variant="h4" sx={{ mb: 3 }}>
          QR Code Created
        </Typography>
        <Stack direction={{ xs: 'column', md: 'row' }} spacing={3}>
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
            <Stack spacing={1} sx={{ mt: 3 }} alignItems="center">
              <QRExportMenu
                containerRef={qrRef}
                token={createdQR.token}
                captionText={qrStyle.captionText}
                bgColor={qrStyle.bgColor}
              />
            </Stack>
          </Card>
          <Card sx={{ flex: 1 }}>
            <CardHeader title="Details" />
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
                <Box>
                  <Typography variant="subtitle2" color="text.secondary">
                    Transparency Log
                  </Typography>
                  <Typography variant="body1">Entry #{createdQR.transparency_log_index}</Typography>
                </Box>
                <Divider />
                <Stack direction="row" spacing={2}>
                  <Button
                    variant="contained"
                    onClick={() => {
                      setStep('type');
                      setCreatedQR(null);
                      setContentValues({});
                      setSelectedType(null);
                    }}
                  >
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
  // Step 1: Choose content type
  // ---------------------------------------------------------------------------
  if (step === 'type') {
    return (
      <>
        <Typography variant="h4" sx={{ mb: 1 }}>
          Create QR Code
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
          Choose what your QR code will show when scanned
        </Typography>
        <ContentTypePicker
          selected={selectedType}
          onSelect={(id) => {
            setSelectedType(id);
            setContentValues({});
          }}
        />
        <Button
          variant="contained"
          size="large"
          disabled={!selectedType}
          onClick={() => setStep('content')}
          sx={{ mt: 3, bgcolor: '#1B2A4A', '&:hover': { bgcolor: '#263B66' } }}
        >
          Continue
        </Button>
      </>
    );
  }

  // ---------------------------------------------------------------------------
  // Step 2: Fill content + style + create
  // ---------------------------------------------------------------------------
  return (
    <>
      <Box sx={{ mb: 3, display: 'flex', alignItems: 'center', gap: 2 }}>
        <Button variant="text" onClick={() => setStep('type')}>
          ← Back
        </Button>
        <Typography variant="h4">{typeDef?.label || 'Create QR Code'}</Typography>
      </Box>

      <Stack direction={{ xs: 'column', md: 'row' }} spacing={3}>
        {/* Left — Content form + Style */}
        <Stack spacing={3} sx={{ flex: 1, minWidth: 0 }}>
          <Card>
            <CardHeader title="Content" subheader={typeDef?.description} />
            <CardContent>
              {typeDef && (
                <ContentForm
                  fields={typeDef.fields}
                  values={contentValues}
                  onChange={handleContentChange}
                />
              )}
            </CardContent>
          </Card>

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
            onClick={handleCreate}
            loading={creating}
            loadingIndicator="Signing..."
            sx={{ bgcolor: '#00A76F', '&:hover': { bgcolor: '#007B55' } }}
          >
            Generate Signed QR Code
          </Button>
        </Stack>

        {/* Right — Tabbed preview */}
        <Box
          sx={{
            width: { xs: '100%', md: 380 },
            position: { md: 'sticky' },
            top: { md: 88 },
            alignSelf: 'flex-start',
          }}
        >
          <Card>
            <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
              <Stack direction="row" spacing={0}>
                <Button
                  fullWidth
                  variant="text"
                  onClick={() => setPreviewTab('qr')}
                  sx={{
                    py: 1.5,
                    borderRadius: 0,
                    borderBottom: '2px solid',
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
                    py: 1.5,
                    borderRadius: 0,
                    borderBottom: '2px solid',
                    borderColor: previewTab === 'page' ? 'primary.main' : 'transparent',
                    color: previewTab === 'page' ? 'primary.main' : 'text.secondary',
                    fontWeight: previewTab === 'page' ? 700 : 400,
                  }}
                >
                  Page Preview
                </Button>
              </Stack>
            </Box>

            {previewTab === 'qr' ? (
              <Box sx={{ p: 3 }} ref={qrRef}>
                <QRPreview
                  value={
                    contentValues.destinationUrl ||
                    contentValues.website ||
                    'https://vqr.io/v/preview'
                  }
                  style={qrStyle}
                  size={260}
                />
              </Box>
            ) : (
              <Box sx={{ height: 520, overflow: 'auto', bgcolor: '#f5f5f5' }}>
                {selectedType === 'vcard' && contentValues.firstName ? (
                  <VCardPreview content={contentValues} />
                ) : selectedType === 'url' ? (
                  <Box sx={{ p: 3, textAlign: 'center', color: 'text.secondary' }}>
                    <Typography variant="body2">
                      URL QR codes redirect to the destination — no hosted page.
                    </Typography>
                  </Box>
                ) : (
                  <Box sx={{ p: 3, textAlign: 'center', color: 'text.secondary' }}>
                    <Typography variant="body2">Fill in the form to see a live preview</Typography>
                  </Box>
                )}
              </Box>
            )}
          </Card>
        </Box>
      </Stack>
    </>
  );
}
