import type { QRStyle } from 'src/components/qr-code';

import { useRef, useState } from 'react';
import { getContentType } from '@qrauth/shared';

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

import { paths } from 'src/routes/paths';
import { useRouter } from 'src/routes/hooks';

import { formatDateTime } from 'src/utils/format-date';

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
  captionText: 'QRAuth Verified',
};

// ----------------------------------------------------------------------

export function PreviewVerifyBar() {
  return (
    <Box sx={{ px: 2, py: 1, bgcolor: '#00A76F', color: 'white', display: 'flex', alignItems: 'center', gap: 1, fontSize: 12, fontWeight: 600 }}>
      <span>&#10003;</span> Verified by QRAuth
    </Box>
  );
}

export function PreviewFooter() {
  return (
    <Box sx={{ p: 1.5, textAlign: 'center', borderTop: '1px solid #f0f0f0', fontSize: 10, color: '#919eab' }}>
      Secured by <strong>QRAuth</strong>
    </Box>
  );
}

export function PreviewFieldRow({ icon, iconBg, label, value }: { icon: string; iconBg: string; label: string; value: string }) {
  return (
    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, py: 1.5, borderBottom: '1px solid #f5f5f5', px: 2 }}>
      <Box sx={{ width: 32, height: 32, borderRadius: 1, bgcolor: iconBg, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 14, flexShrink: 0 }}>
        {icon}
      </Box>
      <Box sx={{ minWidth: 0 }}>
        <Typography variant="caption" color="text.secondary" display="block">{label}</Typography>
        <Typography variant="body2" noWrap>{value}</Typography>
      </Box>
    </Box>
  );
}

export function ContentPagePreview({ type, content }: { type: string; content: Record<string, any> }) {
  switch (type) {
    case 'url':
      return (
        <Box>
          <PreviewVerifyBar />
          <Box sx={{ p: 3 }}>
            {content.destinationUrl ? (
              <>
                <Box sx={{ p: 2, bgcolor: '#f8f9fa', borderRadius: 1, mb: 2, wordBreak: 'break-all', fontSize: 13, color: '#0D47A1' }}>
                  {content.destinationUrl}
                </Box>
                <Box sx={{ py: 1.5, textAlign: 'center', bgcolor: '#00A76F', color: 'white', borderRadius: 1.5, fontWeight: 600, fontSize: 14 }}>
                  Continue to {(() => { try { return new URL(content.destinationUrl).hostname; } catch { return 'website'; } })()}
                </Box>
              </>
            ) : (
              <Typography variant="body2" color="text.secondary" textAlign="center">Enter a URL to see preview</Typography>
            )}
          </Box>
          <PreviewFooter />
        </Box>
      );

    case 'vcard': {
      const fullName = [content.firstName, content.lastName].filter(Boolean).join(' ') || 'Your Name';
      return (
        <Box>
          <PreviewVerifyBar />
          <Box sx={{ p: 3, textAlign: 'center' }}>
            <Box sx={{ width: 64, height: 64, borderRadius: '50%', mx: 'auto', mb: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', bgcolor: '#E3F2FD', color: '#0D47A1', fontSize: 24, fontWeight: 700 }}>
              {fullName.charAt(0).toUpperCase()}
            </Box>
            <Typography variant="subtitle1" fontWeight={800} sx={{ color: '#1B2A4A' }}>{fullName}</Typography>
            {content.title && <Typography variant="caption" color="text.secondary" display="block">{content.title}</Typography>}
            {content.company && <Typography variant="caption" color="text.secondary" display="block">{content.company}</Typography>}
          </Box>
          {content.email && <PreviewFieldRow icon="&#9993;" iconBg="#E3F2FD" label="Email" value={content.email} />}
          {content.phone && <PreviewFieldRow icon="&#9742;" iconBg="#E8F5E9" label="Phone" value={content.phone} />}
          {content.website && <PreviewFieldRow icon="&#127760;" iconBg="#FFF3E0" label="Website" value={content.website} />}
          <Box sx={{ p: 2 }}>
            <Box sx={{ py: 1.5, textAlign: 'center', bgcolor: '#1B2A4A', color: 'white', borderRadius: 1.5, fontWeight: 600, fontSize: 14 }}>Save Contact</Box>
          </Box>
          <PreviewFooter />
        </Box>
      );
    }

    case 'coupon':
      return (
        <Box>
          <PreviewVerifyBar />
          {content.imageUrl && <Box component="img" src={content.imageUrl} sx={{ width: '100%', height: 140, objectFit: 'cover' }} onError={(e: any) => { e.target.style.display = 'none'; }} />}
          <Box sx={{ p: 3, textAlign: 'center' }}>
            {content.discountBadge && <Box sx={{ display: 'inline-block', px: 2, py: 0.5, bgcolor: '#FF5630', color: 'white', borderRadius: 1, fontWeight: 700, fontSize: 14, mb: 1 }}>{content.discountBadge}</Box>}
            <Typography variant="h6" fontWeight={800} sx={{ color: '#1B2A4A' }}>{content.headline || 'Your Offer'}</Typography>
            {content.company && <Typography variant="caption" color="text.secondary" display="block">{content.company}</Typography>}
            {content.description && <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>{content.description}</Typography>}
            {content.expiresAt && <Typography variant="caption" color="error.main" display="block" sx={{ mt: 1 }}>Expires: {formatDateTime(content.expiresAt)}</Typography>}
          </Box>
          {content.redemptionUrl && (
            <Box sx={{ px: 2, pb: 2 }}>
              <Box sx={{ py: 1.5, textAlign: 'center', bgcolor: '#FF5630', color: 'white', borderRadius: 1.5, fontWeight: 600, fontSize: 14 }}>GET COUPON</Box>
            </Box>
          )}
          <PreviewFooter />
        </Box>
      );

    case 'event':
      return (
        <Box>
          <PreviewVerifyBar />
          {content.imageUrl && <Box component="img" src={content.imageUrl} sx={{ width: '100%', height: 140, objectFit: 'cover' }} onError={(e: any) => { e.target.style.display = 'none'; }} />}
          <Box sx={{ p: 3 }}>
            <Typography variant="h6" fontWeight={800} sx={{ color: '#1B2A4A' }}>{content.title || 'Event Title'}</Typography>
            {content.organizer && <Typography variant="caption" color="text.secondary" display="block">by {content.organizer}</Typography>}
            {content.description && <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>{content.description}</Typography>}
          </Box>
          {content.startDate && <PreviewFieldRow icon="&#128197;" iconBg="#E3F2FD" label="When" value={formatDateTime(content.startDate)} />}
          {content.location && <PreviewFieldRow icon="&#128205;" iconBg="#F3E5F5" label="Where" value={`${content.location}${content.address ? `, ${content.address}` : ''}`} />}
          {content.contactEmail && <PreviewFieldRow icon="&#9993;" iconBg="#E3F2FD" label="Contact" value={content.contactEmail} />}
          <Box sx={{ px: 2, py: 2 }}>
            <Box sx={{ py: 1.5, textAlign: 'center', bgcolor: '#0065DB', color: 'white', borderRadius: 1.5, fontWeight: 600, fontSize: 14 }}>Add to Calendar</Box>
          </Box>
          <PreviewFooter />
        </Box>
      );

    case 'pdf':
      return (
        <Box>
          <PreviewVerifyBar />
          <Box sx={{ p: 3, textAlign: 'center' }}>
            <Box sx={{ fontSize: 48, mb: 1 }}>&#128196;</Box>
            <Typography variant="h6" fontWeight={800} sx={{ color: '#1B2A4A' }}>{content.title || 'Document'}</Typography>
            {content.description && <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>{content.description}</Typography>}
          </Box>
          <Box sx={{ px: 2, pb: 2 }}>
            <Box sx={{ py: 1.5, textAlign: 'center', bgcolor: '#1B2A4A', color: 'white', borderRadius: 1.5, fontWeight: 600, fontSize: 14 }}>View PDF</Box>
          </Box>
          <PreviewFooter />
        </Box>
      );


    case 'feedback':
      return (
        <Box>
          <PreviewVerifyBar />
          <Box sx={{ p: 3, textAlign: 'center' }}>
            <Typography variant="h6" fontWeight={800} sx={{ color: '#1B2A4A' }}>{content.title || 'How was your experience?'}</Typography>
            {content.description && <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>{content.description}</Typography>}
            <Stack direction="row" spacing={1} justifyContent="center" sx={{ mt: 2 }}>
              {[1, 2, 3, 4, 5].map((star) => (
                <Box key={star} sx={{ fontSize: 32, color: '#FFAB00' }}>&#9733;</Box>
              ))}
            </Stack>
          </Box>
          <Box sx={{ px: 2 }}>
            {content.collectName && (
              <Box sx={{ mb: 1, p: 1.5, bgcolor: '#f8f9fa', borderRadius: 1, fontSize: 13, color: '#919eab' }}>Your name</Box>
            )}
            {content.collectEmail && (
              <Box sx={{ mb: 1, p: 1.5, bgcolor: '#f8f9fa', borderRadius: 1, fontSize: 13, color: '#919eab' }}>Your email</Box>
            )}
            {content.collectPhone && (
              <Box sx={{ mb: 1, p: 1.5, bgcolor: '#f8f9fa', borderRadius: 1, fontSize: 13, color: '#919eab' }}>Your phone</Box>
            )}
            <Box sx={{ mb: 2, p: 1.5, bgcolor: '#f8f9fa', borderRadius: 1, fontSize: 13, color: '#919eab' }}>
              Leave a comment...
            </Box>
            <Box sx={{ py: 1.5, mb: 2, textAlign: 'center', bgcolor: '#00A76F', color: 'white', borderRadius: 1.5, fontWeight: 600, fontSize: 14 }}>Submit Feedback</Box>
          </Box>
          <PreviewFooter />
        </Box>
      );

    default:
      return (
        <Box sx={{ p: 3, textAlign: 'center', color: 'text.secondary' }}>
          <Typography variant="body2">Preview not available for this type yet</Typography>
        </Box>
      );
  }
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
        // Strip location fields (prefixed with _) from content before sending
        const content: Record<string, any> = {};
        for (const [key, val] of Object.entries(contentValues)) {
          if (!key.startsWith('_')) content[key] = val;
        }
        payload.content = content;
      }

      // Location binding
      if (contentValues._latitude && contentValues._longitude) {
        payload.location = {
          lat: parseFloat(contentValues._latitude),
          lng: parseFloat(contentValues._longitude),
          radiusM: parseFloat(contentValues._radiusM) || 50,
        };
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
            <CardHeader
              title="Location Binding"
              subheader="Optional — bind this QR code to a physical location"
            />
            <CardContent>
              <Stack direction="row" spacing={2}>
                <TextField
                  label="Latitude"
                  type="number"
                  value={contentValues._latitude || ''}
                  onChange={(e) => handleContentChange('_latitude', e.target.value)}
                  fullWidth
                  size="small"
                  placeholder="40.6321"
                  slotProps={{ inputLabel: { shrink: true } }}
                />
                <TextField
                  label="Longitude"
                  type="number"
                  value={contentValues._longitude || ''}
                  onChange={(e) => handleContentChange('_longitude', e.target.value)}
                  fullWidth
                  size="small"
                  placeholder="22.9414"
                  slotProps={{ inputLabel: { shrink: true } }}
                />
                <TextField
                  label="Radius (m)"
                  type="number"
                  value={contentValues._radiusM || 50}
                  onChange={(e) => handleContentChange('_radiusM', e.target.value)}
                  fullWidth
                  size="small"
                  slotProps={{ inputLabel: { shrink: true } }}
                />
              </Stack>
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

            {/* QR — always rendered for export ref, hidden when on page tab */}
            <Box sx={{ p: 3, display: previewTab === 'qr' ? 'block' : 'none' }} ref={qrRef}>
              <QRPreview
                value={contentValues.destinationUrl || contentValues.website || 'https://qrauth.io/v/preview'}
                style={qrStyle}
                size={260}
              />
            </Box>
            {previewTab === 'page' && (
              <Box sx={{ height: 520, overflow: 'auto', bgcolor: '#f5f5f5' }}>
                <ContentPagePreview type={selectedType || 'url'} content={contentValues} />
              </Box>
            )}
          </Card>
        </Box>
      </Stack>
    </>
  );
}
