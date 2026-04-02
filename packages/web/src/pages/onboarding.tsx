import { useState } from 'react';

import Box from '@mui/material/Box';
import Card from '@mui/material/Card';
import Step from '@mui/material/Step';
import Stack from '@mui/material/Stack';
import Button from '@mui/material/Button';
import Stepper from '@mui/material/Stepper';
import StepLabel from '@mui/material/StepLabel';
import TextField from '@mui/material/TextField';
import Container from '@mui/material/Container';
import Typography from '@mui/material/Typography';
import ButtonBase from '@mui/material/ButtonBase';
import CardContent from '@mui/material/CardContent';
import { alpha, useTheme } from '@mui/material/styles';

import { paths } from 'src/routes/paths';
import { useRouter } from 'src/routes/hooks';

import axios, { endpoints } from 'src/lib/axios';

import { useSnackbar } from 'src/components/snackbar';

import { useAuthContext } from 'src/auth/hooks';

// ----------------------------------------------------------------------

const STEPS = ['Organization', 'Use Case', 'First QR Code'];

const USE_CASES = [
  { id: 'MUNICIPALITY', label: 'Municipality', desc: 'Government & public services', icon: '🏛️' },
  { id: 'PARKING', label: 'Parking', desc: 'Parking meters & operators', icon: '🅿️' },
  { id: 'FINANCE', label: 'Finance', desc: 'Banks & financial services', icon: '🏦' },
  { id: 'RESTAURANT', label: 'Restaurant & Retail', desc: 'Menus, payments, storefronts', icon: '🍽️' },
  { id: 'DEVELOPER', label: 'Developer', desc: 'QR auth SDK, API integration', icon: '👩‍💻' },
  { id: 'OTHER', label: 'Other', desc: 'Events, healthcare, logistics', icon: '📦' },
];

export default function OnboardingPage() {
  const router = useRouter();
  const theme = useTheme();
  const { showSuccess, showError } = useSnackbar();
  const { user, checkUserSession } = useAuthContext();

  const [activeStep, setActiveStep] = useState(0);
  const [orgName, setOrgName] = useState((user as any)?.organization?.name || '');
  const [useCase, setUseCase] = useState('');
  const [saving, setSaving] = useState(false);

  // QR creation (step 3)
  const [qrUrl, setQrUrl] = useState('');
  const [qrLabel, setQrLabel] = useState('');
  const [creatingQR, setCreatingQR] = useState(false);

  const handleComplete = async () => {
    setSaving(true);
    try {
      await axios.post(endpoints.onboarding.complete, {
        organizationName: orgName,
        useCase,
      });
      await checkUserSession?.();
      showSuccess('Welcome to vQR!');
      router.push(paths.dashboard.root);
    } catch (err: any) {
      showError(err.message || 'Failed to complete setup');
    } finally {
      setSaving(false);
    }
  };

  const handleCreateQR = async () => {
    if (!qrUrl) {
      showError('Enter a destination URL');
      return;
    }
    setCreatingQR(true);
    try {
      await axios.post(endpoints.qrcodes.create, {
        destinationUrl: qrUrl,
        label: qrLabel || undefined,
      });
      showSuccess('QR code created!');
      handleComplete();
    } catch (err: any) {
      showError(err.message || 'Failed to create QR code');
    } finally {
      setCreatingQR(false);
    }
  };

  const canProceed = () => {
    if (activeStep === 0) return orgName.trim().length >= 2;
    if (activeStep === 1) return !!useCase;
    return true;
  };

  return (
    <Box sx={{ minHeight: '100vh', bgcolor: 'background.default', py: { xs: 4, md: 8 } }}>
      <Container maxWidth="sm">
        {/* Logo */}
        <Box sx={{ textAlign: 'center', mb: 4 }}>
          <Box component="img" src="/logo.svg" alt="vQR" sx={{ width: 56, height: 56, mb: 1 }} />
          <Typography variant="h4" fontWeight={800} color="#1B2A4A">
            Welcome to vQR
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
            Let&apos;s set up your account in 30 seconds
          </Typography>
        </Box>

        {/* Stepper */}
        <Stepper activeStep={activeStep} alternativeLabel sx={{ mb: 4 }}>
          {STEPS.map((label) => (
            <Step key={label}>
              <StepLabel>{label}</StepLabel>
            </Step>
          ))}
        </Stepper>

        <Card>
          <CardContent sx={{ p: 4 }}>
            {/* Step 1: Organization Name */}
            {activeStep === 0 && (
              <Stack spacing={3}>
                <Typography variant="h6" fontWeight={700}>
                  Name your organization
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  This is how your organization will appear to users who scan your QR codes.
                </Typography>
                <TextField
                  label="Organization Name"
                  value={orgName}
                  onChange={(e) => setOrgName(e.target.value)}
                  placeholder="Municipality of Thessaloniki"
                  fullWidth
                  autoFocus
                  slotProps={{ inputLabel: { shrink: true } }}
                />
              </Stack>
            )}

            {/* Step 2: Use Case */}
            {activeStep === 1 && (
              <Stack spacing={3}>
                <Typography variant="h6" fontWeight={700}>
                  What will you use vQR for?
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  This helps us tailor your experience.
                </Typography>
                <Box sx={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 1.5 }}>
                  {USE_CASES.map((uc) => (
                    <ButtonBase
                      key={uc.id}
                      onClick={() => setUseCase(uc.id)}
                      sx={{
                        p: 2,
                        borderRadius: 1.5,
                        textAlign: 'left',
                        flexDirection: 'column',
                        alignItems: 'flex-start',
                        border: '2px solid',
                        borderColor: useCase === uc.id ? 'primary.main' : 'divider',
                        bgcolor:
                          useCase === uc.id
                            ? alpha(theme.palette.primary.main, 0.08)
                            : 'transparent',
                        transition: 'all 0.2s',
                        '&:hover': { bgcolor: alpha(theme.palette.primary.main, 0.04) },
                      }}
                    >
                      <Typography sx={{ fontSize: 28, mb: 0.5 }}>{uc.icon}</Typography>
                      <Typography variant="subtitle2">{uc.label}</Typography>
                      <Typography variant="caption" color="text.secondary">
                        {uc.desc}
                      </Typography>
                    </ButtonBase>
                  ))}
                </Box>
              </Stack>
            )}

            {/* Step 3: First QR Code */}
            {activeStep === 2 && (
              <Stack spacing={3}>
                <Typography variant="h6" fontWeight={700}>
                  Create your first QR code
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Enter a URL you want to protect with vQR verification. You can skip this and
                  create one later.
                </Typography>
                <TextField
                  label="Destination URL"
                  value={qrUrl}
                  onChange={(e) => setQrUrl(e.target.value)}
                  placeholder="https://parking.city.gov/pay"
                  fullWidth
                  slotProps={{ inputLabel: { shrink: true } }}
                />
                <TextField
                  label="Label (optional)"
                  value={qrLabel}
                  onChange={(e) => setQrLabel(e.target.value)}
                  placeholder="Parking Zone A"
                  fullWidth
                  slotProps={{ inputLabel: { shrink: true } }}
                />
              </Stack>
            )}

            {/* Navigation buttons */}
            <Stack direction="row" justifyContent="space-between" sx={{ mt: 4 }}>
              <Button
                variant="text"
                disabled={activeStep === 0}
                onClick={() => setActiveStep((s) => s - 1)}
              >
                Back
              </Button>

              <Stack direction="row" spacing={1}>
                {activeStep === 2 && (
                  <Button
                    variant="outlined"
                    onClick={handleComplete}
                    disabled={saving}
                  >
                    Skip
                  </Button>
                )}

                {activeStep < 2 ? (
                  <Button
                    variant="contained"
                    disabled={!canProceed()}
                    onClick={() => setActiveStep((s) => s + 1)}
                    sx={{ bgcolor: '#1B2A4A', '&:hover': { bgcolor: '#263B66' } }}
                  >
                    Continue
                  </Button>
                ) : (
                  <Button
                    variant="contained"
                    onClick={qrUrl ? handleCreateQR : handleComplete}
                    disabled={saving || creatingQR}
                    sx={{ bgcolor: '#00A76F', '&:hover': { bgcolor: '#007B55' } }}
                  >
                    {saving || creatingQR ? 'Setting up...' : qrUrl ? 'Create & Finish' : 'Finish Setup'}
                  </Button>
                )}
              </Stack>
            </Stack>
          </CardContent>
        </Card>
      </Container>
    </Box>
  );
}
