import Box from '@mui/material/Box';
import Card from '@mui/material/Card';
import Chip from '@mui/material/Chip';
import Grid from '@mui/material/Grid';
import Stack from '@mui/material/Stack';
import Button from '@mui/material/Button';
import Container from '@mui/material/Container';
import Typography from '@mui/material/Typography';
import CardContent from '@mui/material/CardContent';

import { paths } from 'src/routes/paths';
import { RouterLink } from 'src/routes/components';

// Logo component using the proper SVG logo
function VQRLogo({ size = 36 }: { size?: number }) {
  return <Box component="img" src="/logo.svg" alt="vQR" sx={{ width: size, height: size }} />;
}

export default function HomePage() {
  return (
    <Box>
      {/* ============================================================ */}
      {/* NAVBAR */}
      {/* ============================================================ */}
      <Box
        component="header"
        sx={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          zIndex: 1100,
          backdropFilter: 'blur(8px)',
          bgcolor: 'rgba(255,255,255,0.9)',
          borderBottom: '1px solid',
          borderColor: 'divider',
        }}
      >
        <Container maxWidth="lg">
          <Stack
            direction="row"
            alignItems="center"
            justifyContent="space-between"
            sx={{ py: 1.5 }}
          >
            <Stack direction="row" alignItems="center" spacing={1}>
              <VQRLogo size={36} />
              <Typography variant="h6" fontWeight={800} color="#1B2A4A">
                vQR
              </Typography>
            </Stack>
            <Stack direction="row" spacing={1}>
              <Button
                href="#how-it-works"
                color="inherit"
                sx={{ display: { xs: 'none', md: 'inline-flex' } }}
              >
                How It Works
              </Button>
              <Button
                href="#security"
                color="inherit"
                sx={{ display: { xs: 'none', md: 'inline-flex' } }}
              >
                Security
              </Button>
              <Button
                href="#developers"
                color="inherit"
                sx={{ display: { xs: 'none', md: 'inline-flex' } }}
              >
                Developers
              </Button>
              <Button
                href="#pricing"
                color="inherit"
                sx={{ display: { xs: 'none', md: 'inline-flex' } }}
              >
                Pricing
              </Button>
              <Button
                component={RouterLink}
                href={paths.auth.jwt.signIn}
                variant="outlined"
                color="inherit"
                size="small"
              >
                Sign In
              </Button>
              <Button
                component={RouterLink}
                href={paths.auth.jwt.signUp}
                variant="contained"
                size="small"
                sx={{ bgcolor: '#1B2A4A', '&:hover': { bgcolor: '#263B66' } }}
              >
                Get Started
              </Button>
            </Stack>
          </Stack>
        </Container>
      </Box>

      {/* ============================================================ */}
      {/* HERO */}
      {/* ============================================================ */}
      <Box
        sx={{
          pt: { xs: 14, md: 20 },
          pb: { xs: 8, md: 14 },
          background: 'linear-gradient(135deg, #0f1724 0%, #1B2A4A 40%, #263B66 100%)',
          color: 'white',
          position: 'relative',
          overflow: 'hidden',
        }}
      >
        {/* Background grid pattern */}
        <Box
          sx={{
            position: 'absolute',
            inset: 0,
            opacity: 0.03,
            background:
              'repeating-linear-gradient(0deg, transparent, transparent 40px, #fff 40px, #fff 41px), repeating-linear-gradient(90deg, transparent, transparent 40px, #fff 40px, #fff 41px)',
          }}
        />

        <Container maxWidth="lg" sx={{ position: 'relative', zIndex: 1 }}>
          <Grid container spacing={6} alignItems="center">
            <Grid size={{ xs: 12, md: 7 }}>
              <Chip
                label="Now Live — QR-Based Authentication"
                size="small"
                sx={{
                  mb: 3,
                  bgcolor: 'rgba(0,167,111,0.2)',
                  color: '#00A76F',
                  fontWeight: 600,
                  borderRadius: 1,
                }}
              />
              <Typography
                variant="h1"
                sx={{ fontSize: { xs: 36, md: 56 }, fontWeight: 800, lineHeight: 1.1, mb: 3 }}
              >
                The Certificate Authority for{' '}
                <Box component="span" sx={{ color: '#00A76F' }}>
                  Physical QR Codes
                </Box>
              </Typography>
              <Typography
                variant="h6"
                sx={{ mb: 4, fontWeight: 400, opacity: 0.8, maxWidth: 540, lineHeight: 1.6 }}
              >
                Cryptographically signed, geospatially bound, anti-phishing QR code verification.
                Stop scammers from replacing your QR codes with fakes.
              </Typography>
              <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2}>
                <Button
                  component={RouterLink}
                  href={paths.auth.jwt.signUp}
                  variant="contained"
                  size="large"
                  sx={{
                    bgcolor: '#00A76F',
                    px: 4,
                    py: 1.5,
                    fontSize: 16,
                    fontWeight: 700,
                    '&:hover': { bgcolor: '#007B55' },
                  }}
                >
                  Start Free
                </Button>
                <Button
                  href="#developers"
                  variant="outlined"
                  size="large"
                  sx={{
                    color: 'white',
                    borderColor: 'rgba(255,255,255,0.3)',
                    px: 4,
                    py: 1.5,
                    fontSize: 16,
                    '&:hover': { borderColor: 'white', bgcolor: 'rgba(255,255,255,0.05)' },
                  }}
                >
                  View SDK Docs
                </Button>
              </Stack>

              {/* Trust badges */}
              <Stack direction="row" spacing={3} sx={{ mt: 5, opacity: 0.6 }}>
                <Typography variant="caption">ECDSA-P256 Signed</Typography>
                <Typography variant="caption">Transparency Log</Typography>
                <Typography variant="caption">WebAuthn Ready</Typography>
                <Typography variant="caption">SOC 2 Roadmap</Typography>
              </Stack>
            </Grid>

            <Grid
              size={{ xs: 12, md: 5 }}
              sx={{ textAlign: 'center', display: { xs: 'none', md: 'block' } }}
            >
              {/* Hero illustration — stylized QR with shield overlay */}
              <Box
                sx={{
                  width: 340,
                  height: 340,
                  mx: 'auto',
                  borderRadius: 4,
                  bgcolor: 'white',
                  p: 4,
                  boxShadow: '0 40px 80px rgba(0,0,0,0.4)',
                  transform: 'rotate(-3deg)',
                  position: 'relative',
                }}
              >
                <Box
                  sx={{
                    width: '100%',
                    height: '100%',
                    borderRadius: 2,
                    bgcolor: '#f8f9fa',
                    display: 'grid',
                    gridTemplateColumns: 'repeat(7, 1fr)',
                    gap: '6px',
                    p: 2,
                  }}
                >
                  {[
                    1, 1, 1, 0, 1, 1, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0,
                    1, 0, 0, 1, 1, 0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1,
                  ].map((cell, i) => (
                    <Box
                       
                      key={i}
                      sx={{ borderRadius: '3px', bgcolor: cell ? '#1B2A4A' : 'transparent' }}
                    />
                  ))}
                </Box>
                {/* Shield overlay */}
                <Box
                  sx={{
                    position: 'absolute',
                    top: '50%',
                    left: '50%',
                    transform: 'translate(-50%, -50%)',
                    width: 80,
                    height: 80,
                    bgcolor: 'white',
                    borderRadius: 2,
                    p: 1,
                    boxShadow: '0 4px 20px rgba(0,0,0,0.15)',
                  }}
                >
                  <VQRLogo size={72} />
                </Box>
              </Box>
            </Grid>
          </Grid>
        </Container>
      </Box>

      {/* ============================================================ */}
      {/* PROBLEM STATEMENT — Stats bar */}
      {/* ============================================================ */}
      <Box sx={{ py: 6, bgcolor: '#f8f9fa' }}>
        <Container maxWidth="lg">
          <Grid container spacing={4} textAlign="center">
            {[
              {
                stat: '651',
                label: 'Suspects arrested in INTERPOL Operation Red Card (2026)',
              },
              { stat: '$1.87B', label: 'Ticket fraud detection market size' },
              { stat: '29+', label: 'Compromised parking stations in Austin, TX alone' },
              { stat: '0', label: 'Ways to verify a physical QR code — until now' },
            ].map((item) => (
              <Grid key={item.stat} size={{ xs: 6, md: 3 }}>
                <Typography variant="h3" fontWeight={800} color="#1B2A4A">
                  {item.stat}
                </Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
                  {item.label}
                </Typography>
              </Grid>
            ))}
          </Grid>
        </Container>
      </Box>

      {/* ============================================================ */}
      {/* HOW IT WORKS */}
      {/* ============================================================ */}
      <Box id="how-it-works" sx={{ py: { xs: 8, md: 12 } }}>
        <Container maxWidth="lg">
          <Typography variant="h3" textAlign="center" fontWeight={800} sx={{ mb: 2 }}>
            How It Works
          </Typography>
          <Typography
            variant="body1"
            textAlign="center"
            color="text.secondary"
            sx={{ mb: 8, maxWidth: 600, mx: 'auto' }}
          >
            Three steps to make any QR code tamper-proof. No app install required — works with any
            phone camera.
          </Typography>

          <Grid container spacing={4}>
            {[
              {
                step: '01',
                title: 'Register & Sign',
                desc: 'Create QR codes on the vQR platform. Each is signed with your ECDSA-P256 private key and logged to an immutable transparency ledger.',
                color: '#00A76F',
              },
              {
                step: '02',
                title: 'Deploy Physically',
                desc: 'Print and place your vQR codes on parking meters, signage, menus, or terminals. Each code is geospatially bound to its physical location.',
                color: '#0065DB',
              },
              {
                step: '03',
                title: 'Scan & Verify',
                desc: 'Anyone scans with their phone camera. vQR instantly shows: verified issuer, trust score, location match, and fraud detection results.',
                color: '#7635DC',
              },
            ].map((item) => (
              <Grid key={item.step} size={{ xs: 12, md: 4 }}>
                <Card sx={{ height: '100%', border: 'none', boxShadow: 'none', bgcolor: 'transparent' }}>
                  <CardContent sx={{ textAlign: 'center', px: 3 }}>
                    <Typography
                      variant="h1"
                      sx={{
                        fontSize: 64,
                        fontWeight: 900,
                        color: item.color,
                        opacity: 0.15,
                        lineHeight: 1,
                      }}
                    >
                      {item.step}
                    </Typography>
                    <Typography variant="h5" fontWeight={700} sx={{ mt: -2, mb: 2 }}>
                      {item.title}
                    </Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.7 }}>
                      {item.desc}
                    </Typography>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>
        </Container>
      </Box>

      {/* ============================================================ */}
      {/* SECURITY MODEL */}
      {/* ============================================================ */}
      <Box id="security" sx={{ py: { xs: 8, md: 12 }, bgcolor: '#0f1724', color: 'white' }}>
        <Container maxWidth="lg">
          <Typography variant="h3" textAlign="center" fontWeight={800} sx={{ mb: 2 }}>
            Four Tiers of Security
          </Typography>
          <Typography
            variant="body1"
            textAlign="center"
            sx={{ mb: 8, color: 'rgba(255,255,255,0.8)', maxWidth: 600, mx: 'auto' }}
          >
            Progressive security that starts automatically and gets stronger over time. Each tier
            builds on the previous.
          </Typography>

          <Grid container spacing={3}>
            {[
              {
                tier: 'Tier 1',
                title: 'Cryptographic Signing',
                desc: 'Every QR code is signed with ECDSA-P256. Verification happens in milliseconds at the edge. Defeats: unregistered fake QR codes.',
                tag: 'Automatic',
                color: '#00A76F',
              },
              {
                tier: 'Tier 2',
                title: 'Ephemeral Visual Proof',
                desc: 'Server-generated verification image with your location, device, timestamp, and a unique visual fingerprint. Cannot be cloned.',
                tag: 'Automatic',
                color: '#0065DB',
              },
              {
                tier: 'Tier 3',
                title: 'Anti-Proxy Detection',
                desc: 'TLS fingerprinting (JA3/JA4), latency analysis, and canvas fingerprinting detect real-time page cloning and MitM proxying.',
                tag: 'Automatic',
                color: '#FFAB00',
              },
              {
                tier: 'Tier 4',
                title: 'WebAuthn Passkeys',
                desc: 'Hardware-backed, origin-bound authentication. A passkey for vqr.io physically cannot activate on a phishing domain. Unphishable.',
                tag: 'One-time setup',
                color: '#FF5630',
              },
            ].map((item) => (
              <Grid key={item.tier} size={{ xs: 12, sm: 6 }}>
                <Card
                  sx={{
                    bgcolor: 'rgba(255,255,255,0.05)',
                    border: '1px solid rgba(255,255,255,0.08)',
                    height: '100%',
                  }}
                >
                  <CardContent sx={{ p: 3 }}>
                    <Stack
                      direction="row"
                      justifyContent="space-between"
                      alignItems="center"
                      sx={{ mb: 2 }}
                    >
                      <Typography variant="overline" sx={{ color: item.color, fontWeight: 700 }}>
                        {item.tier}
                      </Typography>
                      <Chip
                        label={item.tag}
                        size="small"
                        sx={{
                          bgcolor: 'rgba(255,255,255,0.08)',
                          color: 'rgba(255,255,255,0.7)',
                        }}
                      />
                    </Stack>
                    <Typography variant="h6" fontWeight={700} sx={{ mb: 1 }}>
                      {item.title}
                    </Typography>
                    <Typography variant="body2" sx={{ color: 'rgba(255,255,255,0.85)', lineHeight: 1.7 }}>
                      {item.desc}
                    </Typography>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>
        </Container>
      </Box>

      {/* ============================================================ */}
      {/* FOR DEVELOPERS — SDK */}
      {/* ============================================================ */}
      <Box id="developers" sx={{ py: { xs: 8, md: 12 } }}>
        <Container maxWidth="lg">
          <Grid container spacing={6} alignItems="center">
            <Grid size={{ xs: 12, md: 6 }}>
              <Chip
                label="For Developers"
                size="small"
                sx={{ mb: 2, bgcolor: '#E3F2FD', color: '#0065DB', fontWeight: 600 }}
              />
              <Typography variant="h3" fontWeight={800} sx={{ mb: 2 }}>
                QR-Based Auth
                <br />
                in 5 Lines of Code
              </Typography>
              <Typography variant="body1" color="text.secondary" sx={{ mb: 3, lineHeight: 1.7 }}>
                Add passwordless QR authentication to any website. Users scan a QR code instead of
                typing passwords. Cryptographically signed proof returned via real-time events.
              </Typography>
              <Stack spacing={1.5}>
                {[
                  'OAuth providers: Google, GitHub, Microsoft, Apple',
                  'Real-time SSE events: scanned → approved → done',
                  'ECDSA-P256 signature on every authentication',
                  'Works on any website — just a <script> tag',
                  'Login metadata: IP, geo, device, fingerprint',
                ].map((feature) => (
                  <Stack key={feature} direction="row" spacing={1.5} alignItems="flex-start">
                    <Box
                      sx={{
                        width: 20,
                        height: 20,
                        borderRadius: '50%',
                        bgcolor: '#E8F5E9',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        flexShrink: 0,
                        mt: 0.3,
                      }}
                    >
                      <Typography sx={{ fontSize: 12, color: '#00A76F' }}>&#10003;</Typography>
                    </Box>
                    <Typography variant="body2">{feature}</Typography>
                  </Stack>
                ))}
              </Stack>
            </Grid>

            <Grid size={{ xs: 12, md: 6 }}>
              <Box
                component="pre"
                sx={{
                  bgcolor: '#1B2A4A',
                  borderRadius: 3,
                  p: 3,
                  fontFamily: 'monospace',
                  fontSize: 13,
                  lineHeight: 1.8,
                  color: '#e0e0e0',
                  overflow: 'auto',
                  boxShadow: '0 20px 40px rgba(0,0,0,0.15)',
                  m: 0,
                  whiteSpace: 'pre-wrap',
                }}
                 
                dangerouslySetInnerHTML={{
                  __html: [
                    '<span style="color:#637381">&lt;!-- Add to any website --&gt;</span>',
                    '<span style="color:#00A76F">&lt;div</span> <span style="color:#FFAB00">id</span>=<span style="color:#FF8A65">&quot;vqr-auth&quot;</span><span style="color:#00A76F">&gt;&lt;/div&gt;</span>',
                    '<span style="color:#00A76F">&lt;script</span> <span style="color:#FFAB00">src</span>=<span style="color:#FF8A65">&quot;https://vqr.progressnet.io/sdk/vqr-auth.js&quot;</span><span style="color:#00A76F">&gt;&lt;/script&gt;</span>',
                    '',
                    '<span style="color:#00A76F">&lt;script&gt;</span>',
                    '  <span style="color:#7C4DFF">new</span> <span style="color:#FFAB00">VQRAuth</span>({',
                    "    clientId: <span style=\"color:#FF8A65\">'vqr_app_xxx'</span>,",
                    "    clientSecret: <span style=\"color:#FF8A65\">'vqr_secret_xxx'</span>,",
                    "    element: <span style=\"color:#FF8A65\">'#vqr-auth'</span>,",
                    '    <span style="color:#00A76F">onSuccess</span>: (result) =&gt; {',
                    '      console.log(result.user);  <span style="color:#637381">// &#123; name, email &#125;</span>',
                    '      console.log(result.signature); <span style="color:#637381">// ECDSA proof</span>',
                    '    }',
                    '  });',
                    '<span style="color:#00A76F">&lt;/script&gt;</span>',
                  ].join('\n'),
                }}
              />
            </Grid>
          </Grid>
        </Container>
      </Box>

      {/* ============================================================ */}
      {/* USE CASES */}
      {/* ============================================================ */}
      <Box sx={{ py: { xs: 8, md: 12 }, bgcolor: '#f8f9fa' }}>
        <Container maxWidth="lg">
          <Typography variant="h3" textAlign="center" fontWeight={800} sx={{ mb: 8 }}>
            Built For
          </Typography>
          <Grid container spacing={3}>
            {[
              {
                icon: '🏛️',
                title: 'Municipalities',
                desc: 'Protect parking meters, government signage, and public service QR codes from tampering.',
              },
              {
                icon: '🅿️',
                title: 'Parking Operators',
                desc: 'Secure payment QR codes across thousands of locations. Real-time fraud alerts.',
              },
              {
                icon: '🏦',
                title: 'Financial Institutions',
                desc: 'ATM QR codes, branch signage, and payment terminals with cryptographic verification.',
              },
              {
                icon: '🍽️',
                title: 'Restaurants & Retail',
                desc: 'Verified menu and payment QR codes. Customers scan with confidence.',
              },
              {
                icon: '🎫',
                title: 'Event Organizers',
                desc: 'Tamper-proof ticket verification. Prevent counterfeiting and duplicate scans.',
              },
              {
                icon: '👩‍💻',
                title: 'Developers',
                desc: 'Add QR-based authentication to any app. SDK, REST API, OAuth providers, webhooks.',
              },
            ].map((item) => (
              <Grid key={item.title} size={{ xs: 12, sm: 6, md: 4 }}>
                <Card sx={{ height: '100%' }}>
                  <CardContent sx={{ p: 3 }}>
                    <Typography sx={{ fontSize: 36, mb: 1 }}>{item.icon}</Typography>
                    <Typography variant="h6" fontWeight={700} sx={{ mb: 1 }}>
                      {item.title}
                    </Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.7 }}>
                      {item.desc}
                    </Typography>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>
        </Container>
      </Box>

      {/* ============================================================ */}
      {/* PRICING */}
      {/* ============================================================ */}
      <Box id="pricing" sx={{ py: { xs: 8, md: 12 } }}>
        <Container maxWidth="md">
          <Typography variant="h3" textAlign="center" fontWeight={800} sx={{ mb: 2 }}>
            Simple Pricing
          </Typography>
          <Typography
            variant="body1"
            textAlign="center"
            color="text.secondary"
            sx={{ mb: 8 }}
          >
            Start free. Scale as you grow.
          </Typography>

          <Grid container spacing={3}>
            {[
              {
                plan: 'Free',
                price: '$0',
                period: 'forever',
                features: [
                  '50 QR codes',
                  'Basic verification',
                  '1,000 auth sessions/mo',
                  'Community support',
                ],
                cta: 'Get Started',
                featured: false,
              },
              {
                plan: 'Pro',
                price: '$49',
                period: '/month',
                features: [
                  'Unlimited QR codes',
                  'Geo binding + fraud alerts',
                  '50,000 auth sessions/mo',
                  'Custom branding',
                  'Analytics dashboard',
                  'Priority support',
                ],
                cta: 'Start Pro Trial',
                featured: true,
              },
              {
                plan: 'Enterprise',
                price: 'Custom',
                period: '',
                features: [
                  'Everything in Pro',
                  'Unlimited auth sessions',
                  'SLA + dedicated support',
                  'SSO / SAML',
                  'On-premise option',
                  'White-label verification',
                ],
                cta: 'Contact Sales',
                featured: false,
              },
            ].map((item) => (
              <Grid key={item.plan} size={{ xs: 12, md: 4 }}>
                <Card
                  sx={{
                    height: '100%',
                    border: item.featured ? '2px solid #00A76F' : '1px solid',
                    borderColor: item.featured ? '#00A76F' : 'divider',
                    position: 'relative',
                    ...(item.featured && { boxShadow: '0 12px 24px rgba(0,167,111,0.15)' }),
                  }}
                >
                  {item.featured && (
                    <Chip
                      label="Most Popular"
                      size="small"
                      sx={{
                        position: 'absolute',
                        top: -12,
                        left: '50%',
                        transform: 'translateX(-50%)',
                        bgcolor: '#00A76F',
                        color: 'white',
                        fontWeight: 700,
                      }}
                    />
                  )}
                  <CardContent sx={{ p: 4, textAlign: 'center' }}>
                    <Typography variant="h6" fontWeight={700}>
                      {item.plan}
                    </Typography>
                    <Typography variant="h2" fontWeight={800} sx={{ my: 2 }}>
                      {item.price}
                      {item.period && (
                        <Typography component="span" variant="body2" color="text.secondary">
                          {item.period}
                        </Typography>
                      )}
                    </Typography>
                    <Stack spacing={1.5} sx={{ mb: 3, textAlign: 'left' }}>
                      {item.features.map((f) => (
                        <Stack key={f} direction="row" spacing={1} alignItems="center">
                          <Typography sx={{ color: '#00A76F', fontSize: 14 }}>&#10003;</Typography>
                          <Typography variant="body2">{f}</Typography>
                        </Stack>
                      ))}
                    </Stack>
                    <Button
                      component={RouterLink}
                      href={paths.auth.jwt.signUp}
                      fullWidth
                      variant={item.featured ? 'contained' : 'outlined'}
                      sx={
                        item.featured
                          ? { bgcolor: '#00A76F', '&:hover': { bgcolor: '#007B55' } }
                          : { color: '#1B2A4A', borderColor: '#1B2A4A' }
                      }
                    >
                      {item.cta}
                    </Button>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>
        </Container>
      </Box>

      {/* ============================================================ */}
      {/* CTA */}
      {/* ============================================================ */}
      <Box
        sx={{ py: { xs: 8, md: 12 }, bgcolor: '#1B2A4A', color: 'white', textAlign: 'center' }}
      >
        <Container maxWidth="sm">
          <Box sx={{ mx: 'auto', mb: 3, width: 64, height: 64 }}>
            <VQRLogo size={64} />
          </Box>
          <Typography variant="h3" fontWeight={800} sx={{ mb: 2 }}>
            Ready to Secure Your QR Codes?
          </Typography>
          <Typography variant="body1" sx={{ mb: 4, opacity: 0.7 }}>
            Join municipalities and enterprises that trust vQR to protect their physical QR
            infrastructure.
          </Typography>
          <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2} justifyContent="center">
            <Button
              component={RouterLink}
              href={paths.auth.jwt.signUp}
              variant="contained"
              size="large"
              sx={{
                bgcolor: '#00A76F',
                px: 5,
                py: 1.5,
                fontSize: 16,
                fontWeight: 700,
                '&:hover': { bgcolor: '#007B55' },
              }}
            >
              Create Free Account
            </Button>
            <Button
              href="https://vqr.progressnet.io/sdk/demo.html"
              target="_blank"
              variant="outlined"
              size="large"
              sx={{
                color: 'white',
                borderColor: 'rgba(255,255,255,0.3)',
                px: 5,
                py: 1.5,
                fontSize: 16,
                '&:hover': { borderColor: 'white' },
              }}
            >
              Try the SDK Demo
            </Button>
          </Stack>
        </Container>
      </Box>

      {/* ============================================================ */}
      {/* FOOTER */}
      {/* ============================================================ */}
      <Box sx={{ py: 4, borderTop: '1px solid', borderColor: 'divider' }}>
        <Container maxWidth="lg">
          <Stack
            direction={{ xs: 'column', md: 'row' }}
            justifyContent="space-between"
            alignItems="center"
            spacing={2}
          >
            <Stack direction="row" alignItems="center" spacing={1}>
              <VQRLogo size={24} />
              <Typography variant="body2" color="text.secondary">
                vQR — Verified QR Code Security Platform
              </Typography>
            </Stack>
            <Typography variant="caption" color="text.disabled">
              Built with the conviction that every QR code in the physical world should be
              verifiable.
            </Typography>
          </Stack>
        </Container>
      </Box>
    </Box>
  );
}
