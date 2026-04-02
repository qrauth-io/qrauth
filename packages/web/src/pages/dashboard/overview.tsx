import { useState, useEffect } from 'react';

import Box from '@mui/material/Box';
import Card from '@mui/material/Card';
import Grid from '@mui/material/Grid';
import Chip from '@mui/material/Chip';
import Stack from '@mui/material/Stack';
import Table from '@mui/material/Table';
import TableRow from '@mui/material/TableRow';
import TableBody from '@mui/material/TableBody';
import TableCell from '@mui/material/TableCell';
import TableHead from '@mui/material/TableHead';
import Typography from '@mui/material/Typography';
import CardHeader from '@mui/material/CardHeader';
import CardContent from '@mui/material/CardContent';
import TableContainer from '@mui/material/TableContainer';
import LinearProgress from '@mui/material/LinearProgress';

import { formatDateTime } from 'src/utils/format-date';

import axios, { endpoints } from 'src/lib/axios';

import { Iconify } from 'src/components/iconify';
import { useSnackbar } from 'src/components/snackbar';
import { Chart, useChart } from 'src/components/chart';

// ----------------------------------------------------------------------

type Summary = {
  totalQRCodes: number;
  totalScans: number;
  scansLast7d: number;
  scansLast30d: number;
  activeFraudIncidents: number;
  avgTrustScore: number | null;
};

type RecentScan = {
  id: string;
  trustScore: number;
  proxyDetected: boolean;
  createdAt: string;
  qrCode: { token: string; label: string | null };
};

type QRCodeItem = {
  id: string;
  token: string;
  label: string | null;
  status: string;
  _count?: { scans: number };
};

// Stat card component
function StatCard({
  title,
  value,
  icon,
  color = 'primary',
}: {
  title: string;
  value: string | number;
  icon: 'solar:list-bold' | 'solar:eye-bold' | 'solar:chart-square-outline' | 'solar:danger-triangle-bold' | 'solar:shield-check-bold';
  color?: 'primary' | 'info' | 'warning' | 'error' | 'success';
}) {
  return (
    <Card>
      <CardContent sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
        <Box
          sx={{
            width: 56,
            height: 56,
            borderRadius: 1.5,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            bgcolor: (theme) => `${theme.palette[color].main}14`,
            color: `${color}.main`,
          }}
        >
          <Iconify icon={icon} width={28} />
        </Box>
        <Box>
          <Typography variant="subtitle2" color="text.secondary">{title}</Typography>
          <Typography variant="h4">{value}</Typography>
        </Box>
      </CardContent>
    </Card>
  );
}

export default function OverviewPage() {
  const { showError } = useSnackbar();
  const [stats, setStats] = useState<Summary | null>(null);
  const [recentScans, setRecentScans] = useState<RecentScan[]>([]);
  const [topQRCodes, setTopQRCodes] = useState<QRCodeItem[]>([]);
  const [fraudRuleCount, setFraudRuleCount] = useState(0);

  useEffect(() => {
    // Fetch all in parallel
    Promise.all([
      axios.get(endpoints.analytics.summary),
      axios.get(endpoints.analytics.scans, { params: { page: 1, pageSize: 8 } }),
      axios.get(endpoints.qrcodes.list, { params: { page: 1, pageSize: 5 } }),
    ])
      .then(([summaryRes, scansRes, qrRes]) => {
        setStats(summaryRes.data);
        setRecentScans(scansRes.data.data ?? []);
        setTopQRCodes(qrRes.data.data ?? []);
      })
      .catch((err: any) => showError(err.message || 'Failed to load dashboard'));

    axios
      .get(endpoints.analytics.fraudRules)
      .then((r) =>
        setFraudRuleCount((r.data.data || []).filter((rule: any) => rule.enabled).length)
      )
      .catch(() => {});
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Trust score gauge chart
  const trustChartOptions = useChart({
    chart: { sparkline: { enabled: true } },
    plotOptions: {
      radialBar: {
        hollow: { size: '68%' },
        track: { margin: 0 },
        dataLabels: {
          name: { show: true, offsetY: -10, fontSize: '13px' },
          value: { show: true, offsetY: 6, fontSize: '28px', fontWeight: 700 },
        },
      },
    },
    labels: ['Trust Score'],
    colors: [
      stats?.avgTrustScore != null && stats.avgTrustScore >= 80
        ? '#00A76F'
        : stats?.avgTrustScore != null && stats.avgTrustScore >= 50
          ? '#FFAB00'
          : '#FF5630',
    ],
  });

  // Scans sparkline (fake data based on 7d vs 30d ratio for visual)
  const scans7d = stats?.scansLast7d ?? 0;
  const scans30d = stats?.scansLast30d ?? 0;
  const scansOlder = scans30d - scans7d;

  const scanBarOptions = useChart({
    chart: { sparkline: { enabled: true } },
    plotOptions: { bar: { borderRadius: 3, columnWidth: '60%' } },
    xaxis: { categories: ['Older', 'Last 7d'] },
    tooltip: { y: { formatter: (v: number) => `${v} scans` } },
  });

  return (
    <>
      <Typography variant="h4" sx={{ mb: 3 }}>Dashboard</Typography>

      {/* Stat cards */}
      <Grid container spacing={3} sx={{ mb: 3 }}>
        <Grid size={{ xs: 12, sm: 6, md: 3 }}>
          <StatCard
            title="Total QR Codes"
            value={stats?.totalQRCodes ?? '—'}
            icon="solar:list-bold"
            color="primary"
          />
        </Grid>
        <Grid size={{ xs: 12, sm: 6, md: 3 }}>
          <StatCard
            title="Total Scans"
            value={stats?.totalScans ?? '—'}
            icon="solar:eye-bold"
            color="info"
          />
        </Grid>
        <Grid size={{ xs: 12, sm: 6, md: 3 }}>
          <StatCard
            title="Scans (7d)"
            value={stats?.scansLast7d ?? '—'}
            icon="solar:chart-square-outline"
            color="success"
          />
        </Grid>
        <Grid size={{ xs: 12, sm: 6, md: 3 }}>
          <StatCard
            title="Fraud Alerts"
            value={stats?.activeFraudIncidents ?? '—'}
            icon="solar:danger-triangle-bold"
            color={stats?.activeFraudIncidents ? 'error' : 'success'}
          />
        </Grid>
      </Grid>

      <Grid container spacing={3}>
        {/* Trust Score Gauge */}
        <Grid size={{ xs: 12, md: 4 }}>
          <Card sx={{ height: '100%' }}>
            <CardHeader title="Avg Trust Score" />
            <CardContent sx={{ display: 'flex', justifyContent: 'center', pt: 2 }}>
              {stats?.avgTrustScore != null ? (
                <Chart
                  type="radialBar"
                  series={[stats.avgTrustScore]}
                  options={trustChartOptions}
                  sx={{ width: 240, height: 240 }}
                />
              ) : (
                <Typography color="text.secondary" sx={{ py: 8 }}>No data yet</Typography>
              )}
            </CardContent>
          </Card>
        </Grid>

        {/* Scan Volume */}
        <Grid size={{ xs: 12, md: 8 }}>
          <Card sx={{ height: '100%' }}>
            <CardHeader title="Scan Volume" subheader="Last 30 days vs previous" />
            <CardContent>
              {scans30d > 0 ? (
                <Chart
                  type="bar"
                  series={[{ name: 'Scans', data: [scansOlder, scans7d] }]}
                  options={scanBarOptions}
                  sx={{ height: 200 }}
                />
              ) : (
                <Typography color="text.secondary" sx={{ py: 6, textAlign: 'center' }}>
                  No scan data yet. Scans will appear once QR codes are verified.
                </Typography>
              )}
            </CardContent>
          </Card>
        </Grid>

        {/* Recent Scans */}
        <Grid size={{ xs: 12, md: 7 }}>
          <Card>
            <CardHeader title="Recent Scans" />
            {recentScans.length > 0 ? (
              <TableContainer>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>QR Code</TableCell>
                      <TableCell>Trust</TableCell>
                      <TableCell>Proxy</TableCell>
                      <TableCell>Time</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {recentScans.map((scan) => (
                      <TableRow key={scan.id} hover>
                        <TableCell>
                          <Typography variant="body2" fontWeight={600} sx={{ fontFamily: 'monospace' }}>
                            {scan.qrCode.token}
                          </Typography>
                          {scan.qrCode.label && (
                            <Typography variant="caption" color="text.secondary">
                              {scan.qrCode.label}
                            </Typography>
                          )}
                        </TableCell>
                        <TableCell>
                          <Stack direction="row" alignItems="center" spacing={1}>
                            <LinearProgress
                              variant="determinate"
                              value={scan.trustScore}
                              color={scan.trustScore >= 80 ? 'success' : scan.trustScore >= 50 ? 'warning' : 'error'}
                              sx={{ width: 60, height: 6, borderRadius: 1 }}
                            />
                            <Typography variant="caption">{scan.trustScore}</Typography>
                          </Stack>
                        </TableCell>
                        <TableCell>
                          {scan.proxyDetected ? (
                            <Chip label="Detected" color="error" size="small" />
                          ) : (
                            <Chip label="Clean" color="success" size="small" variant="outlined" />
                          )}
                        </TableCell>
                        <TableCell>
                          <Typography variant="caption" color="text.secondary">
                            {formatDateTime(scan.createdAt)}
                          </Typography>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            ) : (
              <CardContent>
                <Typography color="text.secondary">No scans recorded yet.</Typography>
              </CardContent>
            )}
          </Card>
        </Grid>

        {/* Top QR Codes */}
        <Grid size={{ xs: 12, md: 5 }}>
          <Card>
            <CardHeader title="QR Codes" />
            {topQRCodes.length > 0 ? (
              <TableContainer>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>Code</TableCell>
                      <TableCell>Status</TableCell>
                      <TableCell align="right">Scans</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {topQRCodes.map((qr) => (
                      <TableRow key={qr.id} hover>
                        <TableCell>
                          <Typography variant="body2" fontWeight={600} sx={{ fontFamily: 'monospace' }}>
                            {qr.token}
                          </Typography>
                          {qr.label && (
                            <Typography variant="caption" color="text.secondary" noWrap sx={{ maxWidth: 150, display: 'block' }}>
                              {qr.label}
                            </Typography>
                          )}
                        </TableCell>
                        <TableCell>
                          <Chip
                            label={qr.status}
                            size="small"
                            color={qr.status === 'ACTIVE' ? 'success' : 'default'}
                          />
                        </TableCell>
                        <TableCell align="right">{qr._count?.scans ?? 0}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            ) : (
              <CardContent>
                <Typography color="text.secondary">No QR codes yet.</Typography>
              </CardContent>
            )}
          </Card>
        </Grid>
      </Grid>

      {/* AI Security Monitoring */}
      <Card sx={{ mt: 3 }}>
        <CardHeader
          title="AI Security Monitoring"
          subheader="Automated fraud detection with dynamic rules"
          action={
            <Chip
              label="Active"
              color="success"
              size="small"
              variant="outlined"
            />
          }
        />
        <CardContent>
          <Grid container spacing={2}>
            <Grid size={{ xs: 12, sm: 4 }}>
              <Box sx={{ textAlign: 'center', p: 2, borderRadius: 1, bgcolor: 'background.neutral' }}>
                <Typography variant="h4" color="primary.main">{fraudRuleCount}</Typography>
                <Typography variant="body2" color="text.secondary">Active Fraud Rules</Typography>
              </Box>
            </Grid>
            <Grid size={{ xs: 12, sm: 4 }}>
              <Box sx={{ textAlign: 'center', p: 2, borderRadius: 1, bgcolor: 'background.neutral' }}>
                <Typography variant="h4" color="info.main">6</Typography>
                <Typography variant="body2" color="text.secondary">Detection Signals</Typography>
              </Box>
            </Grid>
            <Grid size={{ xs: 12, sm: 4 }}>
              <Box sx={{ textAlign: 'center', p: 2, borderRadius: 1, bgcolor: 'background.neutral' }}>
                <Typography variant="h4" color="success.main">24/7</Typography>
                <Typography variant="body2" color="text.secondary">Real-Time Monitoring</Typography>
              </Box>
            </Grid>
          </Grid>
          <Typography variant="body2" color="text.secondary" sx={{ mt: 2 }}>
            Dynamic rules are evaluated on every QR code scan. The AI agent analyzes patterns daily and creates new rules automatically.
          </Typography>
        </CardContent>
      </Card>
    </>
  );
}
