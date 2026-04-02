import { useState, useEffect, useCallback } from 'react';

import Card from '@mui/material/Card';
import Chip from '@mui/material/Chip';
import Grid from '@mui/material/Grid';
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
import TablePagination from '@mui/material/TablePagination';
import CircularProgress from '@mui/material/CircularProgress';

import { formatDateTime } from 'src/utils/format-date';

import axios, { endpoints } from 'src/lib/axios';

import { Iconify } from 'src/components/iconify';
import { useSnackbar } from 'src/components/snackbar';
import { Chart, useChart } from 'src/components/chart';

// ----------------------------------------------------------------------

type Scan = {
  id: string;
  clientIpHash: string;
  clientLat: number | null;
  clientLng: number | null;
  trustScore: number;
  proxyDetected: boolean;
  passkeyVerified: boolean;
  userAgent: string | null;
  createdAt: string;
  qrCode: { token: string; label: string | null };
};

type HeatmapPoint = { lat: number; lng: number; count: number };

type Summary = {
  totalQRCodes: number;
  totalScans: number;
  scansLast7d: number;
  scansLast30d: number;
  activeFraudIncidents: number;
  avgTrustScore: number | null;
};

export default function AnalyticsPage() {
  const { showError } = useSnackbar();
  const [scans, setScans] = useState<Scan[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(0);
  const [pageSize, setPageSize] = useState(10);
  const [loading, setLoading] = useState(true);
  const [heatmap, setHeatmap] = useState<HeatmapPoint[]>([]);
  const [summary, setSummary] = useState<Summary | null>(null);

  const fetchScans = useCallback(async () => {
    setLoading(true);
    try {
      const res = await axios.get(endpoints.analytics.scans, {
        params: { page: page + 1, pageSize },
      });
      setScans(res.data.data ?? []);
      setTotal(res.data.total ?? 0);
    } catch (err: any) {
      showError(err.message || 'Failed to load scans');
    } finally {
      setLoading(false);
    }
  }, [page, pageSize, showError]);

  useEffect(() => {
    fetchScans();
  }, [fetchScans]);

  useEffect(() => {
    Promise.all([
      axios.get(endpoints.analytics.heatmap),
      axios.get(endpoints.analytics.summary),
    ])
      .then(([hRes, sRes]) => {
        setHeatmap(hRes.data.data ?? []);
        setSummary(sRes.data);
      })
      .catch(() => {});
     
  }, []);

  // Trust score distribution chart
  const trustBuckets = { high: 0, medium: 0, low: 0 };
  scans.forEach((s) => {
    if (s.trustScore >= 80) trustBuckets.high++;
    else if (s.trustScore >= 50) trustBuckets.medium++;
    else trustBuckets.low++;
  });

  const donutOptions = useChart({
    labels: ['High (80-100)', 'Medium (50-79)', 'Low (0-49)'],
    colors: ['#00A76F', '#FFAB00', '#FF5630'],
    plotOptions: {
      pie: { donut: { labels: { show: true, total: { label: 'Total Scans' } } } },
    },
    legend: { show: true, position: 'bottom' },
  });

  return (
    <>
      <Typography variant="h4" sx={{ mb: 3 }}>Analytics</Typography>

      {/* Summary cards */}
      <Grid container spacing={3} sx={{ mb: 3 }}>
        <Grid size={{ xs: 6, md: 3 }}>
          <Card>
            <CardContent sx={{ textAlign: 'center' }}>
              <Typography variant="h3" color="primary.main">{summary?.totalScans ?? '—'}</Typography>
              <Typography variant="body2" color="text.secondary">Total Scans</Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid size={{ xs: 6, md: 3 }}>
          <Card>
            <CardContent sx={{ textAlign: 'center' }}>
              <Typography variant="h3" color="success.main">{summary?.scansLast7d ?? '—'}</Typography>
              <Typography variant="body2" color="text.secondary">Last 7 Days</Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid size={{ xs: 6, md: 3 }}>
          <Card>
            <CardContent sx={{ textAlign: 'center' }}>
              <Typography variant="h3" color="info.main">{summary?.scansLast30d ?? '—'}</Typography>
              <Typography variant="body2" color="text.secondary">Last 30 Days</Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid size={{ xs: 6, md: 3 }}>
          <Card>
            <CardContent sx={{ textAlign: 'center' }}>
              <Typography
                variant="h3"
                color={summary?.avgTrustScore && summary.avgTrustScore >= 80 ? 'success.main' : 'warning.main'}
              >
                {summary?.avgTrustScore != null ? `${summary.avgTrustScore}%` : '—'}
              </Typography>
              <Typography variant="body2" color="text.secondary">Avg Trust Score</Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      <Grid container spacing={3} sx={{ mb: 3 }}>
        {/* Trust Score Distribution */}
        <Grid size={{ xs: 12, md: 4 }}>
          <Card sx={{ height: '100%' }}>
            <CardHeader title="Trust Score Distribution" />
            <CardContent>
              {total > 0 ? (
                <Chart
                  type="donut"
                  series={[trustBuckets.high, trustBuckets.medium, trustBuckets.low]}
                  options={donutOptions}
                  sx={{ height: 260 }}
                />
              ) : (
                <Typography color="text.secondary" sx={{ py: 8, textAlign: 'center' }}>No data yet</Typography>
              )}
            </CardContent>
          </Card>
        </Grid>

        {/* Scan Locations */}
        <Grid size={{ xs: 12, md: 8 }}>
          <Card sx={{ height: '100%' }}>
            <CardHeader title="Scan Locations" subheader={`${heatmap.length} location clusters`} />
            <CardContent>
              {heatmap.length > 0 ? (
                <TableContainer sx={{ maxHeight: 260 }}>
                  <Table size="small" stickyHeader>
                    <TableHead>
                      <TableRow>
                        <TableCell>Latitude</TableCell>
                        <TableCell>Longitude</TableCell>
                        <TableCell align="right">Scans</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {heatmap.slice(0, 20).map((point, i) => (
                        <TableRow key={i} hover>
                          <TableCell>{point.lat.toFixed(4)}</TableCell>
                          <TableCell>{point.lng.toFixed(4)}</TableCell>
                          <TableCell align="right">
                            <Chip label={point.count} size="small" color="primary" variant="outlined" />
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              ) : (
                <Typography color="text.secondary" sx={{ py: 6, textAlign: 'center' }}>
                  No geo-located scans yet. Location data appears when users scan with GPS.
                </Typography>
              )}
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Full scan history table */}
      <Card>
        <CardHeader title="Scan History" />
        {loading ? (
          <CardContent sx={{ textAlign: 'center', py: 5 }}>
            <CircularProgress />
          </CardContent>
        ) : (
          <>
            <TableContainer>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>QR Code</TableCell>
                    <TableCell>Trust Score</TableCell>
                    <TableCell>Proxy</TableCell>
                    <TableCell>Passkey</TableCell>
                    <TableCell>Location</TableCell>
                    <TableCell>User Agent</TableCell>
                    <TableCell>Time</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {scans.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={7} sx={{ textAlign: 'center', py: 4 }}>
                        <Typography color="text.secondary">No scans recorded yet.</Typography>
                      </TableCell>
                    </TableRow>
                  ) : (
                    scans.map((scan) => (
                      <TableRow key={scan.id} hover>
                        <TableCell>
                          <Typography variant="body2" fontWeight={600} sx={{ fontFamily: 'monospace' }}>
                            {scan.qrCode.token}
                          </Typography>
                          {scan.qrCode.label && (
                            <Typography variant="caption" color="text.secondary">{scan.qrCode.label}</Typography>
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
                            <Typography variant="body2">{scan.trustScore}</Typography>
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
                          {scan.passkeyVerified ? (
                            <Iconify icon="solar:verified-check-bold" color="success.main" />
                          ) : (
                            <Typography variant="caption" color="text.disabled">—</Typography>
                          )}
                        </TableCell>
                        <TableCell>
                          {scan.clientLat != null ? (
                            <Typography variant="caption" sx={{ fontFamily: 'monospace' }}>
                              {scan.clientLat.toFixed(3)}, {scan.clientLng?.toFixed(3)}
                            </Typography>
                          ) : (
                            <Typography variant="caption" color="text.disabled">—</Typography>
                          )}
                        </TableCell>
                        <TableCell>
                          <Typography variant="caption" noWrap sx={{ maxWidth: 180, display: 'block' }}>
                            {scan.userAgent || '—'}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Typography variant="caption">{formatDateTime(scan.createdAt)}</Typography>
                        </TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </TableContainer>
            <TablePagination
              component="div"
              count={total}
              page={page}
              rowsPerPage={pageSize}
              onPageChange={(_, p) => setPage(p)}
              onRowsPerPageChange={(e) => { setPageSize(parseInt(e.target.value, 10)); setPage(0); }}
              rowsPerPageOptions={[5, 10, 25]}
            />
          </>
        )}
      </Card>
    </>
  );
}
