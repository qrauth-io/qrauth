import { useState, useEffect, useCallback } from 'react';

import Box from '@mui/material/Box';
import Card from '@mui/material/Card';
import Chip from '@mui/material/Chip';
import Grid from '@mui/material/Grid';
import Stack from '@mui/material/Stack';
import Table from '@mui/material/Table';
import Button from '@mui/material/Button';
import Dialog from '@mui/material/Dialog';
import Drawer from '@mui/material/Drawer';
import Select from '@mui/material/Select';
import Divider from '@mui/material/Divider';
import MenuItem from '@mui/material/MenuItem';
import TableRow from '@mui/material/TableRow';
import TextField from '@mui/material/TextField';
import TableBody from '@mui/material/TableBody';
import TableCell from '@mui/material/TableCell';
import TableHead from '@mui/material/TableHead';
import IconButton from '@mui/material/IconButton';
import Typography from '@mui/material/Typography';
import CardHeader from '@mui/material/CardHeader';
import InputLabel from '@mui/material/InputLabel';
import CardContent from '@mui/material/CardContent';
import FormControl from '@mui/material/FormControl';
import DialogTitle from '@mui/material/DialogTitle';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import TableContainer from '@mui/material/TableContainer';
import TablePagination from '@mui/material/TablePagination';
import CircularProgress from '@mui/material/CircularProgress';

import axios, { endpoints } from 'src/lib/axios';

import { Iconify } from 'src/components/iconify';
import { useSnackbar } from 'src/components/snackbar';
import { Chart, useChart } from 'src/components/chart';

// ----------------------------------------------------------------------

type FraudIncident = {
  id: string;
  type: string;
  severity: string;
  resolved: boolean;
  resolvedAt: string | null;
  resolvedBy: string | null;
  resolutionNote: string | null;
  acknowledgedAt: string | null;
  createdAt: string;
  details: Record<string, unknown>;
  qrCode: {
    token: string;
    label: string | null;
    destinationUrl?: string;
    latitude?: number;
    longitude?: number;
  };
  scan?: {
    id: string;
    clientIpHash: string;
    clientLat?: number;
    clientLng?: number;
    userAgent?: string;
    trustScore: number;
    createdAt: string;
  } | null;
};

const SEVERITY_COLORS: Record<string, 'default' | 'info' | 'warning' | 'error'> = {
  LOW: 'info',
  MEDIUM: 'warning',
  HIGH: 'error',
  CRITICAL: 'error',
};

const TYPE_LABELS: Record<string, string> = {
  DUPLICATE_LOCATION: 'Duplicate Location',
  PROXY_DETECTED: 'Proxy Detected',
  PATTERN_ANOMALY: 'Pattern Anomaly',
  MANUAL_REPORT: 'Manual Report',
  GEO_IMPOSSIBLE: 'Geo Impossibility',
};

const DETAIL_REASONS: Record<string, string> = {
  scan_velocity: 'Unusual scan volume detected',
  bot_detected: 'Automated scanner / bot detected',
  device_clustering: 'Same device scanning many QR codes',
  duplicate_location: 'Another org has a QR code at this location',
  geo_impossible: 'Same IP scanned from impossible distance',
  proxy_detected: 'VPN or proxy connection detected',
};

export default function FraudPage() {
  const { showSuccess, showError } = useSnackbar();
  const [incidents, setIncidents] = useState<FraudIncident[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(0);
  const [pageSize, setPageSize] = useState(10);
  const [loading, setLoading] = useState(true);
  const [severity, setSeverity] = useState<string>('');
  const [resolved, setResolved] = useState<string>('');

  // Incident detail drawer
  const [selectedIncident, setSelectedIncident] = useState<FraudIncident | null>(null);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [loadingDetail, setLoadingDetail] = useState(false);

  // Resolve dialog
  const [resolveId, setResolveId] = useState<string | null>(null);
  const [resolveNote, setResolveNote] = useState('');
  const [resolving, setResolving] = useState(false);

  const fetchIncidents = useCallback(async () => {
    setLoading(true);
    try {
      const params: Record<string, unknown> = { page: page + 1, pageSize };
      if (severity) params.severity = severity;
      if (resolved) params.resolved = resolved;

      const res = await axios.get(endpoints.analytics.fraud, { params });
      setIncidents(res.data.data ?? []);
      setTotal(res.data.total ?? 0);
    } catch (err: unknown) {
      showError((err as Error).message || 'Failed to load incidents');
    } finally {
      setLoading(false);
    }
  }, [page, pageSize, severity, resolved, showError]);

  useEffect(() => {
    fetchIncidents();
  }, [fetchIncidents]);

  const handleViewDetail = async (id: string) => {
    setLoadingDetail(true);
    setDrawerOpen(true);
    try {
      const res = await axios.get(`${endpoints.analytics.fraud}/${id}`);
      setSelectedIncident(res.data);
    } catch (err: unknown) {
      showError((err as Error).message || 'Failed to load incident');
      setDrawerOpen(false);
    } finally {
      setLoadingDetail(false);
    }
  };

  const handleAcknowledge = async (id: string) => {
    try {
      await axios.post(`${endpoints.analytics.fraud}/${id}/acknowledge`);
      showSuccess('Incident acknowledged');
      fetchIncidents();
      if (selectedIncident?.id === id) {
        setSelectedIncident({ ...selectedIncident, acknowledgedAt: new Date().toISOString() });
      }
    } catch (err: unknown) {
      showError((err as Error).message || 'Failed to acknowledge');
    }
  };

  const handleResolve = async () => {
    if (!resolveId) return;
    setResolving(true);
    try {
      await axios.post(`${endpoints.analytics.fraud}/${resolveId}/resolve`, {
        note: resolveNote || undefined,
      });
      showSuccess('Incident resolved');
      setResolveId(null);
      setResolveNote('');
      setDrawerOpen(false);
      fetchIncidents();
    } catch (err: unknown) {
      showError((err as Error).message || 'Failed to resolve');
    } finally {
      setResolving(false);
    }
  };

  // Stats from current data
  const activeCount = incidents.filter((i) => !i.resolved).length;
  const criticalCount = incidents.filter((i) => i.severity === 'CRITICAL' && !i.resolved).length;
  const highCount = incidents.filter((i) => i.severity === 'HIGH' && !i.resolved).length;

  // Type breakdown for chart
  const typeBreakdown: Record<string, number> = {};
  incidents.forEach((i) => {
    const label = TYPE_LABELS[i.type] || i.type;
    typeBreakdown[label] = (typeBreakdown[label] || 0) + 1;
  });

  const donutOptions = useChart({
    labels: Object.keys(typeBreakdown),
    colors: ['#FF5630', '#FFAB00', '#00A76F', '#0065DB', '#7635DC'],
    plotOptions: {
      pie: { donut: { labels: { show: true, total: { label: 'Incidents' } } } },
    },
    legend: { show: true, position: 'bottom' },
  });

  return (
    <>
      <Box sx={{ mb: 3, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <Stack direction="row" alignItems="center" spacing={2}>
          <Typography variant="h4">Fraud Detection</Typography>
          {criticalCount > 0 && (
            <Chip label={`${criticalCount} critical`} color="error" size="small" />
          )}
          {highCount > 0 && <Chip label={`${highCount} high`} color="warning" size="small" />}
          {activeCount === 0 && <Chip label="All clear" color="success" size="small" />}
        </Stack>
      </Box>

      {/* Stats row */}
      <Grid container spacing={3} sx={{ mb: 3 }}>
        <Grid size={{ xs: 6, md: 3 }}>
          <Card>
            <CardContent sx={{ textAlign: 'center', py: 2 }}>
              <Typography variant="h3" color={activeCount > 0 ? 'error.main' : 'success.main'}>
                {activeCount}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Active Incidents
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid size={{ xs: 6, md: 3 }}>
          <Card>
            <CardContent sx={{ textAlign: 'center', py: 2 }}>
              <Typography variant="h3">{total}</Typography>
              <Typography variant="body2" color="text.secondary">
                Total Detected
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid size={{ xs: 6, md: 3 }}>
          <Card>
            <CardContent sx={{ textAlign: 'center', py: 2 }}>
              <Typography variant="h3" color="error.main">
                {criticalCount + highCount}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                High + Critical
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid size={{ xs: 6, md: 3 }}>
          <Card sx={{ height: '100%' }}>
            <CardHeader title="" />
            <CardContent sx={{ py: 1, display: 'flex', justifyContent: 'center' }}>
              {Object.keys(typeBreakdown).length > 0 ? (
                <Chart
                  type="donut"
                  series={Object.values(typeBreakdown)}
                  options={donutOptions}
                  sx={{ height: 120, width: 180 }}
                />
              ) : (
                <Typography color="text.secondary" variant="body2" sx={{ py: 3 }}>
                  No data
                </Typography>
              )}
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Filters */}
      <Stack direction="row" spacing={2} sx={{ mb: 3 }}>
        <FormControl size="small" sx={{ minWidth: 140 }}>
          <InputLabel>Severity</InputLabel>
          <Select
            value={severity}
            label="Severity"
            onChange={(e) => {
              setSeverity(e.target.value);
              setPage(0);
            }}
          >
            <MenuItem value="">All</MenuItem>
            <MenuItem value="LOW">Low</MenuItem>
            <MenuItem value="MEDIUM">Medium</MenuItem>
            <MenuItem value="HIGH">High</MenuItem>
            <MenuItem value="CRITICAL">Critical</MenuItem>
          </Select>
        </FormControl>
        <FormControl size="small" sx={{ minWidth: 140 }}>
          <InputLabel>Status</InputLabel>
          <Select
            value={resolved}
            label="Status"
            onChange={(e) => {
              setResolved(e.target.value);
              setPage(0);
            }}
          >
            <MenuItem value="">All</MenuItem>
            <MenuItem value="false">Active</MenuItem>
            <MenuItem value="true">Resolved</MenuItem>
          </Select>
        </FormControl>
      </Stack>

      {/* Incidents table */}
      <Card>
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
                    <TableCell>Type</TableCell>
                    <TableCell>Severity</TableCell>
                    <TableCell>QR Code</TableCell>
                    <TableCell>Reason</TableCell>
                    <TableCell>Status</TableCell>
                    <TableCell>Detected</TableCell>
                    <TableCell align="right">Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {incidents.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={7} sx={{ textAlign: 'center', py: 6 }}>
                        <Iconify
                          icon="solar:shield-check-bold"
                          width={48}
                          sx={{ color: 'success.main', mb: 1, display: 'block', mx: 'auto' }}
                        />
                        <Typography color="text.secondary">
                          No fraud incidents detected.
                        </Typography>
                      </TableCell>
                    </TableRow>
                  ) : (
                    incidents.map((incident) => (
                      <TableRow
                        key={incident.id}
                        hover
                        sx={{
                          cursor: 'pointer',
                          ...(incident.severity === 'CRITICAL' &&
                            !incident.resolved && { bgcolor: 'error.lighter' }),
                        }}
                        onClick={() => handleViewDetail(incident.id)}
                      >
                        <TableCell>
                          <Typography variant="body2" fontWeight={600}>
                            {TYPE_LABELS[incident.type] || incident.type}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Chip
                            label={incident.severity}
                            color={SEVERITY_COLORS[incident.severity] || 'default'}
                            size="small"
                            variant={incident.severity === 'CRITICAL' ? 'filled' : 'outlined'}
                          />
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                            {incident.qrCode.token}
                          </Typography>
                          {incident.qrCode.label && (
                            <Typography variant="caption" color="text.secondary">
                              {incident.qrCode.label}
                            </Typography>
                          )}
                        </TableCell>
                        <TableCell>
                          <Typography variant="caption" color="text.secondary">
                            {DETAIL_REASONS[incident.details?.reason as string] ||
                              JSON.stringify(incident.details).slice(0, 60)}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Stack direction="row" spacing={0.5}>
                            <Chip
                              label={
                                incident.resolved
                                  ? 'Resolved'
                                  : incident.acknowledgedAt
                                    ? 'Acknowledged'
                                    : 'New'
                              }
                              color={
                                incident.resolved
                                  ? 'default'
                                  : incident.acknowledgedAt
                                    ? 'info'
                                    : 'error'
                              }
                              size="small"
                              variant={incident.resolved ? 'outlined' : 'filled'}
                            />
                          </Stack>
                        </TableCell>
                        <TableCell>
                          <Typography variant="caption">
                            {new Date(incident.createdAt).toLocaleString()}
                          </Typography>
                        </TableCell>
                        <TableCell align="right" onClick={(e) => e.stopPropagation()}>
                          <Stack direction="row" spacing={0.5} justifyContent="flex-end">
                            {!incident.acknowledgedAt && !incident.resolved && (
                              <IconButton
                                size="small"
                                title="Acknowledge"
                                onClick={() => handleAcknowledge(incident.id)}
                              >
                                <Iconify icon="solar:bell-bing-bold" />
                              </IconButton>
                            )}
                            {!incident.resolved && (
                              <IconButton
                                size="small"
                                color="success"
                                title="Resolve"
                                onClick={() => setResolveId(incident.id)}
                              >
                                <Iconify icon="solar:check-circle-bold" />
                              </IconButton>
                            )}
                          </Stack>
                        </TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </TableContainer>
            {total > 0 && (
              <TablePagination
                component="div"
                count={total}
                page={page}
                rowsPerPage={pageSize}
                onPageChange={(_, p) => setPage(p)}
                onRowsPerPageChange={(e) => {
                  setPageSize(parseInt(e.target.value, 10));
                  setPage(0);
                }}
                rowsPerPageOptions={[5, 10, 25]}
              />
            )}
          </>
        )}
      </Card>

      {/* Incident Detail Drawer */}
      <Drawer
        anchor="right"
        open={drawerOpen}
        onClose={() => setDrawerOpen(false)}
        PaperProps={{ sx: { width: { xs: '100%', sm: 420 } } }}
      >
        {loadingDetail ? (
          <Box sx={{ p: 4, textAlign: 'center' }}>
            <CircularProgress />
          </Box>
        ) : (
          selectedIncident && (
            <Box sx={{ p: 3 }}>
              <Stack
                direction="row"
                justifyContent="space-between"
                alignItems="center"
                sx={{ mb: 3 }}
              >
                <Typography variant="h6">Incident Detail</Typography>
                <IconButton onClick={() => setDrawerOpen(false)}>
                  <Iconify icon="mingcute:close-line" />
                </IconButton>
              </Stack>

              {/* Severity + Status */}
              <Stack direction="row" spacing={1} sx={{ mb: 3 }}>
                <Chip
                  label={selectedIncident.severity}
                  color={SEVERITY_COLORS[selectedIncident.severity] || 'default'}
                />
                <Chip
                  label={
                    selectedIncident.resolved
                      ? 'Resolved'
                      : selectedIncident.acknowledgedAt
                        ? 'Acknowledged'
                        : 'Active'
                  }
                  color={selectedIncident.resolved ? 'default' : 'error'}
                  variant="outlined"
                />
              </Stack>

              {/* Type + Reason */}
              <Typography variant="subtitle2" color="text.secondary">
                Type
              </Typography>
              <Typography variant="body1" fontWeight={600} sx={{ mb: 2 }}>
                {TYPE_LABELS[selectedIncident.type] || selectedIncident.type}
              </Typography>

              <Typography variant="subtitle2" color="text.secondary">
                Description
              </Typography>
              <Typography variant="body2" sx={{ mb: 2 }}>
                {DETAIL_REASONS[selectedIncident.details?.reason as string] ||
                  'Fraud signal detected during scan analysis.'}
              </Typography>

              <Divider sx={{ my: 2 }} />

              {/* QR Code info */}
              <Typography variant="subtitle2" color="text.secondary">
                QR Code
              </Typography>
              <Typography variant="body1" sx={{ fontFamily: 'monospace', mb: 0.5 }}>
                {selectedIncident.qrCode.token}
              </Typography>
              {selectedIncident.qrCode.label && (
                <Typography variant="body2" color="text.secondary" sx={{ mb: 0.5 }}>
                  {selectedIncident.qrCode.label}
                </Typography>
              )}
              {selectedIncident.qrCode.destinationUrl && (
                <Typography
                  variant="caption"
                  sx={{ wordBreak: 'break-all', color: 'info.main' }}
                >
                  {selectedIncident.qrCode.destinationUrl}
                </Typography>
              )}

              <Divider sx={{ my: 2 }} />

              {/* Scan info */}
              {selectedIncident.scan && (
                <>
                  <Typography variant="subtitle2" color="text.secondary" sx={{ mb: 1 }}>
                    Scan Details
                  </Typography>
                  <Stack spacing={1} sx={{ mb: 2 }}>
                    <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
                      <Typography variant="caption" color="text.secondary">
                        Trust Score
                      </Typography>
                      <Chip
                        label={selectedIncident.scan.trustScore}
                        size="small"
                        color={
                          selectedIncident.scan.trustScore >= 80
                            ? 'success'
                            : selectedIncident.scan.trustScore >= 50
                              ? 'warning'
                              : 'error'
                        }
                      />
                    </Box>
                    <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
                      <Typography variant="caption" color="text.secondary">
                        IP Hash
                      </Typography>
                      <Typography variant="caption" sx={{ fontFamily: 'monospace' }}>
                        {selectedIncident.scan.clientIpHash.slice(0, 12)}...
                      </Typography>
                    </Box>
                    {selectedIncident.scan.clientLat && (
                      <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
                        <Typography variant="caption" color="text.secondary">
                          Location
                        </Typography>
                        <Typography variant="caption" sx={{ fontFamily: 'monospace' }}>
                          {selectedIncident.scan.clientLat.toFixed(4)},{' '}
                          {selectedIncident.scan.clientLng?.toFixed(4)}
                        </Typography>
                      </Box>
                    )}
                    {selectedIncident.scan.userAgent && (
                      <Box>
                        <Typography variant="caption" color="text.secondary">
                          User Agent
                        </Typography>
                        <Typography
                          variant="caption"
                          display="block"
                          sx={{ wordBreak: 'break-all' }}
                        >
                          {selectedIncident.scan.userAgent}
                        </Typography>
                      </Box>
                    )}
                    <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
                      <Typography variant="caption" color="text.secondary">
                        Scanned At
                      </Typography>
                      <Typography variant="caption">
                        {new Date(selectedIncident.scan.createdAt).toLocaleString()}
                      </Typography>
                    </Box>
                  </Stack>
                  <Divider sx={{ my: 2 }} />
                </>
              )}

              {/* Raw details */}
              <Typography variant="subtitle2" color="text.secondary" sx={{ mb: 1 }}>
                Raw Details
              </Typography>
              <Box
                sx={{
                  p: 1.5,
                  borderRadius: 1,
                  bgcolor: 'background.neutral',
                  fontFamily: 'monospace',
                  fontSize: 11,
                  whiteSpace: 'pre-wrap',
                  wordBreak: 'break-all',
                  maxHeight: 200,
                  overflow: 'auto',
                }}
              >
                {JSON.stringify(selectedIncident.details, null, 2)}
              </Box>

              {/* Resolution info */}
              {selectedIncident.resolved && (
                <>
                  <Divider sx={{ my: 2 }} />
                  <Typography variant="subtitle2" color="text.secondary" sx={{ mb: 1 }}>
                    Resolution
                  </Typography>
                  <Typography variant="body2">
                    Resolved {new Date(selectedIncident.resolvedAt!).toLocaleString()}
                  </Typography>
                  {selectedIncident.resolutionNote && (
                    <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
                      {selectedIncident.resolutionNote}
                    </Typography>
                  )}
                </>
              )}

              {/* Timeline */}
              <Divider sx={{ my: 2 }} />
              <Typography variant="subtitle2" color="text.secondary" sx={{ mb: 1 }}>
                Timeline
              </Typography>
              <Stack spacing={1}>
                <Typography variant="caption">
                  Detected: {new Date(selectedIncident.createdAt).toLocaleString()}
                </Typography>
                {selectedIncident.acknowledgedAt && (
                  <Typography variant="caption">
                    Acknowledged: {new Date(selectedIncident.acknowledgedAt).toLocaleString()}
                  </Typography>
                )}
                {selectedIncident.resolvedAt && (
                  <Typography variant="caption">
                    Resolved: {new Date(selectedIncident.resolvedAt).toLocaleString()}
                  </Typography>
                )}
              </Stack>

              {/* Actions */}
              {!selectedIncident.resolved && (
                <Stack direction="row" spacing={1} sx={{ mt: 3 }}>
                  {!selectedIncident.acknowledgedAt && (
                    <Button
                      variant="outlined"
                      fullWidth
                      onClick={() => handleAcknowledge(selectedIncident.id)}
                    >
                      Acknowledge
                    </Button>
                  )}
                  <Button
                    variant="contained"
                    color="success"
                    fullWidth
                    onClick={() => setResolveId(selectedIncident.id)}
                  >
                    Resolve
                  </Button>
                </Stack>
              )}
            </Box>
          )
        )}
      </Drawer>

      {/* Resolve Dialog */}
      <Dialog
        open={Boolean(resolveId)}
        onClose={() => setResolveId(null)}
        maxWidth="sm"
        fullWidth
      >
        <DialogTitle>Resolve Incident</DialogTitle>
        <DialogContent>
          <TextField
            label="Resolution Note (optional)"
            value={resolveNote}
            onChange={(e) => setResolveNote(e.target.value)}
            fullWidth
            multiline
            rows={3}
            placeholder="Describe what was found and how it was resolved..."
            sx={{ mt: 1 }}
            slotProps={{ inputLabel: { shrink: true } }}
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setResolveId(null)}>Cancel</Button>
          <Button
            variant="contained"
            color="success"
            onClick={handleResolve}
            disabled={resolving}
          >
            {resolving ? 'Resolving...' : 'Mark as Resolved'}
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
}
