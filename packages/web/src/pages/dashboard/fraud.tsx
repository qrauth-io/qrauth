import { useState, useEffect, useCallback } from 'react';

import Box from '@mui/material/Box';
import Card from '@mui/material/Card';
import Chip from '@mui/material/Chip';
import Stack from '@mui/material/Stack';
import Table from '@mui/material/Table';
import Select from '@mui/material/Select';
import MenuItem from '@mui/material/MenuItem';
import TableRow from '@mui/material/TableRow';
import TableBody from '@mui/material/TableBody';
import TableCell from '@mui/material/TableCell';
import TableHead from '@mui/material/TableHead';
import Typography from '@mui/material/Typography';
import InputLabel from '@mui/material/InputLabel';
import CardContent from '@mui/material/CardContent';
import FormControl from '@mui/material/FormControl';
import TableContainer from '@mui/material/TableContainer';
import TablePagination from '@mui/material/TablePagination';
import CircularProgress from '@mui/material/CircularProgress';

import axios, { endpoints } from 'src/lib/axios';

import { Iconify } from 'src/components/iconify';
import { useSnackbar } from 'src/components/snackbar';

// ----------------------------------------------------------------------

type FraudIncident = {
  id: string;
  type: string;
  severity: string;
  resolved: boolean;
  resolvedAt: string | null;
  createdAt: string;
  details: Record<string, unknown>;
  qrCode: { token: string; label: string | null };
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

export default function FraudPage() {
  const { showError } = useSnackbar();
  const [incidents, setIncidents] = useState<FraudIncident[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(0);
  const [pageSize, setPageSize] = useState(10);
  const [loading, setLoading] = useState(true);
  const [severity, setSeverity] = useState<string>('');
  const [resolved, setResolved] = useState<string>('');

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
      const message = err instanceof Error ? err.message : 'Failed to load fraud incidents';
      showError(message);
    } finally {
      setLoading(false);
    }
  }, [page, pageSize, severity, resolved, showError]);

  useEffect(() => {
    fetchIncidents();
  }, [fetchIncidents]);

  const activeCount = incidents.filter((i) => !i.resolved).length;

  return (
    <>
      <Box sx={{ mb: 3, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <Stack direction="row" alignItems="center" spacing={2}>
          <Typography variant="h4">Fraud Incidents</Typography>
          <Chip
            label={`${activeCount} active`}
            color={activeCount > 0 ? 'error' : 'success'}
            size="small"
          />
        </Stack>
      </Box>

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
                    <TableCell>Status</TableCell>
                    <TableCell>Detected</TableCell>
                    <TableCell>Details</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {incidents.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={6} sx={{ textAlign: 'center', py: 6 }}>
                        <Iconify
                          icon="solar:shield-check-bold"
                          width={48}
                          sx={{ color: 'success.main', mb: 1, display: 'block', mx: 'auto' }}
                        />
                        <Typography color="text.secondary">
                          No fraud incidents detected. The system continuously monitors for
                          suspicious activity.
                        </Typography>
                      </TableCell>
                    </TableRow>
                  ) : (
                    incidents.map((incident) => (
                      <TableRow key={incident.id} hover>
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
                          <Chip
                            label={incident.resolved ? 'Resolved' : 'Active'}
                            color={incident.resolved ? 'default' : 'error'}
                            size="small"
                            variant={incident.resolved ? 'outlined' : 'filled'}
                          />
                        </TableCell>
                        <TableCell>
                          <Typography variant="caption">
                            {new Date(incident.createdAt).toLocaleString()}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Typography
                            variant="caption"
                            color="text.secondary"
                            noWrap
                            sx={{ maxWidth: 200, display: 'block' }}
                          >
                            {JSON.stringify(incident.details).slice(0, 80)}
                          </Typography>
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
    </>
  );
}
