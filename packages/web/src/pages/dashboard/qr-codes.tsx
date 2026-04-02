import { useState, useEffect, useCallback } from 'react';

import Box from '@mui/material/Box';
import Card from '@mui/material/Card';
import Chip from '@mui/material/Chip';
import Stack from '@mui/material/Stack';
import Table from '@mui/material/Table';
import Button from '@mui/material/Button';
import Dialog from '@mui/material/Dialog';
import Drawer from '@mui/material/Drawer';
import TableRow from '@mui/material/TableRow';
import TableBody from '@mui/material/TableBody';
import TableCell from '@mui/material/TableCell';
import TableHead from '@mui/material/TableHead';
import IconButton from '@mui/material/IconButton';
import Typography from '@mui/material/Typography';
import CardContent from '@mui/material/CardContent';
import DialogTitle from '@mui/material/DialogTitle';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import TableContainer from '@mui/material/TableContainer';
import CircularProgress from '@mui/material/CircularProgress';

import { paths } from 'src/routes/paths';
import { useRouter } from 'src/routes/hooks';
import { RouterLink } from 'src/routes/components';

import { formatDate } from 'src/utils/format-date';

import axios, { endpoints } from 'src/lib/axios';

import { Iconify } from 'src/components/iconify';
import { useSnackbar } from 'src/components/snackbar';

// ----------------------------------------------------------------------

type FeedbackEntry = {
  id: string;
  rating: number;
  comment?: string;
  createdAt: string;
};

type QRCode = {
  id: string;
  token: string;
  destinationUrl: string;
  label?: string;
  contentType?: string;
  status: string;
  createdAt: string;
  _count?: { scans: number };
};

export default function QRCodesPage() {
  const router = useRouter();
  const { showError, showSuccess } = useSnackbar();
  const [qrCodes, setQrCodes] = useState<QRCode[]>([]);
  const [loading, setLoading] = useState(true);
  const [revokeToken, setRevokeToken] = useState<string | null>(null);
  const [revoking, setRevoking] = useState(false);

  // Feedback drawer
  const [feedbackToken, setFeedbackToken] = useState<string | null>(null);
  const [feedbackData, setFeedbackData] = useState<FeedbackEntry[]>([]);
  const [feedbackAvg, setFeedbackAvg] = useState<number | null>(null);
  const [loadingFeedback, setLoadingFeedback] = useState(false);

  const fetchQRCodes = useCallback(async () => {
    try {
      const res = await axios.get(endpoints.qrcodes.list);
      setQrCodes(res.data.data ?? res.data ?? []);
    } catch (error: any) {
      showError(error.message || 'Failed to load QR codes');
    } finally {
      setLoading(false);
    }
  }, [showError]);

  const handleViewFeedback = async (token: string) => {
    setFeedbackToken(token);
    setLoadingFeedback(true);
    try {
      const res = await axios.get(`${endpoints.analytics.fraud.replace('/fraud', '/feedback')}/${token}`);
      setFeedbackData(res.data.data ?? []);
      setFeedbackAvg(res.data.avgRating ?? null);
    } catch {
      setFeedbackData([]);
      setFeedbackAvg(null);
    } finally {
      setLoadingFeedback(false);
    }
  };

  useEffect(() => {
    fetchQRCodes();
  }, [fetchQRCodes]);

  return (
    <>
      <Box sx={{ mb: 3, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <Typography variant="h4">QR Codes</Typography>
        <Box sx={{ display: 'flex', gap: 1 }}>
          <Button
            component={RouterLink}
            href={paths.dashboard.qrcodes.bulk}
            variant="outlined"
            startIcon={<Iconify icon="solar:copy-bold" />}
          >
            Bulk Create
          </Button>
          <Button
            component={RouterLink}
            href={paths.dashboard.qrcodes.create}
            variant="contained"
            startIcon={<Iconify icon="mingcute:add-line" />}
          >
            New QR Code
          </Button>
        </Box>
      </Box>

      <Card>
        {loading ? (
          <CardContent sx={{ textAlign: 'center', py: 5 }}>
            <CircularProgress />
          </CardContent>
        ) : qrCodes.length === 0 ? (
          <CardContent>
            <Typography color="text.secondary">
              No QR codes yet. Create your first one to get started.
            </Typography>
          </CardContent>
        ) : (
          <TableContainer>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>Token</TableCell>
                  <TableCell>Type</TableCell>
                  <TableCell>Label</TableCell>
                  <TableCell>Status</TableCell>
                  <TableCell>Scans</TableCell>
                  <TableCell>Created</TableCell>
                  <TableCell>Actions</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {qrCodes.map((qr) => (
                  <TableRow key={qr.id} hover>
                    <TableCell>
                      <Typography variant="body2" sx={{ fontFamily: 'monospace', fontWeight: 600 }}>
                        {qr.token}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Chip label={qr.contentType || 'url'} size="small" variant="outlined" />
                    </TableCell>
                    <TableCell>{qr.label || '—'}</TableCell>
                    <TableCell>
                      <Chip
                        label={qr.status}
                        size="small"
                        color={qr.status === 'ACTIVE' ? 'success' : 'default'}
                      />
                    </TableCell>
                    <TableCell>{qr._count?.scans ?? 0}</TableCell>
                    <TableCell>{formatDate(qr.createdAt)}</TableCell>
                    <TableCell>
                      {qr.contentType === 'feedback' && (
                        <IconButton
                          size="small"
                          color="info"
                          title="View Responses"
                          onClick={() => handleViewFeedback(qr.token)}
                        >
                          <Iconify icon="solar:chat-round-dots-bold" />
                        </IconButton>
                      )}
                      <IconButton
                        size="small"
                        onClick={() => router.push(paths.dashboard.qrcodes.edit(qr.token))}
                      >
                        <Iconify icon="solar:pen-bold" />
                      </IconButton>
                      <IconButton
                        size="small"
                        color="error"
                        title="Revoke"
                        onClick={() => setRevokeToken(qr.token)}
                        disabled={qr.status !== 'ACTIVE'}
                      >
                        <Iconify icon="solar:close-circle-bold" />
                      </IconButton>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        )}
      </Card>

      <Dialog open={Boolean(revokeToken)} onClose={() => setRevokeToken(null)}>
        <DialogTitle>Revoke QR Code</DialogTitle>
        <DialogContent>
          <Typography>
            Are you sure you want to revoke <strong>{revokeToken}</strong>? This action cannot be undone. The QR code will show as invalid when scanned.
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setRevokeToken(null)}>Cancel</Button>
          <Button
            color="error"
            variant="contained"
            disabled={revoking}
            onClick={async () => {
              setRevoking(true);
              try {
                await axios.delete(endpoints.qrcodes.details(revokeToken!));
                showSuccess('QR code revoked');
                setRevokeToken(null);
                fetchQRCodes();
              } catch (err: unknown) {
                showError((err as Error).message || 'Failed to revoke');
              } finally {
                setRevoking(false);
              }
            }}
          >
            {revoking ? 'Revoking...' : 'Revoke'}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Feedback Responses Drawer */}
      <Drawer
        anchor="right"
        open={Boolean(feedbackToken)}
        onClose={() => setFeedbackToken(null)}
        PaperProps={{ sx: { width: { xs: '100%', sm: 400 } } }}
      >
        <Box sx={{ p: 3 }}>
          <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ mb: 3 }}>
            <Typography variant="h6">Feedback Responses</Typography>
            <IconButton onClick={() => setFeedbackToken(null)}>
              <Iconify icon="mingcute:close-line" />
            </IconButton>
          </Stack>

          {feedbackAvg !== null && (
            <Box sx={{ textAlign: 'center', mb: 3, p: 2, bgcolor: 'background.neutral', borderRadius: 2 }}>
              <Typography variant="h2" color="warning.main">{feedbackAvg}</Typography>
              <Stack direction="row" justifyContent="center" spacing={0.5} sx={{ mt: 0.5 }}>
                {[1, 2, 3, 4, 5].map((s) => (
                  <Typography key={s} sx={{ fontSize: 20, color: s <= Math.round(feedbackAvg) ? '#FFAB00' : '#dfe3e8' }}>
                    &#9733;
                  </Typography>
                ))}
              </Stack>
              <Typography variant="caption" color="text.secondary">{feedbackData.length} responses</Typography>
            </Box>
          )}

          {loadingFeedback ? (
            <Box sx={{ textAlign: 'center', py: 4 }}><CircularProgress size={24} /></Box>
          ) : feedbackData.length === 0 ? (
            <Typography color="text.secondary" textAlign="center">No responses yet.</Typography>
          ) : (
            <Stack spacing={2}>
              {feedbackData.map((fb) => (
                <Box key={fb.id} sx={{ p: 2, borderRadius: 1, border: '1px solid', borderColor: 'divider' }}>
                  <Stack direction="row" justifyContent="space-between" alignItems="center">
                    <Stack direction="row" spacing={0.3}>
                      {[1, 2, 3, 4, 5].map((s) => (
                        <Typography key={s} sx={{ fontSize: 16, color: s <= fb.rating ? '#FFAB00' : '#dfe3e8' }}>
                          &#9733;
                        </Typography>
                      ))}
                    </Stack>
                    <Typography variant="caption" color="text.secondary">
                      {formatDate(fb.createdAt)}
                    </Typography>
                  </Stack>
                  {fb.comment && (
                    <Typography variant="body2" sx={{ mt: 1, color: 'text.secondary' }}>
                      {fb.comment}
                    </Typography>
                  )}
                </Box>
              ))}
            </Stack>
          )}
        </Box>
      </Drawer>
    </>
  );
}
