import { useState, useEffect, useCallback } from 'react';

import Box from '@mui/material/Box';
import Card from '@mui/material/Card';
import Chip from '@mui/material/Chip';
import Table from '@mui/material/Table';
import Button from '@mui/material/Button';
import Dialog from '@mui/material/Dialog';
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

import axios, { endpoints } from 'src/lib/axios';

import { Iconify } from 'src/components/iconify';
import { useSnackbar } from 'src/components/snackbar';

// ----------------------------------------------------------------------

type QRCode = {
  id: string;
  token: string;
  destinationUrl: string;
  label?: string;
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
                  <TableCell>Label</TableCell>
                  <TableCell>Destination</TableCell>
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
                    <TableCell>{qr.label || '—'}</TableCell>
                    <TableCell>
                      <Typography variant="body2" noWrap sx={{ maxWidth: 250 }}>
                        {qr.destinationUrl}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Chip
                        label={qr.status}
                        size="small"
                        color={qr.status === 'ACTIVE' ? 'success' : 'default'}
                      />
                    </TableCell>
                    <TableCell>{qr._count?.scans ?? 0}</TableCell>
                    <TableCell>{new Date(qr.createdAt).toLocaleDateString()}</TableCell>
                    <TableCell>
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
    </>
  );
}
