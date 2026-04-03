import { useState, useEffect, useCallback } from 'react';

import Box from '@mui/material/Box';
import Card from '@mui/material/Card';
import Chip from '@mui/material/Chip';
import Stack from '@mui/material/Stack';
import Table from '@mui/material/Table';
import Collapse from '@mui/material/Collapse';
import TableRow from '@mui/material/TableRow';
import TableBody from '@mui/material/TableBody';
import TableCell from '@mui/material/TableCell';
import TableHead from '@mui/material/TableHead';
import Typography from '@mui/material/Typography';
import IconButton from '@mui/material/IconButton';
import CardContent from '@mui/material/CardContent';
import TableContainer from '@mui/material/TableContainer';
import TablePagination from '@mui/material/TablePagination';
import CircularProgress from '@mui/material/CircularProgress';

import { formatDateTime } from 'src/utils/format-date';

import axios, { endpoints } from 'src/lib/axios';

import { Iconify } from 'src/components/iconify';
import { useSnackbar } from 'src/components/snackbar';

// ----------------------------------------------------------------------

type WebhookDelivery = {
  id: string;
  event: string;
  url: string;
  statusCode: number | null;
  attempts: number;
  deliveredAt: string | null;
  failedAt: string | null;
  error: string | null;
  createdAt: string;
  app: { id: string; name: string };
};

type DeliveryStatus = 'delivered' | 'failed' | 'pending';

function getStatus(delivery: WebhookDelivery): DeliveryStatus {
  if (delivery.deliveredAt) return 'delivered';
  if (delivery.failedAt) return 'failed';
  return 'pending';
}

// ----------------------------------------------------------------------

function StatusChip({ delivery }: { delivery: WebhookDelivery }) {
  const status = getStatus(delivery);

  const config = {
    delivered: { label: 'Delivered', color: 'success' as const },
    failed: { label: 'Failed', color: 'error' as const },
    pending: { label: 'Pending', color: 'warning' as const },
  }[status];

  return (
    <Chip
      label={config.label}
      color={config.color}
      size="small"
      variant="soft"
    />
  );
}

// ----------------------------------------------------------------------

function DeliveryRow({ delivery }: { delivery: WebhookDelivery }) {
  const [open, setOpen] = useState(false);

  return (
    <>
      <TableRow
        hover
        onClick={() => setOpen((prev) => !prev)}
        sx={{ cursor: 'pointer', '& > *': { borderBottom: open ? 0 : undefined } }}
      >
        <TableCell padding="checkbox">
          <IconButton size="small" onClick={(e) => { e.stopPropagation(); setOpen((prev) => !prev); }}>
            <Iconify
              icon={open ? 'eva:arrow-ios-upward-fill' : 'eva:arrow-ios-downward-fill'}
              width={16}
            />
          </IconButton>
        </TableCell>
        <TableCell>
          <Typography
            variant="body2"
            sx={{ fontFamily: 'monospace', fontSize: 12, fontWeight: 600 }}
          >
            {delivery.event}
          </Typography>
        </TableCell>
        <TableCell>
          <Typography
            variant="body2"
            sx={{
              fontFamily: 'monospace',
              fontSize: 12,
              maxWidth: 260,
              overflow: 'hidden',
              textOverflow: 'ellipsis',
              whiteSpace: 'nowrap',
            }}
            title={delivery.url}
          >
            {delivery.url}
          </Typography>
        </TableCell>
        <TableCell>
          <StatusChip delivery={delivery} />
        </TableCell>
        <TableCell>
          {delivery.statusCode != null ? (
            <Chip
              label={delivery.statusCode}
              size="small"
              variant="outlined"
              color={delivery.statusCode < 300 ? 'success' : 'error'}
            />
          ) : (
            <Typography variant="body2" color="text.disabled">—</Typography>
          )}
        </TableCell>
        <TableCell>
          <Typography variant="body2" color="text.secondary">
            {delivery.attempts}
          </Typography>
        </TableCell>
        <TableCell>
          <Typography variant="body2" color="text.secondary" sx={{ whiteSpace: 'nowrap' }}>
            {formatDateTime(delivery.createdAt)}
          </Typography>
        </TableCell>
        <TableCell>
          <Typography variant="body2" color="text.secondary">
            {delivery.app.name}
          </Typography>
        </TableCell>
      </TableRow>

      {/* Expandable detail row */}
      <TableRow>
        <TableCell colSpan={8} sx={{ py: 0, background: 'transparent' }}>
          <Collapse in={open} timeout="auto" unmountOnExit>
            <Box
              sx={{
                mx: 2,
                my: 1.5,
                p: 2,
                bgcolor: 'background.neutral',
                borderRadius: 1,
                border: '1px solid',
                borderColor: 'divider',
              }}
            >
              <Stack spacing={1.5}>
                <Stack direction="row" spacing={4}>
                  <Box>
                    <Typography variant="caption" color="text.secondary" fontWeight={600}>
                      Delivery ID
                    </Typography>
                    <Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: 12 }}>
                      {delivery.id}
                    </Typography>
                  </Box>
                  {delivery.deliveredAt && (
                    <Box>
                      <Typography variant="caption" color="text.secondary" fontWeight={600}>
                        Delivered At
                      </Typography>
                      <Typography variant="body2">{formatDateTime(delivery.deliveredAt)}</Typography>
                    </Box>
                  )}
                  {delivery.failedAt && (
                    <Box>
                      <Typography variant="caption" color="text.secondary" fontWeight={600}>
                        Failed At
                      </Typography>
                      <Typography variant="body2">{formatDateTime(delivery.failedAt)}</Typography>
                    </Box>
                  )}
                </Stack>

                {delivery.error && (
                  <Box>
                    <Typography variant="caption" color="text.secondary" fontWeight={600}>
                      Error
                    </Typography>
                    <Box
                      sx={{
                        mt: 0.5,
                        p: 1.5,
                        bgcolor: 'error.lighter',
                        borderRadius: 0.5,
                        border: '1px solid',
                        borderColor: 'error.light',
                      }}
                    >
                      <Typography
                        variant="body2"
                        color="error.dark"
                        sx={{ fontFamily: 'monospace', fontSize: 12, whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}
                      >
                        {delivery.error}
                      </Typography>
                    </Box>
                  </Box>
                )}

                <Box>
                  <Typography variant="caption" color="text.secondary" fontWeight={600}>
                    Endpoint URL
                  </Typography>
                  <Typography
                    variant="body2"
                    sx={{ fontFamily: 'monospace', fontSize: 12, wordBreak: 'break-all' }}
                  >
                    {delivery.url}
                  </Typography>
                </Box>
              </Stack>
            </Box>
          </Collapse>
        </TableCell>
      </TableRow>
    </>
  );
}

// ----------------------------------------------------------------------

export default function WebhookLogsPage() {
  const { showError } = useSnackbar();
  const [deliveries, setDeliveries] = useState<WebhookDelivery[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(0);
  const [pageSize, setPageSize] = useState(10);
  const [loading, setLoading] = useState(true);

  const fetchDeliveries = useCallback(async () => {
    setLoading(true);
    try {
      const res = await axios.get(endpoints.webhookDeliveries.list, {
        params: { page: page + 1, pageSize },
      });
      setDeliveries(res.data.data ?? []);
      setTotal(res.data.total ?? 0);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to load webhook deliveries';
      showError(message);
    } finally {
      setLoading(false);
    }
  }, [page, pageSize, showError]);

  useEffect(() => {
    fetchDeliveries();
  }, [fetchDeliveries]);

  return (
    <>
      <Box sx={{ mb: 3 }}>
        <Typography variant="h4">Webhook Logs</Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
          Delivery history for webhook events sent from your apps
        </Typography>
      </Box>

      <Card>
        {loading ? (
          <CardContent sx={{ textAlign: 'center', py: 5 }}>
            <CircularProgress />
          </CardContent>
        ) : deliveries.length === 0 ? (
          <CardContent sx={{ textAlign: 'center', py: 6 }}>
            <Iconify
              icon="solar:bell-off-bold"
              width={48}
              sx={{ color: 'text.disabled', mb: 2, display: 'block', mx: 'auto' }}
            />
            <Typography variant="h6" sx={{ mb: 1 }}>
              No webhook deliveries yet
            </Typography>
            <Typography color="text.secondary">
              Webhook events will appear here once your apps start sending them.
            </Typography>
          </CardContent>
        ) : (
          <>
            <TableContainer>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell padding="checkbox" />
                    <TableCell>Event</TableCell>
                    <TableCell>URL</TableCell>
                    <TableCell>Status</TableCell>
                    <TableCell>HTTP Code</TableCell>
                    <TableCell>Attempts</TableCell>
                    <TableCell>Created</TableCell>
                    <TableCell>App</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {deliveries.map((delivery) => (
                    <DeliveryRow key={delivery.id} delivery={delivery} />
                  ))}
                </TableBody>
              </Table>
            </TableContainer>

            <TablePagination
              component="div"
              count={total}
              page={page}
              rowsPerPage={pageSize}
              onPageChange={(_e, newPage) => setPage(newPage)}
              onRowsPerPageChange={(e) => {
                setPageSize(Number(e.target.value));
                setPage(0);
              }}
              rowsPerPageOptions={[10, 25, 50]}
            />
          </>
        )}
      </Card>
    </>
  );
}
