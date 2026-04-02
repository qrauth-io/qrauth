import { useState, useEffect, useCallback } from 'react';

import Box from '@mui/material/Box';
import Card from '@mui/material/Card';
import Chip from '@mui/material/Chip';
import Stack from '@mui/material/Stack';
import Table from '@mui/material/Table';
import Button from '@mui/material/Button';
import TableRow from '@mui/material/TableRow';
import TableBody from '@mui/material/TableBody';
import TableCell from '@mui/material/TableCell';
import TableHead from '@mui/material/TableHead';
import Typography from '@mui/material/Typography';
import CardHeader from '@mui/material/CardHeader';
import CardContent from '@mui/material/CardContent';
import TableContainer from '@mui/material/TableContainer';
import CircularProgress from '@mui/material/CircularProgress';

import { paths } from 'src/routes/paths';
import { useParams, useRouter } from 'src/routes/hooks';

import { formatDateTime } from 'src/utils/format-date';

import axios, { endpoints } from 'src/lib/axios';

import { useSnackbar } from 'src/components/snackbar';

// ----------------------------------------------------------------------

type FeedbackEntry = {
  id: string;
  rating: number;
  comment?: string;
  name?: string;
  email?: string;
  phone?: string;
  createdAt: string;
};

function Stars({ rating }: { rating: number }) {
  return (
    <Stack direction="row" spacing={0.3}>
      {[1, 2, 3, 4, 5].map((s) => (
        <Typography key={s} sx={{ fontSize: 16, color: s <= rating ? '#FFAB00' : '#dfe3e8' }}>
          &#9733;
        </Typography>
      ))}
    </Stack>
  );
}

export default function QRCodesFeedbackPage() {
  const { token } = useParams();
  const router = useRouter();
  const { showError } = useSnackbar();

  const [loading, setLoading] = useState(true);
  const [data, setData] = useState<FeedbackEntry[]>([]);
  const [avgRating, setAvgRating] = useState<number | null>(null);

  const fetchFeedback = useCallback(async () => {
    try {
      const res = await axios.get(`${endpoints.analytics.scans.replace('/scans', '/feedback')}/${token}`);
      setData(res.data.data ?? []);
      setAvgRating(res.data.avgRating ?? null);
    } catch (err: unknown) {
      showError((err as Error).message || 'Failed to load feedback');
    } finally {
      setLoading(false);
    }
  }, [token, showError]);

  useEffect(() => {
    if (token) fetchFeedback();
  }, [token, fetchFeedback]);

  return (
    <>
      <Box sx={{ mb: 3, display: 'flex', alignItems: 'center', gap: 2 }}>
        <Button variant="text" onClick={() => router.push(paths.dashboard.qrcodes.root)}>
          ← Back
        </Button>
        <Typography variant="h4">Feedback Responses</Typography>
        <Chip label={token} size="small" variant="outlined" sx={{ fontFamily: 'monospace' }} />
      </Box>

      {/* Summary */}
      {avgRating !== null && (
        <Card sx={{ mb: 3 }}>
          <CardContent>
            <Stack direction="row" spacing={4} alignItems="center" justifyContent="center">
              <Box sx={{ textAlign: 'center' }}>
                <Typography variant="h1" color="warning.main">{avgRating}</Typography>
                <Stars rating={Math.round(avgRating)} />
                <Typography variant="caption" color="text.secondary" sx={{ mt: 0.5, display: 'block' }}>
                  Average rating
                </Typography>
              </Box>
              <Box sx={{ textAlign: 'center' }}>
                <Typography variant="h2">{data.length}</Typography>
                <Typography variant="caption" color="text.secondary">
                  Total responses
                </Typography>
              </Box>
              {/* Rating distribution */}
              <Stack spacing={0.5}>
                {[5, 4, 3, 2, 1].map((r) => {
                  const count = data.filter((d) => d.rating === r).length;
                  const pct = data.length > 0 ? (count / data.length) * 100 : 0;
                  return (
                    <Stack key={r} direction="row" alignItems="center" spacing={1} sx={{ minWidth: 180 }}>
                      <Typography variant="caption" sx={{ width: 10 }}>{r}</Typography>
                      <Typography sx={{ fontSize: 14, color: '#FFAB00' }}>&#9733;</Typography>
                      <Box sx={{ flex: 1, height: 8, borderRadius: 1, bgcolor: '#f0f0f0' }}>
                        <Box sx={{ width: `${pct}%`, height: '100%', borderRadius: 1, bgcolor: '#FFAB00' }} />
                      </Box>
                      <Typography variant="caption" color="text.secondary" sx={{ width: 24, textAlign: 'right' }}>
                        {count}
                      </Typography>
                    </Stack>
                  );
                })}
              </Stack>
            </Stack>
          </CardContent>
        </Card>
      )}

      {/* Responses table */}
      <Card>
        <CardHeader title="All Responses" />
        {loading ? (
          <CardContent sx={{ textAlign: 'center', py: 5 }}>
            <CircularProgress />
          </CardContent>
        ) : data.length === 0 ? (
          <CardContent>
            <Typography color="text.secondary" textAlign="center">
              No responses yet. Share the QR code to start collecting feedback.
            </Typography>
          </CardContent>
        ) : (
          <TableContainer>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>Rating</TableCell>
                  <TableCell>Name</TableCell>
                  <TableCell>Email</TableCell>
                  <TableCell>Phone</TableCell>
                  <TableCell>Comment</TableCell>
                  <TableCell>Date</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {data.map((fb) => (
                  <TableRow key={fb.id} hover>
                    <TableCell>
                      <Stars rating={fb.rating} />
                    </TableCell>
                    <TableCell>{fb.name || '—'}</TableCell>
                    <TableCell>{fb.email || '—'}</TableCell>
                    <TableCell>{fb.phone || '—'}</TableCell>
                    <TableCell>
                      <Typography variant="body2" noWrap sx={{ maxWidth: 250 }}>
                        {fb.comment || '—'}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Typography variant="caption">{formatDateTime(fb.createdAt)}</Typography>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        )}
      </Card>
    </>
  );
}
