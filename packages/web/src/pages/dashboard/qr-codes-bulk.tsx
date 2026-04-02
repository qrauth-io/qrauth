import { useState } from 'react';

import Box from '@mui/material/Box';
import Card from '@mui/material/Card';
import Stack from '@mui/material/Stack';
import Alert from '@mui/material/Alert';
import Button from '@mui/material/Button';
import TextField from '@mui/material/TextField';
import CardHeader from '@mui/material/CardHeader';
import Typography from '@mui/material/Typography';
import CardContent from '@mui/material/CardContent';
import LinearProgress from '@mui/material/LinearProgress';

import { paths } from 'src/routes/paths';
import { useRouter } from 'src/routes/hooks';

import axios, { endpoints } from 'src/lib/axios';

import { useSnackbar } from 'src/components/snackbar';

// ----------------------------------------------------------------------

type BulkResult = { token: string; destinationUrl: string; success: boolean; error?: string };

export default function QRCodesBulkPage() {
  const router = useRouter();
  const { showSuccess, showError } = useSnackbar();
  const [urls, setUrls] = useState('');
  const [labelPrefix, setLabelPrefix] = useState('');
  const [creating, setCreating] = useState(false);
  const [results, setResults] = useState<BulkResult[] | null>(null);

  const handleCreate = async () => {
    const lines = urls.split('\n').map((l) => l.trim()).filter(Boolean);
    if (lines.length === 0) {
      showError('Enter at least one URL');
      return;
    }
    if (lines.length > 100) {
      showError('Maximum 100 QR codes at once');
      return;
    }

    setCreating(true);
    try {
      const items = lines.map((url, i) => ({
        destinationUrl: url,
        label: labelPrefix ? `${labelPrefix} #${i + 1}` : undefined,
      }));

      const res = await axios.post(endpoints.qrcodes.bulk, { items });
      const data = res.data.results ?? res.data ?? [];
      setResults(data);
      const successCount = data.filter((r: any) => r.success !== false).length;
      showSuccess(`${successCount}/${lines.length} QR codes created`);
    } catch (err: unknown) {
      showError((err as Error).message || 'Bulk creation failed');
    } finally {
      setCreating(false);
    }
  };

  return (
    <>
      <Box sx={{ mb: 3, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <Typography variant="h4">Bulk Create QR Codes</Typography>
        <Button variant="outlined" onClick={() => router.push(paths.dashboard.qrcodes.root)}>
          Back to QR Codes
        </Button>
      </Box>

      {results ? (
        <Card>
          <CardHeader title={`Created ${results.filter((r) => r.success !== false).length} QR Codes`} />
          <CardContent>
            <Stack spacing={1}>
              {results.map((r, i) => (
                <Alert key={i} severity={r.success !== false ? 'success' : 'error'} sx={{ py: 0.5 }}>
                  <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                    {r.success !== false ? r.token : r.error} — {r.destinationUrl}
                  </Typography>
                </Alert>
              ))}
            </Stack>
            <Stack direction="row" spacing={2} sx={{ mt: 3 }}>
              <Button variant="contained" onClick={() => { setResults(null); setUrls(''); }}>
                Create More
              </Button>
              <Button variant="outlined" onClick={() => router.push(paths.dashboard.qrcodes.root)}>
                View All QR Codes
              </Button>
            </Stack>
          </CardContent>
        </Card>
      ) : (
        <Card>
          <CardHeader title="Enter Destination URLs" subheader="One URL per line, up to 100" />
          <CardContent>
            <Stack spacing={3}>
              <TextField
                multiline
                rows={10}
                value={urls}
                onChange={(e) => setUrls(e.target.value)}
                placeholder={`https://parking.city.gov/zone-a\nhttps://parking.city.gov/zone-b\nhttps://parking.city.gov/zone-c`}
                fullWidth
                slotProps={{ inputLabel: { shrink: true } }}
              />
              <TextField
                label="Label prefix (optional)"
                value={labelPrefix}
                onChange={(e) => setLabelPrefix(e.target.value)}
                placeholder="Parking Zone"
                helperText="Each QR will be labeled: Parking Zone #1, Parking Zone #2, etc."
                fullWidth
                slotProps={{ inputLabel: { shrink: true } }}
              />
              {creating && <LinearProgress />}
              <Button
                variant="contained"
                size="large"
                onClick={handleCreate}
                disabled={creating || !urls.trim()}
              >
                {creating ? 'Creating...' : `Generate ${urls.split('\n').filter((l) => l.trim()).length || 0} QR Codes`}
              </Button>
            </Stack>
          </CardContent>
        </Card>
      )}
    </>
  );
}
