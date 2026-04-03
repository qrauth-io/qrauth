import { useState, useEffect, useCallback } from 'react';

import Box from '@mui/material/Box';
import Card from '@mui/material/Card';
import Stack from '@mui/material/Stack';
import Table from '@mui/material/Table';
import Alert from '@mui/material/Alert';
import Button from '@mui/material/Button';
import Dialog from '@mui/material/Dialog';
import TableRow from '@mui/material/TableRow';
import TextField from '@mui/material/TextField';
import TableBody from '@mui/material/TableBody';
import TableCell from '@mui/material/TableCell';
import TableHead from '@mui/material/TableHead';
import Typography from '@mui/material/Typography';
import IconButton from '@mui/material/IconButton';
import CardContent from '@mui/material/CardContent';
import DialogTitle from '@mui/material/DialogTitle';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import TableContainer from '@mui/material/TableContainer';
import InputAdornment from '@mui/material/InputAdornment';
import CircularProgress from '@mui/material/CircularProgress';

import { formatDate, formatDateTime } from 'src/utils/format-date';

import axios, { endpoints } from 'src/lib/axios';

import { Iconify } from 'src/components/iconify';
import { useSnackbar } from 'src/components/snackbar';

// ----------------------------------------------------------------------

type ApiKeyItem = {
  id: string;
  prefix: string;
  label: string | null;
  lastUsedAt: string | null;
  createdAt: string;
};

type CreatedApiKey = {
  id: string;
  key: string;
  prefix: string;
  label: string | null;
  createdAt: string;
  message: string;
};

export default function ApiKeysPage() {
  const { showSuccess, showError } = useSnackbar();
  const [apiKeys, setApiKeys] = useState<ApiKeyItem[]>([]);
  const [loading, setLoading] = useState(true);

  // Create dialog
  const [createOpen, setCreateOpen] = useState(false);
  const [creating, setCreating] = useState(false);
  const [createdKey, setCreatedKey] = useState<CreatedApiKey | null>(null);
  const [label, setLabel] = useState('');

  // Copy state
  const [copied, setCopied] = useState(false);

  const fetchApiKeys = useCallback(async () => {
    try {
      const res = await axios.get(endpoints.apiKeys.list);
      setApiKeys(res.data.data ?? []);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to load API keys';
      showError(message);
    } finally {
      setLoading(false);
    }
  }, [showError]);

  useEffect(() => {
    fetchApiKeys();
  }, [fetchApiKeys]);

  const handleCreate = async () => {
    setCreating(true);
    try {
      const res = await axios.post(endpoints.apiKeys.create, {
        label: label.trim() || undefined,
      });
      setCreatedKey(res.data);
      showSuccess('API key generated. Save it now — it will not be shown again.');
      fetchApiKeys();
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to generate API key';
      showError(message);
    } finally {
      setCreating(false);
    }
  };

  const handleCopyKey = async () => {
    if (!createdKey) return;
    try {
      await navigator.clipboard.writeText(createdKey.key);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      showError('Failed to copy to clipboard');
    }
  };

  const handleRevoke = async (keyId: string, keyPrefix: string) => {
    if (!window.confirm(`Revoke the key "qrauth_${keyPrefix}..."? It will stop working immediately.`)) return;
    try {
      await axios.delete(endpoints.apiKeys.revoke(keyId));
      showSuccess('API key revoked');
      fetchApiKeys();
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to revoke API key';
      showError(message);
    }
  };

  const handleCloseCreate = () => {
    setCreateOpen(false);
    setCreatedKey(null);
    setLabel('');
    setCopied(false);
  };

  return (
    <>
      <Box sx={{ mb: 3, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <Box>
          <Typography variant="h4">API Keys</Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
            Generate API keys to authenticate server-to-server requests
          </Typography>
        </Box>
        <Button
          variant="contained"
          startIcon={<Iconify icon="mingcute:add-line" />}
          onClick={() => setCreateOpen(true)}
        >
          Generate API Key
        </Button>
      </Box>

      <Card>
        {loading ? (
          <CardContent sx={{ textAlign: 'center', py: 5 }}>
            <CircularProgress />
          </CardContent>
        ) : apiKeys.length === 0 ? (
          <CardContent sx={{ textAlign: 'center', py: 6 }}>
            <Iconify
              icon="ic:round-vpn-key"
              width={48}
              sx={{ color: 'text.disabled', mb: 2, display: 'block', mx: 'auto' }}
            />
            <Typography variant="h6" sx={{ mb: 1 }}>No API keys yet</Typography>
            <Typography color="text.secondary" sx={{ mb: 3 }}>
              Generate an API key to start making authenticated requests to the QRAuth API.
            </Typography>
            <Button variant="contained" onClick={() => setCreateOpen(true)}>
              Generate Your First Key
            </Button>
          </CardContent>
        ) : (
          <TableContainer>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>Key</TableCell>
                  <TableCell>Label</TableCell>
                  <TableCell>Last Used</TableCell>
                  <TableCell>Created</TableCell>
                  <TableCell align="right">Actions</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {apiKeys.map((apiKey) => (
                  <TableRow key={apiKey.id} hover>
                    <TableCell>
                      <Typography
                        variant="body2"
                        sx={{ fontFamily: 'monospace', fontSize: 13 }}
                      >
                        qrauth_{apiKey.prefix}...
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2" color={apiKey.label ? 'text.primary' : 'text.disabled'}>
                        {apiKey.label ?? 'No label'}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2" color="text.secondary">
                        {formatDateTime(apiKey.lastUsedAt)}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2" color="text.secondary">
                        {formatDate(apiKey.createdAt)}
                      </Typography>
                    </TableCell>
                    <TableCell align="right">
                      <IconButton
                        size="small"
                        color="error"
                        title="Revoke key"
                        onClick={() => handleRevoke(apiKey.id, apiKey.prefix)}
                      >
                        <Iconify icon="solar:trash-bin-trash-bold" />
                      </IconButton>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        )}
      </Card>

      {/* Generate / Success Dialog */}
      <Dialog open={createOpen} onClose={handleCloseCreate} maxWidth="sm" fullWidth>
        <DialogTitle>{createdKey ? 'API Key Generated' : 'Generate New API Key'}</DialogTitle>
        <DialogContent>
          {createdKey ? (
            <Stack spacing={3} sx={{ mt: 1 }}>
              <Alert severity="warning" icon={<Iconify icon="solar:danger-triangle-bold" />}>
                This key will only be shown once. Copy it now and store it somewhere safe.
              </Alert>

              <Box>
                <Typography variant="subtitle2" color="text.secondary" sx={{ mb: 1 }}>
                  API Key
                </Typography>
                <TextField
                  fullWidth
                  value={createdKey.key}
                  slotProps={{
                    input: {
                      readOnly: true,
                      sx: { fontFamily: 'monospace', fontSize: 13 },
                      endAdornment: (
                        <InputAdornment position="end">
                          <IconButton onClick={handleCopyKey} edge="end" title="Copy to clipboard">
                            <Iconify
                              icon={copied ? 'solar:check-circle-bold' : 'solar:copy-bold'}
                              sx={{ color: copied ? 'success.main' : 'text.secondary' }}
                            />
                          </IconButton>
                        </InputAdornment>
                      ),
                    },
                  }}
                />
              </Box>

              {createdKey.label && (
                <Box>
                  <Typography variant="subtitle2" color="text.secondary">Label</Typography>
                  <Typography variant="body2">{createdKey.label}</Typography>
                </Box>
              )}

              <Alert severity="info">
                Pass the key in the Authorization header:
                <Box component="pre" sx={{ mt: 1, fontSize: 12, fontFamily: 'monospace', whiteSpace: 'pre-wrap' }}>
                  {`Authorization: Bearer ${createdKey.key}`}
                </Box>
              </Alert>
            </Stack>
          ) : (
            <Stack spacing={3} sx={{ mt: 1 }}>
              <TextField
                label="Label (optional)"
                value={label}
                onChange={(e) => setLabel(e.target.value)}
                fullWidth
                autoFocus
                placeholder="e.g. Production server, CI pipeline"
                helperText="A human-readable name to help you identify this key later"
                slotProps={{ inputLabel: { shrink: true } }}
              />
            </Stack>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCloseCreate}>
            {createdKey ? 'Done' : 'Cancel'}
          </Button>
          {!createdKey && (
            <Button variant="contained" onClick={handleCreate} disabled={creating}>
              {creating ? 'Generating...' : 'Generate Key'}
            </Button>
          )}
        </DialogActions>
      </Dialog>
    </>
  );
}
