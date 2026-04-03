import { useState, useEffect, useCallback } from 'react';

import Box from '@mui/material/Box';
import Card from '@mui/material/Card';
import Chip from '@mui/material/Chip';
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
import CircularProgress from '@mui/material/CircularProgress';

import axios, { endpoints } from 'src/lib/axios';

import { Iconify } from 'src/components/iconify';
import { useSnackbar } from 'src/components/snackbar';

// ----------------------------------------------------------------------

type AppItem = {
  id: string;
  name: string;
  slug: string;
  clientId: string;
  status: string;
  allowedScopes: string[];
  redirectUrls: string[];
  createdAt: string;
  _count?: { authSessions: number };
};

type CreatedApp = AppItem & { clientSecret: string };

export default function AppsPage() {
  const { showSuccess, showError } = useSnackbar();
  const [apps, setApps] = useState<AppItem[]>([]);
  const [loading, setLoading] = useState(true);

  // Create dialog
  const [createOpen, setCreateOpen] = useState(false);
  const [creating, setCreating] = useState(false);
  const [newApp, setNewApp] = useState<CreatedApp | null>(null);
  const [form, setForm] = useState({ name: '', redirectUrl: '', description: '' });

  // Secret reveal
  const [revealedSecret, setRevealedSecret] = useState<{ appId: string; secret: string } | null>(null);

  const fetchApps = useCallback(async () => {
    try {
      const res = await axios.get(endpoints.apps.list);
      setApps(res.data.data ?? []);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to load apps';
      showError(message);
    } finally {
      setLoading(false);
    }
  }, [showError]);

  useEffect(() => {
    fetchApps();
  }, [fetchApps]);

  const handleCreate = async () => {
    if (!form.name || !form.redirectUrl) {
      showError('Name and redirect URL are required');
      return;
    }
    setCreating(true);
    try {
      const res = await axios.post(endpoints.apps.create, {
        name: form.name,
        redirectUrls: [form.redirectUrl],
        description: form.description || undefined,
        allowedScopes: ['identity', 'email'],
      });
      setNewApp(res.data);
      showSuccess('App created! Save the client secret — it will not be shown again.');
      fetchApps();
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to create app';
      showError(message);
    } finally {
      setCreating(false);
    }
  };

  const handleRotateSecret = async (appId: string, appName: string) => {
    if (!window.confirm(`Rotate the secret for "${appName}"? The old secret will stop working immediately.`)) return;
    try {
      const res = await axios.post(endpoints.apps.rotateSecret(appId));
      setRevealedSecret({ appId, secret: res.data.clientSecret });
      showSuccess('Secret rotated! Save the new value.');
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to rotate secret';
      showError(message);
    }
  };

  const handleDelete = async (appId: string, appName: string) => {
    if (!window.confirm(`Delete "${appName}"? All active sessions will be invalidated.`)) return;
    try {
      await axios.delete(endpoints.apps.details(appId));
      showSuccess('App deleted');
      fetchApps();
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to delete app';
      showError(message);
    }
  };

  const handleCloseCreate = () => {
    setCreateOpen(false);
    setNewApp(null);
    setForm({ name: '', redirectUrl: '', description: '' });
  };

  return (
    <>
      <Box sx={{ mb: 3, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <Box>
          <Typography variant="h4">Auth Apps</Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
            Register apps that use QRAuth for QR-based authentication
          </Typography>
        </Box>
        <Button
          variant="contained"
          startIcon={<Iconify icon="mingcute:add-line" />}
          onClick={() => setCreateOpen(true)}
        >
          Register App
        </Button>
      </Box>

      <Card>
        {loading ? (
          <CardContent sx={{ textAlign: 'center', py: 5 }}>
            <CircularProgress />
          </CardContent>
        ) : apps.length === 0 ? (
          <CardContent sx={{ textAlign: 'center', py: 6 }}>
            <Iconify icon="solar:shield-check-bold" width={48} sx={{ color: 'text.disabled', mb: 2, display: 'block', mx: 'auto' }} />
            <Typography variant="h6" sx={{ mb: 1 }}>No apps registered</Typography>
            <Typography color="text.secondary" sx={{ mb: 3 }}>
              Register your first app to enable QR-based authentication for your users.
            </Typography>
            <Button variant="contained" onClick={() => setCreateOpen(true)}>
              Register Your First App
            </Button>
          </CardContent>
        ) : (
          <TableContainer>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>App</TableCell>
                  <TableCell>Client ID</TableCell>
                  <TableCell>Scopes</TableCell>
                  <TableCell>Sessions</TableCell>
                  <TableCell>Status</TableCell>
                  <TableCell align="right">Actions</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {apps.map((app) => (
                  <TableRow key={app.id} hover>
                    <TableCell>
                      <Typography variant="body2" fontWeight={600}>{app.name}</Typography>
                      <Typography variant="caption" color="text.secondary">{app.slug}</Typography>
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: 12 }}>
                        {app.clientId}
                      </Typography>
                      {revealedSecret?.appId === app.id && (
                        <Alert severity="warning" sx={{ mt: 1, py: 0 }}>
                          <Typography variant="caption" sx={{ fontFamily: 'monospace', wordBreak: 'break-all' }}>
                            Secret: {revealedSecret.secret}
                          </Typography>
                        </Alert>
                      )}
                    </TableCell>
                    <TableCell>
                      <Stack direction="row" spacing={0.5} flexWrap="wrap" useFlexGap>
                        {app.allowedScopes.map((s) => (
                          <Chip key={s} label={s} size="small" variant="outlined" />
                        ))}
                      </Stack>
                    </TableCell>
                    <TableCell>{app._count?.authSessions ?? 0}</TableCell>
                    <TableCell>
                      <Chip
                        label={app.status}
                        size="small"
                        color={app.status === 'ACTIVE' ? 'success' : 'default'}
                      />
                    </TableCell>
                    <TableCell align="right">
                      <Stack direction="row" spacing={0.5} justifyContent="flex-end">
                        <IconButton
                          size="small"
                          title="Rotate secret"
                          onClick={() => handleRotateSecret(app.id, app.name)}
                        >
                          <Iconify icon="solar:restart-bold" />
                        </IconButton>
                        <IconButton
                          size="small"
                          color="error"
                          title="Delete app"
                          onClick={() => handleDelete(app.id, app.name)}
                        >
                          <Iconify icon="solar:trash-bin-trash-bold" />
                        </IconButton>
                      </Stack>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        )}
      </Card>

      {/* Create / Success Dialog */}
      <Dialog open={createOpen} onClose={handleCloseCreate} maxWidth="sm" fullWidth>
        <DialogTitle>{newApp ? 'App Created' : 'Register New App'}</DialogTitle>
        <DialogContent>
          {newApp ? (
            <Stack spacing={3} sx={{ mt: 1 }}>
              <Alert severity="warning">
                Save the client secret now. It will never be shown again.
              </Alert>

              <Box>
                <Typography variant="subtitle2" color="text.secondary">Client ID</Typography>
                <Typography variant="body1" sx={{ fontFamily: 'monospace', userSelect: 'all' }}>
                  {newApp.clientId}
                </Typography>
              </Box>

              <Box>
                <Typography variant="subtitle2" color="text.secondary">Client Secret</Typography>
                <Typography
                  variant="body2"
                  sx={{
                    fontFamily: 'monospace',
                    wordBreak: 'break-all',
                    p: 1.5,
                    borderRadius: 1,
                    bgcolor: 'error.lighter',
                    border: '1px solid',
                    borderColor: 'error.light',
                    userSelect: 'all',
                  }}
                >
                  {newApp.clientSecret}
                </Typography>
              </Box>

              <Alert severity="info">
                Use these credentials to create auth sessions via the API:
                <Box component="pre" sx={{ mt: 1, fontSize: 12, fontFamily: 'monospace', whiteSpace: 'pre-wrap' }}>
{`POST /api/v1/auth-sessions
Authorization: Basic <base64(clientId:clientSecret)>
Content-Type: application/json

{ "scopes": ["identity", "email"] }`}
                </Box>
              </Alert>
            </Stack>
          ) : (
            <Stack spacing={3} sx={{ mt: 1 }}>
              <TextField
                label="App Name"
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
                fullWidth
                autoFocus
                placeholder="My Authentication App"
                slotProps={{ inputLabel: { shrink: true } }}
              />
              <TextField
                label="Redirect URL"
                value={form.redirectUrl}
                onChange={(e) => setForm({ ...form, redirectUrl: e.target.value })}
                fullWidth
                placeholder="https://myapp.com/auth/callback"
                helperText="The URL where users are redirected after authentication"
                slotProps={{ inputLabel: { shrink: true } }}
              />
              <TextField
                label="Description (optional)"
                value={form.description}
                onChange={(e) => setForm({ ...form, description: e.target.value })}
                fullWidth
                multiline
                rows={2}
                placeholder="Brief description of your app"
                slotProps={{ inputLabel: { shrink: true } }}
              />
            </Stack>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCloseCreate}>
            {newApp ? 'Done' : 'Cancel'}
          </Button>
          {!newApp && (
            <Button variant="contained" onClick={handleCreate} disabled={creating}>
              {creating ? 'Creating...' : 'Register App'}
            </Button>
          )}
        </DialogActions>
      </Dialog>
    </>
  );
}
