import { useState, useEffect, useCallback } from 'react';

import Box from '@mui/material/Box';
import Card from '@mui/material/Card';
import Chip from '@mui/material/Chip';
import Grid from '@mui/material/Grid';
import Alert from '@mui/material/Alert';
import Stack from '@mui/material/Stack';
import Table from '@mui/material/Table';
import Button from '@mui/material/Button';
import Divider from '@mui/material/Divider';
import TableRow from '@mui/material/TableRow';
import TableBody from '@mui/material/TableBody';
import TableCell from '@mui/material/TableCell';
import TableHead from '@mui/material/TableHead';
import TextField from '@mui/material/TextField';
import Typography from '@mui/material/Typography';
import CardHeader from '@mui/material/CardHeader';
import CardContent from '@mui/material/CardContent';
import TableContainer from '@mui/material/TableContainer';
import CircularProgress from '@mui/material/CircularProgress';

import axios, { endpoints } from 'src/lib/axios';

import { Iconify } from 'src/components/iconify';
import { useSnackbar } from 'src/components/snackbar';

import { useAuthContext } from 'src/auth/hooks';

// ----------------------------------------------------------------------

type Organization = {
  id: string;
  name: string;
  slug: string;
  email: string;
  domain: string | null;
  billingEmail: string | null;
  trustLevel: string;
  kycStatus: string;
  plan: string;
  createdAt: string;
};

type SigningKey = {
  id: string;
  keyId: string;
  algorithm: string;
  status: string;
  createdAt: string;
};

const KYC_COLORS: Record<string, 'default' | 'info' | 'success' | 'warning' | 'error'> = {
  PENDING: 'warning',
  UNDER_REVIEW: 'info',
  VERIFIED: 'success',
  REJECTED: 'error',
};

export default function SettingsPage() {
  const { showSuccess, showError } = useSnackbar();
  const { user } = useAuthContext();
  const orgId = (user as Record<string, unknown> & { organization?: { id: string } })?.organization
    ?.id;

  const [org, setOrg] = useState<Organization | null>(null);
  const [keys, setKeys] = useState<SigningKey[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [rotating, setRotating] = useState(false);
  const [apiKeys, setApiKeys] = useState<any[]>([]);
  const [newApiKey, setNewApiKey] = useState<string | null>(null);
  const [apiKeyLabel, setApiKeyLabel] = useState('');
  const [creatingKey, setCreatingKey] = useState(false);
  const [loginHistory, setLoginHistory] = useState<any[]>([]);

  // Form state
  const [name, setName] = useState('');
  const [domain, setDomain] = useState('');
  const [billingEmail, setBillingEmail] = useState('');

  const fetchData = useCallback(async () => {
    if (!orgId) return;
    try {
      const [orgRes, keysRes, apiKeysRes, loginHistoryRes] = await Promise.all([
        axios.get(endpoints.organizations.details(orgId)),
        axios.get(endpoints.organizations.keys(orgId)),
        axios.get(`${endpoints.organizations.details(orgId)}/api-keys`),
        axios.get('/api/v1/auth/login-history').catch(() => ({ data: { data: [] } })),
      ]);
      const orgData: Organization = orgRes.data;
      setOrg(orgData);
      setName(orgData.name);
      setDomain(orgData.domain || '');
      setBillingEmail(orgData.billingEmail || '');
      setKeys(keysRes.data.data ?? keysRes.data ?? []);
      setApiKeys(apiKeysRes.data.data ?? apiKeysRes.data ?? []);
      setLoginHistory(loginHistoryRes.data.data ?? []);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to load settings';
      showError(message);
    } finally {
      setLoading(false);
    }
  }, [orgId, showError]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  const handleSave = async () => {
    if (!orgId) return;
    setSaving(true);
    try {
      await axios.patch(endpoints.organizations.details(orgId), {
        name,
        domain: domain || undefined,
        billingEmail: billingEmail || undefined,
      });
      showSuccess('Settings saved');
      fetchData();
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to save settings';
      showError(message);
    } finally {
      setSaving(false);
    }
  };

  const handleRotateKey = async () => {
    if (!orgId) return;
    if (
      !window.confirm(
        'Rotate the signing key? New QR codes will be signed with the new key. Existing QR codes remain valid.'
      )
    )
      return;
    setRotating(true);
    try {
      await axios.post(`${endpoints.organizations.keys(orgId)}/rotate`);
      showSuccess('Signing key rotated successfully');
      fetchData();
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to rotate key';
      showError(message);
    } finally {
      setRotating(false);
    }
  };

  const handleSubmitKYC = async () => {
    if (!orgId) return;
    try {
      await axios.post(`${endpoints.organizations.details(orgId)}/verify`, {
        kycData: { submittedAt: new Date().toISOString() },
      });
      showSuccess('KYC verification submitted');
      fetchData();
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to submit KYC';
      showError(message);
    }
  };

  if (loading) {
    return (
      <Box sx={{ textAlign: 'center', py: 10 }}>
        <CircularProgress />
      </Box>
    );
  }

  const currentUserRole = (user as Record<string, unknown>)?.role as string | undefined;
  const canEdit = ['OWNER', 'ADMIN'].includes(currentUserRole ?? '');

  return (
    <>
      <Typography variant="h4" sx={{ mb: 3 }}>
        Organization Settings
      </Typography>

      <Grid container spacing={3}>
        {/* General Settings */}
        <Grid size={{ xs: 12, md: 8 }}>
          <Card>
            <CardHeader title="General" />
            <CardContent>
              <Stack spacing={3}>
                <TextField
                  label="Organization Name"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  fullWidth
                  disabled={!canEdit}
                  slotProps={{ inputLabel: { shrink: true } }}
                />
                <TextField
                  label="Domain"
                  value={domain}
                  onChange={(e) => setDomain(e.target.value)}
                  placeholder="example.com"
                  fullWidth
                  disabled={!canEdit}
                  slotProps={{ inputLabel: { shrink: true } }}
                />
                <TextField
                  label="Billing Email"
                  value={billingEmail}
                  onChange={(e) => setBillingEmail(e.target.value)}
                  placeholder="billing@example.com"
                  fullWidth
                  disabled={!canEdit}
                  slotProps={{ inputLabel: { shrink: true } }}
                />
                {canEdit && (
                  <Button variant="contained" onClick={handleSave} disabled={saving}>
                    {saving ? 'Saving...' : 'Save Changes'}
                  </Button>
                )}
              </Stack>
            </CardContent>
          </Card>

          <Card sx={{ mt: 3 }}>
            <CardHeader title="Login History" subheader="Last 50 sign-in events" />
            <CardContent>
              {loginHistory.length === 0 ? (
                <Typography color="text.secondary" variant="body2">
                  No login history.
                </Typography>
              ) : (
                <TableContainer sx={{ maxHeight: 400 }}>
                  <Table size="small" stickyHeader>
                    <TableHead>
                      <TableRow>
                        <TableCell>Time</TableCell>
                        <TableCell>Provider</TableCell>
                        <TableCell>Device</TableCell>
                        <TableCell>Location</TableCell>
                        <TableCell>Status</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {loginHistory.map((event: any) => (
                        <TableRow key={event.id} hover>
                          <TableCell>
                            <Typography variant="caption">
                              {new Date(event.createdAt).toLocaleString()}
                            </Typography>
                          </TableCell>
                          <TableCell>
                            <Chip label={event.provider} size="small" variant="outlined" />
                          </TableCell>
                          <TableCell>
                            <Typography variant="caption">
                              {event.browser || '—'} / {event.os || '—'}
                            </Typography>
                            <Typography variant="caption" color="text.secondary" display="block">
                              {event.deviceType || '—'}
                            </Typography>
                          </TableCell>
                          <TableCell>
                            <Typography variant="caption">
                              {[event.ipCity, event.ipCountry].filter(Boolean).join(', ') || '—'}
                            </Typography>
                          </TableCell>
                          <TableCell>
                            <Chip
                              label={event.success ? 'Success' : 'Failed'}
                              size="small"
                              color={event.success ? 'success' : 'error'}
                              variant={event.success ? 'outlined' : 'filled'}
                            />
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              )}
            </CardContent>
          </Card>
        </Grid>

        {/* Status sidebar */}
        <Grid size={{ xs: 12, md: 4 }}>
          <Stack spacing={3}>
            {/* Plan & KYC */}
            <Card>
              <CardHeader title="Status" />
              <CardContent>
                <Stack spacing={2}>
                  <Box
                    sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}
                  >
                    <Typography variant="body2" color="text.secondary">
                      Plan
                    </Typography>
                    <Chip label={org?.plan || 'FREE'} color="primary" size="small" />
                  </Box>
                  <Box
                    sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}
                  >
                    <Typography variant="body2" color="text.secondary">
                      Trust Level
                    </Typography>
                    <Chip
                      label={org?.trustLevel || 'INDIVIDUAL'}
                      size="small"
                      variant="outlined"
                    />
                  </Box>
                  <Box
                    sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}
                  >
                    <Typography variant="body2" color="text.secondary">
                      KYC Status
                    </Typography>
                    <Chip
                      label={org?.kycStatus || 'PENDING'}
                      color={KYC_COLORS[org?.kycStatus || 'PENDING'] || 'default'}
                      size="small"
                    />
                  </Box>
                  <Divider />
                  <Box
                    sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}
                  >
                    <Typography variant="body2" color="text.secondary">
                      Slug
                    </Typography>
                    <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                      {org?.slug}
                    </Typography>
                  </Box>
                  <Box
                    sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}
                  >
                    <Typography variant="body2" color="text.secondary">
                      Created
                    </Typography>
                    <Typography variant="body2">
                      {org?.createdAt ? new Date(org.createdAt).toLocaleDateString() : '—'}
                    </Typography>
                  </Box>
                  {org?.kycStatus === 'PENDING' && canEdit && (
                    <>
                      <Divider />
                      <Button variant="outlined" size="small" onClick={handleSubmitKYC}>
                        Submit KYC Verification
                      </Button>
                    </>
                  )}
                </Stack>
              </CardContent>
            </Card>

            {/* Signing Keys */}
            <Card>
              <CardHeader
                title="Signing Keys"
                action={
                  canEdit && (
                    <Button
                      size="small"
                      startIcon={<Iconify icon="solar:restart-bold" />}
                      onClick={handleRotateKey}
                      disabled={rotating}
                    >
                      Rotate
                    </Button>
                  )
                }
              />
              <CardContent>
                {keys.length === 0 ? (
                  <Typography color="text.secondary" variant="body2">
                    No signing keys.
                  </Typography>
                ) : (
                  <Stack spacing={1.5}>
                    {keys.map((key) => (
                      <Box
                        key={key.id}
                        sx={{
                          p: 1.5,
                          borderRadius: 1,
                          border: '1px solid',
                          borderColor: 'divider',
                          bgcolor:
                            key.status === 'ACTIVE' ? 'success.lighter' : 'background.neutral',
                        }}
                      >
                        <Stack
                          direction="row"
                          justifyContent="space-between"
                          alignItems="center"
                        >
                          <Typography variant="caption" sx={{ fontFamily: 'monospace' }}>
                            {key.keyId.slice(0, 8)}...
                          </Typography>
                          <Chip
                            label={key.status}
                            size="small"
                            color={key.status === 'ACTIVE' ? 'success' : 'default'}
                          />
                        </Stack>
                        <Typography variant="caption" color="text.secondary">
                          {key.algorithm} · {new Date(key.createdAt).toLocaleDateString()}
                        </Typography>
                      </Box>
                    ))}
                  </Stack>
                )}
              </CardContent>
            </Card>
            {/* API Keys */}
            <Card>
              <CardHeader
                title="API Keys"
                action={
                  canEdit && (
                    <Button
                      size="small"
                      startIcon={<Iconify icon="mingcute:add-line" />}
                      onClick={async () => {
                        setCreatingKey(true);
                        try {
                          const res = await axios.post(
                            `${endpoints.organizations.details(orgId!)}/api-keys`,
                            { label: apiKeyLabel || undefined }
                          );
                          setNewApiKey(res.data.key);
                          setApiKeyLabel('');
                          fetchData();
                          showSuccess('API key created');
                        } catch (err: unknown) {
                          showError((err as Error).message || 'Failed to create API key');
                        } finally {
                          setCreatingKey(false);
                        }
                      }}
                      disabled={creatingKey}
                    >
                      Create
                    </Button>
                  )
                }
              />
              <CardContent>
                <Stack spacing={1.5}>
                  {canEdit && (
                    <TextField
                      size="small"
                      label="Key label (optional)"
                      value={apiKeyLabel}
                      onChange={(e) => setApiKeyLabel(e.target.value)}
                      placeholder="production-server"
                      fullWidth
                      slotProps={{ inputLabel: { shrink: true } }}
                    />
                  )}

                  {newApiKey && (
                    <Alert severity="warning" onClose={() => setNewApiKey(null)} sx={{ wordBreak: 'break-all' }}>
                      <Typography variant="caption" sx={{ fontFamily: 'monospace' }}>
                        {newApiKey}
                      </Typography>
                      <Typography variant="caption" display="block" sx={{ mt: 0.5, color: 'warning.dark' }}>
                        Copy now — this key will not be shown again.
                      </Typography>
                    </Alert>
                  )}

                  {apiKeys.length === 0 ? (
                    <Typography color="text.secondary" variant="body2">No API keys.</Typography>
                  ) : (
                    apiKeys.map((ak: any) => (
                      <Box
                        key={ak.id}
                        sx={{
                          p: 1.5, borderRadius: 1, border: '1px solid', borderColor: 'divider',
                          display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                        }}
                      >
                        <Box>
                          <Typography variant="caption" sx={{ fontFamily: 'monospace' }}>
                            {ak.prefix}••••••••
                          </Typography>
                          {ak.label && (
                            <Typography variant="caption" color="text.secondary" display="block">
                              {ak.label}
                            </Typography>
                          )}
                        </Box>
                        {canEdit && !ak.revokedAt && (
                          <Button
                            size="small"
                            color="error"
                            onClick={async () => {
                              if (!window.confirm('Revoke this API key? It will stop working immediately.')) return;
                              try {
                                await axios.delete(`${endpoints.organizations.details(orgId!)}/api-keys/${ak.id}`);
                                showSuccess('API key revoked');
                                fetchData();
                              } catch (err: unknown) {
                                showError((err as Error).message || 'Failed to revoke');
                              }
                            }}
                          >
                            Revoke
                          </Button>
                        )}
                      </Box>
                    ))
                  )}
                </Stack>
              </CardContent>
            </Card>
          </Stack>
        </Grid>
      </Grid>
    </>
  );
}
