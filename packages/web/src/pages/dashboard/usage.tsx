import { useState, useEffect, useCallback } from 'react';

import Box from '@mui/material/Box';
import Card from '@mui/material/Card';
import Chip from '@mui/material/Chip';
import Stack from '@mui/material/Stack';
import Button from '@mui/material/Button';
import Divider from '@mui/material/Divider';
import Skeleton from '@mui/material/Skeleton';
import Typography from '@mui/material/Typography';
import CardContent from '@mui/material/CardContent';
import LinearProgress from '@mui/material/LinearProgress';

import { paths } from 'src/routes/paths';
import { RouterLink } from 'src/routes/components';

import axios, { endpoints } from 'src/lib/axios';

import { Iconify } from 'src/components/iconify';
import { useSnackbar } from 'src/components/snackbar';

// ----------------------------------------------------------------------

type UsageMeter = {
  current: number;
  limit: number;
};

type UsageData = {
  plan: string;
  period: string;
  usage: {
    qrCodes: UsageMeter;
    verifications: UsageMeter;
    authSessions: UsageMeter;
  };
};

// ----------------------------------------------------------------------

function MeterRow({
  label,
  meter,
}: {
  label: string;
  meter: UsageMeter;
}) {
  const isUnlimited = meter.limit === -1;
  const pct = isUnlimited ? 0 : Math.min(100, Math.round((meter.current / meter.limit) * 100));

  const barColor = pct >= 90 ? 'error' : pct >= 70 ? 'warning' : 'primary';

  return (
    <Box>
      <Stack direction="row" alignItems="center" justifyContent="space-between" sx={{ mb: 1 }}>
        <Stack direction="row" alignItems="center" spacing={1}>
          <Typography variant="subtitle2">{label}</Typography>
        </Stack>
        <Typography variant="body2" color="text.secondary">
          {isUnlimited ? (
            <Box component="span" sx={{ color: 'success.main', fontWeight: 600 }}>
              Unlimited
            </Box>
          ) : (
            <>
              <Box component="span" sx={{ fontWeight: 600, color: 'text.primary' }}>
                {meter.current.toLocaleString()}
              </Box>
              {' / '}
              {meter.limit.toLocaleString()}
              {'  '}
              <Box component="span" sx={{ color: barColor === 'error' ? 'error.main' : 'text.disabled' }}>
                ({pct}%)
              </Box>
            </>
          )}
        </Typography>
      </Stack>

      {isUnlimited ? (
        <LinearProgress
          variant="determinate"
          value={100}
          color="success"
          sx={{ height: 6, borderRadius: 1, '& .MuiLinearProgress-bar': { borderRadius: 1 } }}
        />
      ) : (
        <LinearProgress
          variant="determinate"
          value={pct}
          color={barColor}
          sx={{ height: 6, borderRadius: 1, '& .MuiLinearProgress-bar': { borderRadius: 1 } }}
        />
      )}
    </Box>
  );
}

// ----------------------------------------------------------------------

function PlanChip({ plan }: { plan: string }) {
  const isPaid = plan !== 'FREE';
  return (
    <Chip
      label={plan}
      size="small"
      color={isPaid ? 'primary' : 'default'}
      variant={isPaid ? 'filled' : 'outlined'}
      sx={{ fontWeight: 700, letterSpacing: 0.5 }}
    />
  );
}

// ----------------------------------------------------------------------

export default function UsagePage() {
  const { showError } = useSnackbar();
  const [data, setData] = useState<UsageData | null>(null);
  const [loading, setLoading] = useState(true);

  const fetchUsage = useCallback(async () => {
    try {
      const res = await axios.get<UsageData>(endpoints.usage.root);
      setData(res.data);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to load usage data';
      showError(message);
    } finally {
      setLoading(false);
    }
  }, [showError]);

  useEffect(() => {
    fetchUsage();
  }, [fetchUsage]);

  const periodLabel = data?.period
    ? (() => {
        const [year, month] = data.period.split('-');
        return new Date(Number(year), Number(month) - 1).toLocaleString('default', {
          month: 'long',
          year: 'numeric',
        });
      })()
    : null;

  return (
    <>
      <Box sx={{ mb: 3, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <Box>
          <Typography variant="h4">Usage</Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
            Monitor your plan limits and resource consumption
          </Typography>
        </Box>
        <Button
          component={RouterLink}
          href={paths.dashboard.settings}
          variant="contained"
          startIcon={<Iconify icon="carbon:rocket" />}
        >
          Upgrade Plan
        </Button>
      </Box>

      <Card>
        {loading ? (
          <CardContent>
            <Stack spacing={3}>
              <Skeleton variant="rectangular" height={24} width={120} sx={{ borderRadius: 1 }} />
              <Skeleton variant="rectangular" height={6} sx={{ borderRadius: 1 }} />
              <Skeleton variant="rectangular" height={6} sx={{ borderRadius: 1 }} />
              <Skeleton variant="rectangular" height={6} sx={{ borderRadius: 1 }} />
            </Stack>
          </CardContent>
        ) : !data ? (
          <CardContent sx={{ textAlign: 'center', py: 6 }}>
            <Iconify
              icon="solar:chart-square-outline"
              width={48}
              sx={{ color: 'text.disabled', mb: 2, display: 'block', mx: 'auto' }}
            />
            <Typography variant="h6">No usage data available</Typography>
          </CardContent>
        ) : (
          <CardContent>
            <Stack direction="row" alignItems="center" justifyContent="space-between" sx={{ mb: 3 }}>
              <Stack direction="row" alignItems="center" spacing={1.5}>
                <Typography variant="subtitle1" fontWeight={700}>
                  Current Plan
                </Typography>
                <PlanChip plan={data.plan} />
              </Stack>
              {periodLabel && (
                <Typography variant="body2" color="text.secondary">
                  Billing period: {periodLabel}
                </Typography>
              )}
            </Stack>

            <Divider sx={{ mb: 3 }} />

            <Stack spacing={3}>
              <MeterRow
                label="QR Codes"
                meter={data.usage.qrCodes}
              />
              <MeterRow
                label="Verifications"
                meter={data.usage.verifications}
              />
              <MeterRow
                label="Auth Sessions"
                meter={data.usage.authSessions}
              />
            </Stack>

            {data.plan === 'FREE' && (
              <>
                <Divider sx={{ my: 3 }} />
                <Stack direction="row" alignItems="center" justifyContent="space-between">
                  <Box>
                    <Typography variant="subtitle2">Need more capacity?</Typography>
                    <Typography variant="body2" color="text.secondary">
                      Upgrade to unlock higher limits and advanced features.
                    </Typography>
                  </Box>
                  <Button
                    component={RouterLink}
                    href={paths.dashboard.settings}
                    variant="outlined"
                    size="small"
                    startIcon={<Iconify icon="eva:arrow-forward-fill" />}
                  >
                    View Plans
                  </Button>
                </Stack>
              </>
            )}
          </CardContent>
        )}
      </Card>
    </>
  );
}
